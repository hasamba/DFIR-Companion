import { describe, it, expect, afterEach, vi } from "vitest";
import { selectSynthesisEventsAnnotated } from "../../src/analysis/synthSelect.js";
import { createTimelineSelection } from "../../src/analysis/ai/synthesisPromptEvents.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { cloudOperationKey, BUDGET_CLOUD_OPERATION } from "../../src/analysis/synthSelectOperation.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

// #2585: on a cloud audit timeline over the synthesis budget, every distinct operation (the
// importer's own operation name) gets a seat before the Nth repeat of one operation — inside the same
// cap, so the number of rows sent never grows.

const BASE = Date.parse("2026-06-01T00:00:00Z");
const at = (minutes: number): string => new Date(BASE + minutes * 60_000).toISOString();

function canonical(action: string, source: string, type: string): ForensicEvent["canonical"] {
  return {
    schemaVersion: 1,
    event: { category: type === "rule" || type === "forwarding" ? "email" : "cloud", type, action },
    evidence: { rawRecords: [{ source, locator: "record:0" }] },
    producer: { importer: "m365-audit", parserVersion: "1", mappingVersion: "test" },
  } as unknown as ForensicEvent["canonical"];
}

function cloud(
  id: string,
  minutes: number,
  severity: Severity,
  op: string,
  opts: { source?: string; type?: string; asset?: string } = {},
): ForensicEvent {
  return {
    id,
    timestamp: at(minutes),
    description: `M365 audit: ${op} by user${id}@contoso.test`,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(opts.asset ? { asset: opts.asset } : {}),
    canonical: canonical(op, opts.source ?? "m365-ual", opts.type ?? "directory-change"),
  };
}

function endpoint(id: string, minutes: number, severity: Severity): ForensicEvent {
  return {
    id,
    timestamp: at(minutes),
    description: `endpoint detection ${id}`,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "ws-01",
  };
}

const ATTACK_OPS: [string, Severity, string][] = [
  ["Set-Mailbox", "Medium", "forwarding"],
  ["New-InboxRule", "Medium", "rule"],
  ["Add member to role", "Medium", "directory-change"],
  ["Add user", "Low", "directory-change"],
  ["FileDownloaded", "Low", "audit-operation"],
];

/** `consents` High consent rows (distinct users, spread over time) plus one row per attack operation. */
function consentFlood(consents: number, lows = 0): ForensicEvent[] {
  const events: ForensicEvent[] = [];
  for (let i = 0; i < consents; i++) events.push(cloud(`c${i}`, i * 7, "High", "Consent to application"));
  for (let i = 0; i < lows; i++) events.push(cloud(`l${i}`, i * 7 + 3, "Low", "UserLoggedIn"));
  ATTACK_OPS.forEach(([op, sev, type], i) =>
    events.push(cloud(`atk${i}`, consents * 4 + i * 11, sev, op, { type })),
  );
  return events;
}

const seatedOps = (sel: ReturnType<typeof selectSynthesisEventsAnnotated>): Set<string> =>
  new Set(sel.events.map((e) => cloudOperationKey(e)).filter((k): k is string => k !== null));

describe("cloudOperationKey (#2585)", () => {
  it("reads the importer's operation from the canonical envelope of an audit row", () => {
    expect(cloudOperationKey(cloud("a", 0, "Medium", "Set-Mailbox", { type: "forwarding" }))).toBe(
      "m365|set-mailbox",
    );
    expect(
      cloudOperationKey(cloud("b", 0, "Low", "ConsoleLogin", { source: "aws-cloudtrail", type: "api" })),
    ).toBe("aws|consolelogin");
    expect(
      cloudOperationKey(cloud("c", 0, "Low", "SetIamPolicy", { source: "gcp-audit", type: "iam-binding" })),
    ).toBe("gcp|setiampolicy");
    expect(cloudOperationKey(cloud("d", 0, "Low", "Add user", { source: "entra-audit" }))).toBe(
      "m365|add user",
    );
  });

  it("treats Entra's trailing-period spelling as the same operation", () => {
    expect(cloudOperationKey(cloud("a", 0, "Low", "Add user."))).toBe(
      cloudOperationKey(cloud("b", 0, "Low", "Add user")),
    );
  });

  it("ignores endpoint rows, non-audit cloud sources and derived summary rows", () => {
    expect(cloudOperationKey(endpoint("e", 0, "High"))).toBeNull();
    expect(
      cloudOperationKey(cloud("az", 0, "Low", "Microsoft.Compute/write", { source: "azure-activity" })),
    ).toBeNull();
    expect(cloudOperationKey(cloud("chain", 0, "High", "chain", { type: "mailbox-chain" }))).toBeNull();
    expect(
      cloudOperationKey(
        cloud("join", 0, "High", "join", { source: "gcp-audit", type: "service-account-join" }),
      ),
    ).toBeNull();
    expect(cloudOperationKey(cloud("omit", 0, "Info", "omitted"))).toBeNull();
    expect(cloudOperationKey(cloud("blank", 0, "Low", "  "))).toBeNull();
  });

  it("reads the key only when the envelope's own first record is the audit log", () => {
    const merged = cloud("m", 0, "High", "Set-Mailbox");
    merged.canonical = {
      ...merged.canonical!,
      evidence: {
        rawRecords: [
          { source: "windows-event", locator: "x" },
          { source: "m365-ual", locator: "y" },
        ],
      },
    };
    expect(cloudOperationKey(merged)).toBeNull();
  });
});

describe("distinct cloud operations get a seat over the budget (#2585)", () => {
  it("2x budget padded with repeated High consent rows: every distinct operation is seated, count unchanged", () => {
    const max = 60;
    const events = consentFlood(115);
    expect(events.length).toBeGreaterThanOrEqual(2 * max);
    const sel = selectSynthesisEventsAnnotated(events, max);
    expect(sel.events).toHaveLength(max);
    const ops = seatedOps(sel);
    for (const [op] of ATTACK_OPS) expect(ops.has(cloudOperationKey(cloud("x", 0, "Low", op))!)).toBe(true);
    for (let i = 0; i < ATTACK_OPS.length; i++) expect(sel.classOf.get(`atk${i}`)).toBe("operation");
    expect(sel.counts.operation).toBe(ATTACK_OPS.length);
  });

  it("overflow never takes the earliest reserve or the last row of an operation", () => {
    const max = 60;
    const events = consentFlood(115);
    const before = selectSynthesisEventsAnnotated(
      events.map((e) => ({ ...e, canonical: undefined })),
      max,
    );
    const after = selectSynthesisEventsAnnotated(events, max);
    expect(after.counts.earliest).toBe(before.counts.earliest);
    // Only repeated consent anchors made room.
    expect(after.counts.anchor).toBe(before.counts.anchor - ATTACK_OPS.length);
    expect(after.events.some((e) => cloudOperationKey(e) === "m365|consent to application")).toBe(true);
  });

  it("overflow never displaces an endpoint anchor (it has no operation, so it is not a repeat)", () => {
    const max = 40;
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 80; i++) events.push(endpoint(`h${i}`, i * 5, "High"));
    events.push(cloud("solo", 100, "High", "Consent to application"));
    events.push(cloud("med", 200, "Medium", "Set-Mailbox", { type: "forwarding" }));
    const sel = selectSynthesisEventsAnnotated(events, max);
    expect(sel.events).toHaveLength(max);
    expect(sel.classOf.get("med")).toBeUndefined(); // nothing displaceable: disclosed, not seated
  });

  it("an overflow displacement re-opens a command seat that the displaced anchor shadowed", () => {
    const max = 30;
    const events = consentFlood(60);
    const cmd = endpoint("cmd", 1, "Low");
    events.push(cmd);
    // Shadowed by the LOWEST-ranked consent anchor kept today, i.e. the first one displaced.
    // The anchors the overflow keeps before any swap: the same case with no operation keys.
    const plain = events.map((e) => ({ ...e, canonical: undefined }));
    const kept = selectSynthesisEventsAnnotated(plain, max).events.filter((e) => /^c\d/.test(e.id));
    const shadow = kept[kept.length - 1].id;
    const sel = selectSynthesisEventsAnnotated(events, max, undefined, [
      { event: cmd, shadowedBy: [shadow] },
    ]);
    expect(sel.events).toHaveLength(max);
    expect(sel.classOf.has(shadow)).toBe(false);
    expect(sel.classOf.get("cmd")).toBe("command");
  });

  it("just under the overflow threshold the share is still real", () => {
    const consents = 55;
    const events = consentFlood(consents, 40);
    const max = consents + 5;
    const sel = selectSynthesisEventsAnnotated(events, max);
    expect(sel.events).toHaveLength(max);
    for (let i = 0; i < ATTACK_OPS.length; i++) expect(sel.classOf.has(`atk${i}`)).toBe(true);
    expect(seatedOps(sel).has("m365|userloggedin")).toBe(true);
  });

  it("normal path: the share is bounded and chosen highest-severity first, then earliest", () => {
    const max = 50;
    const share = Math.max(1, Math.floor(max * BUDGET_CLOUD_OPERATION));
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 200; i++) events.push(cloud(`r${i}`, i, "Low", "UserLoggedIn"));
    for (let i = 0; i < 20; i++)
      events.push(cloud(`op${i}`, 500 + i, i < 3 ? "Medium" : "Low", `Op-${String.fromCharCode(97 + i)}`));
    const sel = selectSynthesisEventsAnnotated(events, max);
    expect(sel.events).toHaveLength(max);
    const opSeats = sel.events.filter((e) => sel.classOf.get(e.id) === "operation").map((e) => e.id);
    expect(opSeats.length).toBe(share);
    // The three Medium operations first, then the earliest Low ones.
    expect(opSeats.slice().sort()).toEqual(
      ["op0", "op1", "op2", ...Array.from({ length: share - 3 }, (_, i) => `op${3 + i}`)].sort(),
    );
  });

  it("operations already shown by a pinned row take no seat", () => {
    const max = 60;
    const events = consentFlood(115);
    const sel = selectSynthesisEventsAnnotated(events, max, undefined, [], {
      shownOperations: new Set([cloudOperationKey(events[events.length - 1])!]),
    });
    expect(sel.classOf.has(events[events.length - 1].id)).toBe(false);
    expect(sel.counts.operation).toBe(ATTACK_OPS.length - 1);
  });

  it("is deterministic", () => {
    const events = consentFlood(115);
    const a = selectSynthesisEventsAnnotated(events, 60);
    const b = selectSynthesisEventsAnnotated([...events].reverse(), 60);
    expect(a.events.map((e) => e.id)).toEqual(b.events.map((e) => e.id));
  });
});

// Letters, not digits: burst grouping folds numbers, so "user 1" and "user 2" would be one burst.
const word = (i: number): string =>
  String.fromCharCode(97 + (i % 26)) + String.fromCharCode(97 + (Math.floor(i / 26) % 26));

describe("createTimelineSelection — cloud operation seats end to end (#2585)", () => {
  afterEach(() => vi.unstubAllEnvs());

  function pipelineCase(): ForensicEvent[] {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 230; i++)
      events.push({
        ...cloud(`c${i}`, i * 7, "High", "Consent to application"),
        description: `M365 AzureActiveDirectory: Consent to application by ${word(i)}@contoso.test → app ${word(i + 7)}`,
      });
    ATTACK_OPS.forEach(([op, sev, type], i) =>
      events.push(cloud(`atk${i}`, 900 + i * 11, sev, op, { type })),
    );
    events.push(cloud("atk-twin", 1300, "Medium", "Set-Mailbox", { type: "forwarding" }));
    return events;
  }

  it("seats every distinct operation after grouping, inside the cap", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "100");
    const events = pipelineCase();
    const t = createTimelineSelection({ ...emptyState("c2585"), forensicTimeline: events }, events);
    expect(t.grouping.events.length).toBeGreaterThan(100); // grouping did not hide the overflow
    expect(t.promptEvents.length).toBe(100);
    const ops = new Set(t.promptEvents.map((e) => cloudOperationKey(e)));
    for (const [op] of ATTACK_OPS) expect(ops.has(cloudOperationKey(cloud("x", 0, "Low", op)))).toBe(true);
  });

  it("keeps the seats after a token-budget re-selection", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "100");
    const events = pipelineCase();
    const t = createTimelineSelection({ ...emptyState("c2585"), forensicTimeline: events }, events);
    t.fitTo(70);
    expect(t.promptEvents.length).toBe(70);
    const ops = new Set(t.promptEvents.map((e) => cloudOperationKey(e)));
    for (const [op] of ATTACK_OPS) expect(ops.has(cloudOperationKey(cloud("x", 0, "Low", op)))).toBe(true);
  });

  it("an operation a pinned row already shows takes no second seat", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "100");
    const events = pipelineCase();
    const t = createTimelineSelection(
      { ...emptyState("c2585"), forensicTimeline: events },
      events,
      undefined,
      new Set(["atk-twin"]),
    );
    expect(t.pinnedCount()).toBe(1);
    expect(t.selection.classOf.get("atk0")).not.toBe("operation"); // Set-Mailbox is already pinned
    expect(t.selection.classOf.get("atk1")).toBe("operation");
  });
});
