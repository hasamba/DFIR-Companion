import { describe, it, expect, afterEach, vi } from "vitest";
import { selectSynthesisEventsAnnotated } from "../../src/analysis/synthSelect.js";
import { sessionCommandSeats } from "../../src/analysis/ai/synthCommandSeats.js";
import { createTimelineSelection } from "../../src/analysis/ai/synthesisPromptEvents.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";

// #1622: quiet Low/Medium session commands get a bounded, reserved share of the synthesis prompt cap.

const BASE = Date.parse("2026-05-20T10:00:00Z");
const at = (seconds: number): string => new Date(BASE + seconds * 1000).toISOString();
const lower = (raw: string): string => raw.trim().toLowerCase();

function ev(
  id: string,
  seconds: number,
  severity: Severity,
  extra: Partial<ForensicEvent> = {},
): ForensicEvent {
  return {
    id,
    timestamp: at(seconds),
    severity,
    description: id,
    asset: "WS-01.example.com",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

// Letters, not digits: burst grouping folds numbers, so "rule 1" and "rule 2" would be one burst.
const word = (i: number): string =>
  String.fromCharCode(97 + (i % 26)) +
  String.fromCharCode(97 + (Math.floor(i / 26) % 26)) +
  String.fromCharCode(97 + Math.floor(i / 676));

const QUIET = [
  ["q-netview", "net view /all"],
  ["q-tasklist", "tasklist /v"],
  ["q-subst", "subst E: C:\\e"],
] as const;

/**
 * A detection-heavy case: `anchors` distinct High detections one minute apart, a Medium process-like
 * row every 30 s through the same stretch (it wins every anchor-context seat), and three quiet Low
 * commands a few minutes after the last anchor.
 */
function detectionHeavy(anchors: number): ForensicEvent[] {
  const events: ForensicEvent[] = [];
  for (let i = 0; i < anchors; i++)
    events.push(ev(`a${i}`, i * 60, "High", { description: `Sigma rule ${word(i)}` }));
  for (let i = 0; i < anchors * 2; i++)
    events.push(
      ev(`n${i}`, i * 30 + 5, "Medium", {
        description: `powershell.exe telemetry ${word(i)}`,
        processName: "powershell.exe",
      }),
    );
  const last = (anchors - 1) * 60;
  QUIET.forEach(([id, commandLine], k) =>
    events.push(
      ev(id, last + 300 + k * 60, "Low", { commandLine, processName: "cmd.exe", description: commandLine }),
    ),
  );
  return events;
}

const seatsFor = (events: ForensicEvent[]) => sessionCommandSeats({ events, hostOf: lower });
const quietIds = QUIET.map(([id]) => id);

describe("selectSynthesisEventsAnnotated — command seats (#1622)", () => {
  it("reproduces the gap without seats, and seats every quiet command with them", () => {
    const events = detectionHeavy(80);
    const without = selectSynthesisEventsAnnotated(events, 100);
    expect(quietIds.some((id) => without.classOf.has(id))).toBe(false);

    const sel = selectSynthesisEventsAnnotated(events, 100, undefined, seatsFor(events));
    for (const id of quietIds) expect(sel.classOf.get(id)).toBe("command");
    expect(sel.counts.command).toBe(3);
    expect(sel.events.length).toBe(100);
    expect(sel.counts.anchor).toBe(80); // anchors fit beside the reserve: none dropped
  });

  it("bounds the reserve at a tenth of the cap", () => {
    const events = detectionHeavy(80);
    for (let i = 0; i < 30; i++)
      events.push(ev(`extra${i}`, 60 * 60 + i, "Low", { commandLine: `whoami /priv ${word(i)}` }));
    const sel = selectSynthesisEventsAnnotated(events, 100, undefined, seatsFor(events));
    expect(sel.counts.command).toBe(10);
    expect(sel.events.length).toBe(100);
  });

  it("drops the lowest-ranked anchors, not the commands, when anchors overflow the cap", () => {
    const events = detectionHeavy(150);
    const sel = selectSynthesisEventsAnnotated(events, 100, undefined, seatsFor(events));
    for (const id of quietIds) expect(sel.classOf.get(id)).toBe("command");
    expect(sel.events.length).toBe(100);
    // Old overflow kept max - earliest reserve (15) anchors; the command reserve comes out of them too.
    expect(sel.counts.anchor).toBe(100 - 15 - 3);
  });

  it("drops only the command reserve's worth of anchors when anchors fit the cap but not the reserve", () => {
    const events = detectionHeavy(99);
    const sel = selectSynthesisEventsAnnotated(events, 100, undefined, seatsFor(events));
    expect(sel.counts.anchor).toBe(97);
    expect(sel.counts.command).toBe(3);
    expect(sel.events.length).toBe(100);
  });

  it("keeps at least one anchor at a tiny cap, then a command", () => {
    const events = detectionHeavy(5);
    const seats = seatsFor(events);
    const one = selectSynthesisEventsAnnotated(events, 1, undefined, seats);
    expect(one.counts).toMatchObject({ anchor: 1, command: 0 });
    for (const max of [2, 3]) {
      const sel = selectSynthesisEventsAnnotated(events, max, undefined, seats);
      expect(sel.events.length).toBe(max);
      expect(sel.counts.command).toBe(1);
      expect(sel.counts.anchor).toBe(max - 1);
    }
  });

  it("changes nothing when there are no command seats", () => {
    const events = detectionHeavy(80).filter((e) => !quietIds.includes(e.id as (typeof quietIds)[number]));
    const before = selectSynthesisEventsAnnotated(events, 100);
    const after = selectSynthesisEventsAnnotated(events, 100, undefined, []);
    expect([...after.classOf]).toEqual([...before.classOf]);
  });

  it("ignores seat rows that are not in the selection's input", () => {
    const events = detectionHeavy(80);
    const stranger = ev("stranger", 10, "Low", { commandLine: "net user" });
    const sel = selectSynthesisEventsAnnotated(events, 100, undefined, [stranger]);
    expect(sel.classOf.has("stranger")).toBe(false);
    expect(sel.counts.command).toBe(0);
  });
});

describe("createTimelineSelection — command seats end to end (#1622)", () => {
  afterEach(() => vi.unstubAllEnvs());

  function stateOf(events: ForensicEvent[]) {
    return { ...emptyState("c1622"), forensicTimeline: events };
  }

  it("seats the quiet commands in the rendered prompt, without the background prefix", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "100");
    const events = detectionHeavy(80);
    const t = createTimelineSelection(stateOf(events), events);
    const shown = new Set(t.promptEvents.map((e) => e.id));
    for (const id of quietIds) expect(shown.has(id)).toBe(true);
    const line = t.renderEvent(t.promptEvents.find((e) => e.id === "q-netview")!);
    expect(line.startsWith("[q-netview]")).toBe(true);
    expect(t.selection.counts.command).toBe(3);
  });

  it("keeps the command seats when the token budget re-selects a smaller prompt", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "100");
    const events = detectionHeavy(80);
    const t = createTimelineSelection(stateOf(events), events);
    t.fitTo(50);
    const shown = new Set(t.promptEvents.map((e) => e.id));
    expect(t.promptEvents.length).toBe(50);
    expect(t.selection.counts.command).toBe(3);
    for (const id of quietIds) expect(shown.has(id)).toBe(true);
  });

  it("opens a session from a High row that is pinned as newly promoted", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "60");
    const events = [
      ...detectionHeavy(80).filter((e) => !quietIds.includes(e.id as (typeof quietIds)[number])),
      ev("pinned-high", 4 * 3600, "High", { asset: "WS-09.example.com", description: "promoted detection" }),
      ev("quiet-9", 4 * 3600 + 120, "Low", { asset: "WS-09.example.com", commandLine: "net view /all" }),
    ];
    const t = createTimelineSelection(stateOf(events), events, undefined, new Set(["pinned-high"]));
    const shown = new Set(t.promptEvents.map((e) => e.id));
    expect(shown.has("pinned-high")).toBe(true);
    expect(t.selection.classOf.get("quiet-9")).toBe("command");
  });

  it("reserves the representative's seat for a command inside a grouped burst", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "100");
    const base = detectionHeavy(80).filter((e) => !quietIds.includes(e.id as (typeof quietIds)[number]));
    // The same quiet command five times: one burst, represented by its earliest member.
    const burst = [0, 1, 2, 3, 4].map((k) =>
      ev(`burst${k}`, 79 * 60 + 60 + k * 30, "Low", {
        commandLine: "net view /all",
        description: "net view /all",
      }),
    );
    const events = [...base, ...burst];
    const t = createTimelineSelection(stateOf(events), events);
    const rep = [...t.grouping.memberIdsByRepresentative].find(([, members]) =>
      members.includes("burst3"),
    )?.[0];
    expect(rep).toBeDefined();
    expect(t.selection.classOf.get(rep!)).toBe("command");
  });

  it("resolves host aliases, so a command logged under the client id joins the host's session", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "100");
    const events = detectionHeavy(80).map((e) => (e.id.startsWith("q-") ? { ...e, asset: "C.1622abcd" } : e));
    const index = buildHostAliasIndex(
      [{ clientId: "C.1622abcd", hostname: "WS-01", fqdn: "WS-01.example.com" }],
      {},
    );
    const withAlias = createTimelineSelection(stateOf(events), events, index);
    expect(withAlias.selection.counts.command).toBe(3);
    const withoutAlias = createTimelineSelection(stateOf(events), events);
    expect(withoutAlias.selection.counts.command).toBe(0);
  });
});
