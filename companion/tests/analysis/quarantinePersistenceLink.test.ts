import { describe, it, expect } from "vitest";
import { parseMacos } from "../../src/analysis/macosImport.js";
import { parseMacPersist } from "../../src/analysis/macosPersistImport.js";
import {
  linkQuarantinePersistence,
  PERSISTED_MARKER,
  DOWNLOAD_EVENT_MARKER,
  LINK_IDS_MAX,
} from "../../src/analysis/quarantinePersistenceLink.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

// #1037 link 2: the quarantine-database record and the launchd job whose program carries the same
// event identifier meet at merge time, across uploads — joined by the identifier alone.

const UUID = "8f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";
const UUID2 = "11111111-2222-3333-4444-555555555555";
// 2020-08-17T05:52:44Z as Cocoa seconds and Unix hex
const COCOA = 619336364;
const UNIX_HEX = "5f3a1b2c";

const dbRecord = (over: Record<string, unknown> = {}) => ({
  LSQuarantineEventIdentifier: UUID,
  LSQuarantineTimeStamp: COCOA,
  LSQuarantineAgentName: "Safari",
  LSQuarantineAgentBundleIdentifier: "com.apple.Safari",
  LSQuarantineDataURLString: "https://cdn.example.invalid/agent",
  LSQuarantineOriginURLString: "https://lure.example.invalid/promo",
  LSQuarantineTypeNumber: 0,
  ...over,
});

type Ev = ForensicEvent;
const asForensic = (e: { description: string; timestamp: string; severity: string }, id: string): Ev =>
  ({
    ...e,
    id,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  }) as unknown as Ev;

const dbRows = (records: unknown[]): Ev[] =>
  parseMacos(JSON.stringify(records), { aggregate: false, maxEvents: records.length })
    .events.filter((e) => e.description.startsWith("macOS quarantine ["))
    .map((e, i) => asForensic(e, `db-${i}`));

const plist = (label: string, program: string) => `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array><string>${program}</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`;

const persistRows = (
  jobs: { label: string; program: string; artifact: string; quarantine?: string }[],
): Ev[] => {
  const text = jobs
    .map(
      (j) =>
        `==> ${j.artifact} <==\n# mtime: 2026-01-02T09:00:00Z\n# codesign: unsigned\n${
          j.quarantine ? `# quarantine: ${j.quarantine}\n` : ""
        }${plist(j.label, j.program)}\n`,
    )
    .join("");
  return parseMacPersist("mac.txt", text).events.map((e) => ({ ...asForensic(e, e.id) }));
};

const target = (
  quarantine = `0083;${UNIX_HEX};Safari;${UUID}`,
  over: Partial<Parameters<typeof persistRows>[0][0]> = {},
) =>
  persistRows([
    {
      label: "com.vendor.helper",
      program: "/Users/Shared/.a/agent",
      artifact: "/Library/LaunchAgents/com.vendor.helper.plist",
      quarantine,
      ...over,
    },
  ]);

const persistOf = (rows: Ev[]) => rows.find((e) => e.description.startsWith("macOS persistence"))!;
const dbOf = (rows: Ev[]) => rows.find((e) => e.description.startsWith("macOS quarantine ["))!;

describe("the download -> persistence link (#1037 link 2)", () => {
  it("joins the database record and the persistence target by the event identifier, and says what the pair establishes", () => {
    const out = linkQuarantinePersistence([...dbRows([dbRecord()]), ...target()]);
    const p = persistOf(out);
    const d = dbOf(out);
    expect(p.description).toContain(
      `${DOWNLOAD_EVENT_MARKER} data url https://cdn.example.invalid/agent; origin https://lure.example.invalid/promo; agent Safari (com.apple.Safari) — the database record with this event identifier;`,
    );
    expect(p.description).toContain("agent agrees");
    expect(p.description).toContain(
      "marked and recorded in the same second (attribute: Unix hex; database: Cocoa seconds)",
    );
    expect(p.description).toContain("download flag set");
    expect(p.description).toContain("host not compared — the persistence collection names no host");
    expect(d.description).toContain(
      `${PERSISTED_MARKER} /Users/Shared/.a/agent — the program of launchd job com.vendor.helper (/Library/LaunchAgents/com.vendor.helper.plist); its quarantine attribute carries this event identifier — set to run by launchd; whether it ran is not established by these records]`,
    );
    // The database row is raised so it survives the Info demote and reaches the forensic timeline;
    // Medium at most, the same cap the browser-visit join puts on a mark. The persistence row is
    // already High on its own evidence and is left where it is.
    expect(d.severity).toBe("Medium");
    expect(p.severity).toBe("High");
    // Never "ran", never a verdict.
    expect(d.description).not.toMatch(/\bran\b(?! is not established)/);
    expect(p.description).not.toContain("malicious");
  });

  it("is recomputed on every pass: running twice yields the same notes, and a lost partner removes them", () => {
    const once = linkQuarantinePersistence([...dbRows([dbRecord()]), ...target()]);
    const twice = linkQuarantinePersistence(once);
    expect(twice.map((e) => e.description)).toEqual(once.map((e) => e.description));
    expect(twice.map((e) => e.severity)).toEqual(once.map((e) => e.severity));
    const alone = linkQuarantinePersistence([persistOf(once)]);
    expect(alone[0].description).not.toContain(DOWNLOAD_EVENT_MARKER);
  });

  it("joins nothing on a different identifier, a basename that matches the URL, or a time that matches", () => {
    const out = linkQuarantinePersistence([
      ...dbRows([dbRecord()]),
      ...target(`0083;${UNIX_HEX};Safari;${UUID2}`),
    ]);
    expect(persistOf(out).description).not.toContain(DOWNLOAD_EVENT_MARKER);
    expect(dbOf(out).description).not.toContain(PERSISTED_MARKER);
    expect(dbOf(out).severity).toBe("Info");
  });

  it("disagreeing database records with one identifier join nothing, and both sides say why", () => {
    const out = linkQuarantinePersistence([
      ...dbRows([dbRecord(), dbRecord({ LSQuarantineDataURLString: "https://other.example.invalid/x" })]),
      ...target(),
    ]);
    expect(persistOf(out).description).toContain(
      `${DOWNLOAD_EVENT_MARKER} database records with this identifier disagree — not joined]`,
    );
    for (const d of out.filter((e) => e.description.startsWith("macOS quarantine ["))) {
      expect(d.description).toContain(
        `${PERSISTED_MARKER} a launchd job's program carries this event identifier, but the database records with it disagree — not joined]`,
      );
      expect(d.severity).toBe("Info");
    }
  });

  it("a sandbox-only mark still joins, says its flags do not say download, and raises nothing on the persistence row", () => {
    const before = target(`0002;${UNIX_HEX};Safari;${UUID}`);
    const out = linkQuarantinePersistence([...dbRows([dbRecord()]), ...before]);
    const p = persistOf(out);
    expect(p.description).toContain(DOWNLOAD_EVENT_MARKER);
    expect(p.description).toContain("download flag not set — sandbox mark only");
    expect(p.severity).toBe(persistOf(before).severity); // the grader's own severity, untouched
    expect(dbOf(out).severity).toBe("Medium");
  });

  it("agent and time differences are stated, never resolved", () => {
    const out = linkQuarantinePersistence([
      ...dbRows([
        dbRecord({
          LSQuarantineTimeStamp: COCOA - 120,
          LSQuarantineAgentName: "curl",
          LSQuarantineAgentBundleIdentifier: "",
        }),
      ]),
      ...target(),
    ]);
    const p = persistOf(out);
    expect(p.description).toContain("agent differs: attribute Safari; database curl");
    expect(p.description).toMatch(/marked [^;\]]* after the record/);
  });

  it("a database host name beside an unnamed persistence collection joins and says the host was not compared; an ambiguous host joins nothing", () => {
    const named = linkQuarantinePersistence([...dbRows([dbRecord({ hostname: "mac-01" })]), ...target()]);
    expect(persistOf(named).description).toContain(
      "host not compared — the persistence collection names no host; the database record names mac-01",
    );
    const rows = parseMacos(
      `LSQuarantineEventIdentifier,LSQuarantineTimeStamp,LSQuarantineAgentName,LSQuarantineDataURLString,hostname,host\n${UUID},${COCOA},Safari,https://cdn.example.invalid/agent,mac-01,mac-02\n`,
      { aggregate: false },
    ).events.map((e, i) => asForensic(e, `db-${i}`));
    const ambiguous = linkQuarantinePersistence([...rows, ...target()]);
    expect(persistOf(ambiguous).description).toContain(
      `${DOWNLOAD_EVENT_MARKER} the database record names two hosts — not joined]`,
    );
    expect(dbOf(ambiguous).severity).toBe("Info");
  });

  it("several targets with one identifier are listed as copies or extracted members, bounded", () => {
    const out = linkQuarantinePersistence([
      ...dbRows([dbRecord()]),
      ...persistRows(
        ["a", "b", "c", "d"].map((n) => ({
          label: `com.vendor.${n}`,
          program: `/Users/Shared/.${n}/agent`,
          artifact: `/Library/LaunchAgents/com.vendor.${n}.plist`,
          quarantine: `0083;${UNIX_HEX};Safari;${UUID}`,
        })),
      ),
    ]);
    const d = dbOf(out);
    expect(d.description).toContain(`${PERSISTED_MARKER} 4 launchd programs —`);
    expect(d.description).toContain("/Users/Shared/.a/agent (com.vendor.a)");
    expect(d.description).toContain("and 1 more");
    expect(d.description).toContain(
      "the same identifier on several files: a copy, or an archive's extracted members; the records do not say which",
    );
    expect(d.severity).toBe("Medium");
  });

  it("the identifier index is bounded, and rows past the bound say so", () => {
    const db = Array.from({ length: LINK_IDS_MAX + 1 }, (_, i) =>
      dbRecord({ LSQuarantineEventIdentifier: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}` }),
    );
    const rows = dbRows(db);
    expect(rows).toHaveLength(LINK_IDS_MAX + 1);
    const lastId = `00000000-0000-4000-8000-${String(LINK_IDS_MAX).padStart(12, "0")}`;
    const out = linkQuarantinePersistence([...rows, ...target(`0083;${UNIX_HEX};Safari;${lastId}`)]);
    expect(persistOf(out).description).toContain(
      `${DOWNLOAD_EVENT_MARKER} not compared — more than ${LINK_IDS_MAX} database identifiers in the case]`,
    );
  });

  it("runs inside the merge, so the two rows meet when both are in the case", () => {
    const base = {
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    };
    const ctx = { windowSequence: 1, timestamp: "2026-01-03T00:00:00Z", sourceScreenshots: [] };
    const first = mergeDelta(
      emptyState("c1"),
      { ...base, forensicEvents: target() } as unknown as AnalysisDelta,
      ctx,
    );
    const second = mergeDelta(
      first,
      { ...base, forensicEvents: dbRows([dbRecord()]) } as unknown as AnalysisDelta,
      { ...ctx, windowSequence: 2 },
    );
    const p = second.forensicTimeline.find((e) => e.description.startsWith("macOS persistence"))!;
    const d = second.forensicTimeline.find((e) => e.description.startsWith("macOS quarantine ["))!;
    expect(p.description).toContain(DOWNLOAD_EVENT_MARKER);
    expect(d.description).toContain(PERSISTED_MARKER);
    expect(d.severity).toBe("Medium");
  });
});
