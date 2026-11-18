import { describe, it, expect } from "vitest";
import { backfillSilenceGapFindings, gapKindLabel } from "../../src/analysis/gapDetect.js";
import { detectGapsWithWaves } from "../../src/analysis/activityWaves.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { buildKnownUnknownItems } from "../../src/analysis/knownUnknowns.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { deltaSchema, stripAiExtractedFrom } from "../../src/analysis/responseSchema.js";
import { parseThorReport } from "../../src/analysis/thorImport.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { timeBasisOf } from "../../src/analysis/promotionMerge.js";

// #2684: the wait between the end of the activity and the start of the collection is not log
// tampering. Last host activity at T, then the first row after the silence is the collection's own
// row (a THOR hit dated at the scan time, or a collector process) at T+1h, graded Medium or higher.
// All hosts, ids and times below are invented.

const T = "2026-03-02T10:00:00.000Z";
const NOW = "2026-03-02T12:00:00Z";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "host activity",
    severity: extra.severity ?? "Low",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: extra.relatedFindingIds ?? [],
    sourceScreenshots: [],
    sources: extra.sources ?? ["EVTX"],
    ...extra,
  };
}

const at = (base: string, minutes: number): string =>
  new Date(Date.parse(base) + minutes * 60_000).toISOString();

// Host activity: one row a minute, ending on `lastEdge` at T. Collection: the closing row at T+1h,
// then a few more rows of the same collection a minute apart.
function collectionCase(
  closingEdge: Partial<ForensicEvent>,
  lastEdge: Partial<ForensicEvent> = {},
  extra: ForensicEvent[] = [],
): ForensicEvent[] {
  const host = [0, 1, 2, 3, 4].map((i) => ev(`h${i}`, at(T, i - 5)));
  host.push(ev("h-last", T, lastEdge));
  const closingAt = at(T, 60);
  const closing = ev("c-first", closingAt, { severity: "High", ...closingEdge });
  const rest = [1, 2, 3, 4].map((i) =>
    ev(`c${i}`, at(closingAt, i), { sources: closing.sources, severity: "Medium" }),
  );
  return [...host, closing, ...rest, ...extra];
}

const THOR_SCAN_ROW: Partial<ForensicEvent> = {
  description: "THOR Alert [Filescan]: Malware file found — c:\\users\\public\\x.exe",
  sources: ["THOR"],
  timeBasis: "scan",
};
const COLLECTOR_ROW: Partial<ForensicEvent> = {
  description: "Process created: C:\\Program Files\\Velociraptor\\Tools\\autorunsc64.exe",
  sources: ["Velociraptor"],
  origin: "collector",
};
const USER_ROW: Partial<ForensicEvent> = {
  description: "Process created: C:\\Users\\alice\\AppData\\Local\\Temp\\run.exe",
  sources: ["EVTX"],
};

function theGap(events: ForensicEvent[]) {
  const { gaps } = detectGapsWithWaves(
    events,
    { activeHours: null, densityFactor: 4 },
    { minWaveEvents: 3, minWaveIntervalHours: 6 },
  );
  const complete = gaps.filter((g) => g.complete);
  expect(complete).toHaveLength(1);
  return { gaps, gap: complete[0] };
}

function findingsFor(events: ForensicEvent[]) {
  const { gaps } = theGap(events);
  return backfillSilenceGapFindings({ ...emptyState("c"), forensicTimeline: events }, gaps, NOW).findings;
}

describe("a gap that closes on the collection's own row (#2684)", () => {
  it("grades the wait before a THOR scan-time row Info, names the closing row, and mints no finding", () => {
    const events = collectionCase(THOR_SCAN_ROW);
    const { gap } = theGap(events);
    expect(gap.severity).toBe("Info");
    expect(gap.collectionEdge).toBe(true);
    expect(gap.collectionEdgeEventId).toBe("c-first");
    expect(gap.corroborated).toBe(false);
    expect(gapKindLabel(gap)).toBe("quiet period before collection");
    // Named by id, source and time — never by the row's (adversary-influenced) description.
    expect(gap.collectionEdgeLabel).toBe(`THOR row c-first at ${at(T, 60)}`);
    expect(gap.collectionEdgeLabel).not.toContain("Malware");
    const findings = findingsFor(events);
    expect(findings.filter((f) => f.severity === "High" || f.severity === "Medium")).toEqual([]);
    expect(findings.flatMap((f) => f.mitreTechniques)).not.toContain("T1070");
  });

  it("grades the wait before a Velociraptor collector process row Info as well", () => {
    const events = collectionCase(COLLECTOR_ROW);
    const { gap } = theGap(events);
    expect(gap.severity).toBe("Info");
    expect(gap.collectionEdge).toBe(true);
    expect(gap.collectionEdgeLabel).toBe(`Velociraptor row c-first at ${at(T, 60)}`);
    expect(findingsFor(events)).toEqual([]);
  });

  it("keeps today's High / T1070 finding when a user process row closes the same gap", () => {
    const events = collectionCase(USER_ROW);
    const { gap } = theGap(events);
    expect(gap.severity).toBe("High");
    expect(gap.collectionEdge).toBeUndefined();
    expect(gapKindLabel(gap)).toBe("complete silence");
    const findings = findingsFor(events);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("High");
    expect(findings[0].mitreTechniques).toEqual(["T1070"]);
    expect(findings[0].description).toContain("classic indicator of log tampering");
  });

  it("keeps today's grade when a THOR row's time is the artifact's own time, not the scan time", () => {
    const events = collectionCase({ ...THOR_SCAN_ROW, timeBasis: undefined });
    expect(theGap(events).gap.severity).toBe("High");
  });

  it("keeps today's High grade when a log clear or a stopped logging service opens the gap", () => {
    const openers: Partial<ForensicEvent>[] = [
      { description: "Security audit log cleared (EID 1102)" },
      { description: "System: EventID 104 — The System log file was cleared." },
      { description: "The event logging service has shut down. (EID 1100)" },
      { description: "Service Control Manager (EID 7036): The Sysmon64 service entered the stopped state." },
      { description: "Service Control Manager (EID 7034): The EventLog service terminated unexpectedly." },
      { description: "auditd stopped: DAEMON_END auditd normal halt" },
    ];
    for (const opener of openers) {
      for (const closing of [THOR_SCAN_ROW, COLLECTOR_ROW]) {
        const { gap } = theGap(collectionCase(closing, opener));
        expect(gap.severity, opener.description).toBe("High");
        expect(gap.collectionEdge, opener.description).toBeUndefined();
      }
    }
  });

  it("does not read an unrelated service stopping as a stopped logging service", () => {
    const opener = {
      description: "Service Control Manager (EID 7036): The Print Spooler service entered the stopped state.",
    };
    expect(theGap(collectionCase(THOR_SCAN_ROW, opener)).gap.severity).toBe("Info");
  });

  it("is not lifted by a log clear elsewhere in the case", () => {
    const clearEarlier = ev("x-clear", at(T, -30), { description: "Security audit log cleared (EID 1102)" });
    const { gap } = theGap(collectionCase(THOR_SCAN_ROW, {}, [clearEarlier]));
    expect(gap.severity).toBe("Info");
    expect(gap.collectionEdge).toBe(true);
  });

  it("keeps the reboot reading when a reboot opens the gap", () => {
    const { gap } = theGap(
      collectionCase(COLLECTOR_ROW, { description: "Event log service stopped (EID 6006)" }),
    );
    expect(gap.rebootEdge).toBe(true);
    expect(gap.severity).toBe("Low");
    expect(gap.collectionEdge).toBeUndefined();
  });

  it("only reads the closing edge: a collection row that OPENS the gap changes nothing", () => {
    const events = collectionCase(USER_ROW, { ...COLLECTOR_ROW, severity: "High" });
    expect(theGap(events).gap.severity).toBe("High");
  });
});

describe("timeBasis is importer-only (#2684)", () => {
  const delta = {
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: [{ id: "t1e1", timestamp: T, description: "THOR hit", timeBasis: "scan" }],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "",
  };

  it("survives the delta schema an importer parses through, and drops a value it does not know", () => {
    expect(deltaSchema.parse(delta).forensicEvents?.[0]?.timeBasis).toBe("scan");
    const odd = { ...delta, forensicEvents: [{ ...delta.forensicEvents[0], timeBasis: "event" }] };
    expect(deltaSchema.parse(odd).forensicEvents?.[0]?.timeBasis).toBeUndefined();
  });

  it("follows the kept timestamp when correlation folds rows, and an artifact-dated row wins", () => {
    const scan = ev("s", T, { timeBasis: "scan" });
    const artifact = ev("a", T);
    const later = ev("l", at(T, 5), { timeBasis: "scan" });
    expect(timeBasisOf([scan, later], T)).toBe("scan");
    expect(timeBasisOf([scan, artifact], T)).toBeUndefined();
    expect(timeBasisOf([artifact, later], T)).toBeUndefined();
  });

  it("is stripped from a model's delta", () => {
    const stripped = stripAiExtractedFrom(deltaSchema.parse(delta));
    expect(stripped.forensicEvents?.[0]).not.toHaveProperty("timeBasis");
  });
});

// The same shape through the real import seam: a THOR report parsed, validated and merged the way
// importThor does it, onto a timeline that already holds the host activity.
describe("a THOR import closing the gap, through the merge (#2684)", () => {
  const empty = { findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [] };
  const merge = (state: ReturnType<typeof emptyState>, events: object[], seq: number) =>
    mergeDelta(
      state,
      deltaSchema.parse({ ...empty, forensicEvents: events, timelineNote: "", summary: "" }),
      {
        windowSequence: seq,
        timestamp: NOW,
        sourceScreenshots: [`import-${seq}`],
      },
    );
  const thorRow = (minutes: number, module: string, extra: object = {}) => ({
    time: at(T, minutes).replace(".000", ""),
    hostname: "WS-LAB-01",
    level: "Alert",
    module,
    message: `Finding from ${module}`,
    entry: `entry-${module}`,
    ...extra,
  });

  function importedCase(rows: object[]) {
    const host = collectionCase(USER_ROW).filter((e) => e.id.startsWith("h"));
    const withHost = merge(emptyState("c"), host, 1);
    const thor = parseThorReport(rows.map((r) => JSON.stringify(r)).join("\n"));
    return merge(
      withHost,
      thor.events.map((e, i) => ({ ...e, id: `t1e${i + 1}` })),
      2,
    );
  }

  it("stores the scan-time mark on the merged row and grades the gap Info", () => {
    const state = importedCase([60, 61, 62, 63].map((m) => thorRow(m, `LogScan${m}`)));
    const closing = state.forensicTimeline.find((e) => e.timestamp.startsWith(at(T, 60).slice(0, 19)))!;
    expect(closing.timeBasis).toBe("scan");
    const { gap } = theGap(state.forensicTimeline);
    expect(gap.severity).toBe("Info");
    expect(gap.collectionEdge).toBe(true);
    expect(gap.collectionEdgeEventId).toBe(closing.id);
  });

  it("keeps today's High grade when the closing THOR row is dated by the artifact's own time", () => {
    const rows = [60, 61, 62, 63].map((m) =>
      thorRow(m, `Filescan${m}`, { created: at(T, m).replace(".000", "") }),
    );
    const state = importedCase(rows);
    expect(state.forensicTimeline.some((e) => e.timeBasis === "scan")).toBe(false);
    expect(theGap(state.forensicTimeline).gap.severity).toBe("High");
  });
});

describe("surfaces of a quiet period before collection (#2684)", () => {
  const gapOptions = { activeHours: null, densityFactor: 4 };

  it("keeps the wait before collection out of the known unknowns the synthesis prompt reads", () => {
    const thor = collectionCase(THOR_SCAN_ROW);
    const state = { ...emptyState("c"), forensicTimeline: thor };
    const gapItems = (events: ForensicEvent[]) =>
      buildKnownUnknownItems({ ...state, forensicTimeline: events }, events, { gapOptions }).filter(
        (i) => i.kind === "silence_gap",
      );
    expect(gapItems(thor)).toEqual([]);
    // The same silence closed by a user process is still asked about.
    const user = gapItems(collectionCase(USER_ROW));
    expect(user).toHaveLength(1);
    expect(user[0].label).toContain("collection gap or cleared logs?");
  });

  it("names the closing row in the report, escaped, without its description", () => {
    const events = collectionCase({ ...THOR_SCAN_ROW, sources: ["THOR|x"] });
    const md = renderMarkdownReport({ ...emptyState("c"), forensicTimeline: events });
    const row = md.split("\n").find((l) => l.includes("quiet period before collection")) ?? "";
    expect(row).toContain("Info (quiet period before collection, closed by THOR\\|x row c-first at");
    expect(row).not.toContain("Malware");
  });
});
