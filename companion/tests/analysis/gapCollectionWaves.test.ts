import { describe, it, expect } from "vitest";
import { backfillSilenceGapFindings, gapKindLabel } from "../../src/analysis/gapDetect.js";
import { backfillActivityWaveFinding, detectGapsWithWaves } from "../../src/analysis/activityWaves.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2688: the #2684 quiet-period rule also holds when the wait before collection is 6h or more. A
// silence that long separates two waves, and the collection's own High rows (THOR verdicts dated at
// the scan time) made the second "wave" look like a returning operator: a Medium dwell finding and
// a High waves finding about the wait before collection. All hosts, ids and times are invented.

const T = "2026-03-02T10:00:00.000Z";
const NOW = "2026-03-03T12:00:00Z";
const GAP_OPTS = { activeHours: null, densityFactor: 4 } as const;
const WAVE_OPTS = { minWaveEvents: 3, minWaveIntervalHours: 6 } as const;

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

// One burst of host activity: six rows a minute apart, ending on `lastEdge` at `end`; one is High.
function hostBurst(
  prefix: string,
  end: string,
  lastEdge: Partial<ForensicEvent> = {},
  scope: Partial<ForensicEvent> = {},
) {
  const rows = [0, 1, 2, 3, 4].map((i) =>
    ev(`${prefix}${i}`, at(end, i - 5), { ...scope, severity: i === 2 ? "High" : "Low" }),
  );
  rows.push(ev(`${prefix}last`, end, { ...scope, ...lastEdge }));
  return rows;
}

// The second burst: the closing row at `start`, then four more High rows of the same source.
function closingBurst(prefix: string, start: string, closingEdge: Partial<ForensicEvent>) {
  const closing = ev(`${prefix}first`, start, { severity: "High", ...closingEdge });
  const rest = [1, 2, 3, 4].map((i) =>
    ev(`${prefix}${i}`, at(start, i), {
      sources: closing.sources,
      severity: "High",
      ...(closingEdge.canonical ? { canonical: closingEdge.canonical } : {}),
    }),
  );
  return [closing, ...rest];
}

// Last host activity at T; the first row after the silence is `closingEdge` at T+8h.
function longWaitCase(closingEdge: Partial<ForensicEvent>, lastEdge: Partial<ForensicEvent> = {}) {
  return [...hostBurst("h", T, lastEdge), ...closingBurst("c", at(T, 8 * 60), closingEdge)];
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

function analyse(events: ForensicEvent[]) {
  const { gaps, pattern } = detectGapsWithWaves(events, GAP_OPTS, WAVE_OPTS);
  const state = { ...emptyState("c"), forensicTimeline: events };
  const gapState = backfillSilenceGapFindings(state, gaps, NOW);
  const waveFindings = backfillActivityWaveFinding(state, pattern, NOW).findings;
  return {
    gaps,
    pattern,
    gapFindings: gapState.findings,
    gapTimeline: gapState.forensicTimeline,
    waveFindings,
  };
}

function theGap(gaps: ReturnType<typeof analyse>["gaps"], afterEventId: string) {
  const gap = gaps.find((g) => g.complete && g.afterEventId === afterEventId);
  expect(gap).toBeDefined();
  return gap!;
}

describe("a wait of 6h or more that closes on the collection's own row (#2688)", () => {
  it("a THOR scan-time row at T+8h with High rows on both sides is the wait before collection, not dwell", () => {
    const { gaps, gapFindings, waveFindings } = analyse(longWaitCase(THOR_SCAN_ROW));
    const gap = theGap(gaps, "cfirst");
    expect(gap.betweenWaves).toBe(true);
    expect(gap.collectionEdge).toBe(true);
    expect(gap.collectionEdgeEventId).toBe("cfirst");
    expect(gap.severity).toBe("Info");
    expect(gap.attackerEdges).toBe(false);
    expect(gapKindLabel(gap)).toBe("quiet period before collection");
    expect(gapFindings).toEqual([]);
    expect(waveFindings).toEqual([]);
  });

  it("treats a collector-origin closing row the same way", () => {
    const { gaps, gapFindings, waveFindings } = analyse(longWaitCase(COLLECTOR_ROW));
    const gap = theGap(gaps, "cfirst");
    expect(gap.collectionEdge).toBe(true);
    expect(gap.severity).toBe("Info");
    expect(gapKindLabel(gap)).toBe("quiet period before collection");
    expect(gapFindings).toEqual([]);
    expect(waveFindings).toEqual([]);
  });

  it("keeps today's grading when the same long gap closes on a user process row", () => {
    const { gaps, gapFindings, waveFindings } = analyse(longWaitCase(USER_ROW));
    const gap = theGap(gaps, "cfirst");
    expect(gap.betweenWaves).toBe(true);
    expect(gap.attackerEdges).toBe(true);
    expect(gap.collectionEdge).toBeUndefined();
    expect(gapKindLabel(gap)).toBe("dwell interval");
    expect(gapFindings).toHaveLength(1);
    expect(gapFindings[0].severity).toBe("Medium");
    expect(gapFindings[0].title).toMatch(/^Dwell interval/);
    expect(waveFindings).toHaveLength(1);
    expect(waveFindings[0].severity).toBe("High");
  });

  it("keeps the dwell finding when the opening edge records a log clear", () => {
    const logClear = { description: "EID 1102 The security audit log was cleared" };
    const { gaps, gapFindings, waveFindings } = analyse(longWaitCase(THOR_SCAN_ROW, logClear));
    const gap = theGap(gaps, "cfirst");
    expect(gap.collectionEdge).toBeUndefined();
    expect(gap.attackerEdges).toBe(true);
    expect(gapFindings).toHaveLength(1);
    expect(gapFindings[0].severity).toBe("Medium");
    expect(waveFindings).toHaveLength(1);
  });

  it("keeps the dwell finding when the opening edge records a stopped logging service", () => {
    for (const description of [
      "Service Control Manager: The Sysmon64 service entered the stopped state",
      "EID 1100 The event logging service has shut down",
    ]) {
      const { gaps, gapFindings } = analyse(longWaitCase(COLLECTOR_ROW, { description }));
      const gap = theGap(gaps, "cfirst");
      expect(gap.collectionEdge).toBeUndefined();
      expect(gapFindings).toHaveLength(1);
      expect(gapFindings[0].severity).toBe("Medium");
    }
  });

  it("keeps a real returning-operator interval and drops only the wait before collection", () => {
    const wave2End = at(T, 3 * 24 * 60);
    const events = [
      ...hostBurst("a", T),
      ...hostBurst("b", wave2End, {}),
      ...closingBurst("c", at(wave2End, 10 * 60), THOR_SCAN_ROW),
    ];
    const { gaps, gapFindings, gapTimeline, waveFindings } = analyse(events);
    expect(theGap(gaps, "b0").attackerEdges).toBe(true);
    expect(theGap(gaps, "cfirst").collectionEdge).toBe(true);
    expect(gapFindings).toHaveLength(1);
    const b0 = gapTimeline.find((e) => e.id === "b0");
    expect(b0?.relatedFindingIds).toContain(gapFindings[0].id);
    expect(waveFindings).toHaveLength(1);
    expect(waveFindings[0].title).toMatch(/^Activity occurred in 2 separate waves/);
    expect(waveFindings[0].description).not.toMatch(/wave 3/);
  });

  it("lets a cross-account boundary win over the collection reading", () => {
    // A minimal canonical record: only the cloud scope matters here, as in gapEdgeClass.test.ts.
    const aws = (acct: string): Partial<ForensicEvent> =>
      ({
        canonical: {
          event: { category: "cloud", type: "api-call" },
          cloud: { provider: "aws", accountId: acct, recipientAccountId: acct },
        },
      }) as unknown as Partial<ForensicEvent>;
    const events = [
      ...hostBurst("h", T, {}, aws("111111111111")),
      ...closingBurst("c", at(T, 8 * 60), { ...COLLECTOR_ROW, ...aws("222222222222") }),
    ];
    const { gaps, gapFindings, waveFindings } = analyse(events);
    const gap = theGap(gaps, "cfirst");
    expect(gap.scopeBoundary).toBe(true);
    expect(gap.severity).toBe("Low");
    expect(gap.collectionEdge).toBeUndefined();
    expect(gapKindLabel(gap)).toBe("wave boundary, separate accounts/tenants");
    expect(gapFindings).toEqual([]);
    expect(waveFindings).toEqual([]);
  });
});
