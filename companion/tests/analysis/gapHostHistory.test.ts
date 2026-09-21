import { describe, it, expect } from "vitest";
import {
  HOST_HISTORY_FINDING_ID,
  backfillHostHistoryNote,
  gapOptionsFor,
  hostBuildMarkers,
  splitHostHistory,
} from "../../src/analysis/gapHostHistory.js";
import { detectGapsWithWaves, backfillActivityWaveFinding } from "../../src/analysis/activityWaves.js";
import { backfillSilenceGapFindings } from "../../src/analysis/gapDetect.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { HostRenameRecord } from "../../src/analysis/hostRenameRecord.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: extra.relatedFindingIds ?? [],
    sourceScreenshots: [],
    sources: ["velo"],
    ...extra,
  };
}

function burst(
  prefix: string,
  startISO: string,
  count: number,
  extra: Partial<ForensicEvent> = {},
): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  let ms = Date.parse(startISO);
  for (let i = 0; i < count; i++) {
    out.push(ev(`${prefix}${i}`, new Date(ms).toISOString(), extra));
    ms += 60_000;
  }
  return out;
}

// The scenario 017 ledger: provisioned as WIN-UK1GV882OK6, renamed twice, last name DESKTOP-16OJFO6.
const renames: HostRenameRecord[] = [
  {
    formerName: "WIN-UK1GV882OK6",
    currentName: "WIN-0NNTB2RTNB1",
    until: "2025-12-05T18:00:00.000Z",
    basis: "collector",
  },
  {
    formerName: "WIN-0NNTB2RTNB1",
    currentName: "DESKTOP-16OJFO6",
    until: "2026-08-17T09:00:00.000Z",
    basis: "machine-account",
  },
];

const HOST = "DESKTOP-16OJFO6";

// Install media → base image → provisioning → sessions → the intrusion, on one host.
function labBox(): ForensicEvent[] {
  return [
    ...burst("iso-", "2024-04-01T00:00:00Z", 5, { asset: HOST }),
    ...burst("img-", "2025-09-15T08:00:00Z", 5, { asset: HOST }),
    ...burst("prov-", "2025-12-05T09:00:00Z", 8, { asset: HOST }),
    ...burst("use-", "2026-08-17T10:00:00Z", 6, { asset: HOST }),
    ...burst("atk-", "2026-08-26T15:00:00Z", 6, { asset: HOST, severity: "High" }),
  ];
}

describe("hostBuildMarkers", () => {
  it("folds a rename chain into one marker at the earliest observed bound", () => {
    const markers = hostBuildMarkers(renames);
    expect(markers).toHaveLength(1);
    expect(markers[0].host).toBe(HOST);
    expect(markers[0].before).toBe("2025-12-05T18:00:00.000Z");
    expect(markers[0].names).toEqual(["DESKTOP-16OJFO6", "WIN-0NNTB2RTNB1", "WIN-UK1GV882OK6"]);
  });

  it("ignores analyst attributions and malformed records", () => {
    expect(
      hostBuildMarkers([
        { formerName: "OLD", currentName: "NEW", until: "2026-01-01T00:00:00Z", basis: "analyst" },
        { formerName: "OLD2", currentName: "NEW2", until: "not-a-date", basis: "6011" },
      ]),
    ).toEqual([]);
  });

  it("keeps two unrelated hosts apart", () => {
    const markers = hostBuildMarkers([
      ...renames,
      { formerName: "WIN-TEMP", currentName: "FILESRV01", until: "2026-03-01T00:00:00Z", basis: "6011" },
    ]);
    expect(markers.map((m) => m.host).sort()).toEqual(["DESKTOP-16OJFO6", "FILESRV01"]);
  });
});

describe("splitHostHistory", () => {
  it("sets aside the renamed host's rows before its bound and keeps the rest", () => {
    const events = labBox();
    const { kept, history } = splitHostHistory(events, hostBuildMarkers(renames));
    expect(history).toHaveLength(1);
    expect(history[0].events.map((e) => e.id.split("-")[0])).toEqual([
      ...Array(5).fill("iso"),
      ...Array(5).fill("img"),
      ...Array(8).fill("prov"),
    ]);
    expect(kept.map((e) => e.id.split("-")[0]).every((p) => p === "use" || p === "atk")).toBe(true);
  });

  it("matches the former names and FQDN spellings of the same host", () => {
    const events = [
      ev("a", "2025-01-01T00:00:00Z", { asset: "win-uk1gv882ok6.example.com" }),
      ev("b", "2025-02-01T00:00:00Z", { asset: "WIN-0NNTB2RTNB1" }),
    ];
    const { history } = splitHostHistory(events, hostBuildMarkers(renames));
    expect(history[0].events.map((e) => e.id)).toEqual(["a", "b"]);
  });

  it("never touches another host's rows or rows naming no asset", () => {
    const events = [
      ev("other", "2025-01-01T00:00:00Z", { asset: "FILESRV01" }),
      ev("bare", "2025-01-02T00:00:00Z"),
      ev("mine", "2025-01-03T00:00:00Z", { asset: HOST }),
    ];
    const { kept } = splitHostHistory(events, hostBuildMarkers(renames));
    expect(kept.map((e) => e.id)).toEqual(["other", "bare"]);
  });

  it("leaves a host whole when a High/Critical row sits before its bound", () => {
    // A rename during the intrusion: the pre-rename activity IS the case and must stay in gap analysis.
    const events = [
      ...burst("pre-", "2025-06-01T00:00:00Z", 4, { asset: HOST }),
      ev("hit", "2025-06-02T00:00:00Z", { asset: HOST, severity: "Critical" }),
      ...burst("post-", "2026-08-17T10:00:00Z", 4, { asset: HOST }),
    ];
    const { kept, history } = splitHostHistory(events, hostBuildMarkers(renames));
    expect(history).toEqual([]);
    expect(kept).toHaveLength(events.length);
  });

  it("uses the filtered set as-is, however small", () => {
    const events = [
      ...burst("iso-", "2024-04-01T00:00:00Z", 5, { asset: HOST }),
      ev("only", "2026-08-17T10:00:00Z", { asset: HOST }),
    ];
    const { kept } = splitHostHistory(events, hostBuildMarkers(renames));
    expect(kept.map((e) => e.id)).toEqual(["only"]);
    expect(detectGapsWithWaves(events, { hostHistory: hostBuildMarkers(renames) }).gaps).toEqual([]);
  });

  it("is a no-op without markers", () => {
    const events = labBox();
    expect(splitHostHistory(events).kept).toEqual(events);
  });
});

describe("gapOptionsFor", () => {
  it("carries the env thresholds plus the case's markers", () => {
    const opts = gapOptionsFor({ hostRenames: renames });
    expect(opts.minGapMinutes).toBeGreaterThan(0);
    expect(opts.hostHistory).toHaveLength(1);
    expect(gapOptionsFor({}).hostHistory).toEqual([]);
  });
});

describe("the scenario 017 shape end to end", () => {
  const ts = "2026-08-27T00:00:00.000Z";

  it("reports the build history once, as Info, and the intrusion dwell interval once, as Medium", () => {
    const events = labBox();
    const state = { ...emptyState("INC-TEST"), forensicTimeline: events, hostRenames: renames };
    const opts = gapOptionsFor(state);
    const { gaps, pattern } = detectGapsWithWaves(events, opts);
    // Only the post-provisioning silences remain: sessions → intrusion.
    expect(gaps.filter((g) => g.complete)).toHaveLength(1);
    expect(gaps[0].startTimestamp.startsWith("2026-08-17")).toBe(true);
    const withWaves = backfillActivityWaveFinding(state, pattern, ts);
    const withHistory = backfillHostHistoryNote(withWaves, opts.hostHistory, ts);
    const final = backfillSilenceGapFindings(withHistory, gaps, ts, opts.maxFindings);
    const history = final.findings.find((f) => f.id === HOST_HISTORY_FINDING_ID)!;
    expect(history.severity).toBe("Info");
    expect(history.title).toBe(
      `Host history before provisioning: ${HOST}: 18 events before 2025-12-05T18:00:00.000Z, first 2024-04-01T00:00:00.000Z`,
    );
    expect(
      final.findings.filter((f) => f.id.startsWith("f-gap-") && f.id !== HOST_HISTORY_FINDING_ID),
    ).toHaveLength(0);
    // The one remaining silence is sessions (Info) → intrusion (High): benign on one side, so no
    // dwell finding and no waves finding — the intrusion's own High rows carry the case.
    expect(final.findings.some((f) => f.id === "f-waves")).toBe(false);
    expect(
      final.forensicTimeline
        .filter((e) => e.relatedFindingIds.includes(HOST_HISTORY_FINDING_ID))
        .map((e) => e.id),
    ).toEqual(["iso-0", "prov-7"]);
  });

  it("emits no history row when nothing was set aside, and never duplicates it", () => {
    const state = {
      ...emptyState("INC-TEST"),
      forensicTimeline: burst("use-", "2026-08-17T10:00:00Z", 6, { asset: HOST }),
      hostRenames: renames,
    };
    expect(backfillHostHistoryNote(state, hostBuildMarkers(renames), ts)).toBe(state);
    const withRows = { ...emptyState("INC-TEST"), forensicTimeline: labBox(), hostRenames: renames };
    const once = backfillHostHistoryNote(withRows, hostBuildMarkers(renames), ts);
    expect(backfillHostHistoryNote(once, hostBuildMarkers(renames), ts)).toBe(once);
    expect(backfillHostHistoryNote(withRows, [], ts)).toBe(withRows);
  });
});
