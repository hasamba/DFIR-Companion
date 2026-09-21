// A complete silence bounded on both sides by the collector's own rows is idle time between two of
// our visits, not a coverage gap (#1500). Anything less than that — one real edge, a partial gap —
// stands as before.
import { describe, it, expect } from "vitest";
import { detectTimelineGaps } from "../../src/analysis/gapDetect.js";
import { dropCollectorBoundedGaps } from "../../src/analysis/gapCollectorEdges.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Chainsaw"],
    ...extra,
  };
}

function series(
  prefix: string,
  startISO: string,
  intervalS: number,
  count: number,
  extra: Partial<ForensicEvent> = {},
) {
  const out: ForensicEvent[] = [];
  let ms = Date.parse(startISO);
  for (let i = 0; i < count; i++) {
    out.push(ev(`${prefix}${i}`, new Date(ms).toISOString(), extra));
    ms += intervalS * 1000;
  }
  return out;
}

// Ten collector rows a second apart (a PersistenceSniper run), thirty quiet minutes, ten more.
const run1 = series("r", "2026-09-21T15:08:00Z", 1, 10, { origin: "collector" });
const run2 = series("s", "2026-09-21T15:38:41Z", 1, 10, { origin: "collector" });

describe("dropCollectorBoundedGaps", () => {
  it("drops the complete gap between two collector runs", () => {
    expect(detectTimelineGaps([...run1, ...run2])).toEqual([]);
  });

  it("keeps the gap when the LAST row before the silence is real host activity", () => {
    const host = ev("h", "2026-09-21T15:08:20Z", { severity: "High", description: "rclone.exe copy" });
    const gaps = detectTimelineGaps([...run1, host, ...run2]);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].beforeEventId).toBe("h");
  });

  it("keeps the gap when the FIRST row after the silence is real host activity", () => {
    const host = ev("h", "2026-09-21T15:38:30Z", { severity: "High" });
    const gaps = detectTimelineGaps([...run1, host, ...run2]);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].afterEventId).toBe("h");
  });

  it("leaves a partial per-source gap alone even when its edges are collector rows", () => {
    // Sysmon (collector rows) goes quiet for an hour while the MFT keeps logging every minute.
    const sysmon = [
      ev("c1", "2026-09-21T15:00:00Z", { sources: ["Sysmon"], origin: "collector" }),
      ev("c2", "2026-09-21T16:00:00Z", { sources: ["Sysmon"], origin: "collector" }),
    ];
    const mft = series("m", "2026-09-21T15:00:30Z", 60, 60, { sources: ["MFT"] });
    const gaps = detectTimelineGaps([...sysmon, ...mft], { densityFactor: 0 });
    const partial = gaps.filter((g) => !g.complete);
    expect(partial).toHaveLength(1);
    expect(partial[0].silentSources).toEqual(["Sysmon"]);
  });

  it("is a pure filter over the gaps it is given", () => {
    const events = [...run1, ...run2];
    const gap = {
      id: "gap-1",
      startTimestamp: run1[9].timestamp,
      endTimestamp: run2[0].timestamp,
      durationSeconds: 1832,
      durationLabel: "30m",
      severity: "High" as const,
      complete: true,
      silentSources: ["Chainsaw"],
      activeSources: [],
      beforeEventId: "r9",
      afterEventId: "s0",
    };
    expect(dropCollectorBoundedGaps([gap], events)).toEqual([]);
    expect(dropCollectorBoundedGaps([{ ...gap, complete: false }], events)).toHaveLength(1);
    expect(dropCollectorBoundedGaps([{ ...gap, beforeEventId: "nope" }], events)).toHaveLength(1);
  });
});
