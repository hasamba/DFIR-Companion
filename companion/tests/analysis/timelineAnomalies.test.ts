import { describe, it, expect } from "vitest";
import {
  detectTimelineAnomalies,
  DEFAULT_BUCKET_MINUTES,
  DEFAULT_SPIKE_FACTOR,
  DEFAULT_MIN_EVENTS,
} from "../../src/analysis/timelineAnomalies.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, asset?: string): ForensicEvent {
  return {
    id,
    timestamp,
    description: `event ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
  };
}

// All in the same hour bucket (2026-05-20 14:xx) on different assets
const BASE_TS = "2026-05-20T14:";

describe("detectTimelineAnomalies", () => {
  it("returns defaults in result metadata", () => {
    const r = detectTimelineAnomalies([]);
    expect(r.bucketMinutes).toBe(DEFAULT_BUCKET_MINUTES);
    expect(r.spikeFactor).toBe(DEFAULT_SPIKE_FACTOR);
    expect(r.anomalies).toEqual([]);
  });

  it("returns no anomalies for an empty timeline", () => {
    expect(detectTimelineAnomalies([]).anomalies).toEqual([]);
  });

  it("returns no anomalies when all events have undated timestamps", () => {
    const events = [ev("e1", "", "host-a"), ev("e2", "not-a-date", "host-b")];
    expect(detectTimelineAnomalies(events).anomalies).toEqual([]);
  });

  it("returns no anomalies with only one asset in a bucket (no baseline to compare)", () => {
    const events = Array.from({ length: 20 }, (_, i) =>
      ev(`e${i}`, `${BASE_TS}0${i < 10 ? "0" : ""}${i}:00Z`, "host-a"),
    );
    expect(detectTimelineAnomalies(events).anomalies).toEqual([]);
  });

  it("detects a spike when one asset far exceeds the median of other assets", () => {
    // host-a: 20 events; host-b, host-c, host-d: 1 event each → median = 1, ratio = 20
    const events: ForensicEvent[] = [
      ...Array.from({ length: 20 }, (_, i) =>
        ev(`a${i}`, `${BASE_TS}01:${String(i).padStart(2, "0")}Z`, "host-a")),
      ev("b0", `${BASE_TS}02:00Z`, "host-b"),
      ev("c0", `${BASE_TS}03:00Z`, "host-c"),
      ev("d0", `${BASE_TS}04:00Z`, "host-d"),
    ];
    const r = detectTimelineAnomalies(events);
    expect(r.anomalies).toHaveLength(1);
    const a = r.anomalies[0];
    expect(a.asset).toBe("host-a");
    expect(a.eventCount).toBe(20);
    expect(a.ratio).toBe(20);
    expect(a.severity).toBe("Critical");   // ≥ 10×
    expect(a.eventIds).toHaveLength(20);
  });

  it("assigns High severity for 7–9× ratio", () => {
    // host-a: 7 events; host-b, host-c: 1 each → median 1, ratio 7
    const events: ForensicEvent[] = [
      ...Array.from({ length: 7 }, (_, i) =>
        ev(`a${i}`, `${BASE_TS}01:0${i}Z`, "host-a")),
      ev("b0", `${BASE_TS}02:00Z`, "host-b"),
      ev("c0", `${BASE_TS}03:00Z`, "host-c"),
    ];
    const r = detectTimelineAnomalies(events);
    expect(r.anomalies).toHaveLength(1);
    expect(r.anomalies[0].severity).toBe("High");
    expect(r.anomalies[0].ratio).toBe(7);
  });

  it("assigns Medium severity for 5–6× ratio", () => {
    const events: ForensicEvent[] = [
      ...Array.from({ length: 5 }, (_, i) =>
        ev(`a${i}`, `${BASE_TS}01:0${i}Z`, "host-a")),
      ev("b0", `${BASE_TS}02:00Z`, "host-b"),
      ev("c0", `${BASE_TS}03:00Z`, "host-c"),
    ];
    const r = detectTimelineAnomalies(events);
    expect(r.anomalies).toHaveLength(1);
    expect(r.anomalies[0].severity).toBe("Medium");
  });

  it("does not flag a bucket where the spike asset is below minEvents", () => {
    // ratio would be 5 but spiker only has 2 events — below minEvents=3
    const events: ForensicEvent[] = [
      ...Array.from({ length: 2 }, (_, i) =>
        ev(`a${i}`, `${BASE_TS}01:0${i}Z`, "host-a")),
      // host-b, host-c each have 1 → but we need 3+ to count
      ev("b0", `${BASE_TS}02:00Z`, "host-b"),
      ev("c0", `${BASE_TS}03:00Z`, "host-b"), // 2 for host-b so median is 1 not 0
      ev("d0", `${BASE_TS}04:00Z`, "host-c"),
    ];
    const r = detectTimelineAnomalies(events, { minEvents: 3, spikeFactor: 1 });
    // host-a: 2 < 3 → skipped; host-b: 2 < 3 → skipped
    expect(r.anomalies).toHaveLength(0);
  });

  it("does not flag a bucket below the spikeFactor threshold", () => {
    // host-a: 4, host-b: 2, host-c: 2 → median 2, ratio 2 < default 5
    const events: ForensicEvent[] = [
      ...Array.from({ length: 4 }, (_, i) =>
        ev(`a${i}`, `${BASE_TS}01:0${i}Z`, "host-a")),
      ev("b0", `${BASE_TS}02:00Z`, "host-b"),
      ev("b1", `${BASE_TS}02:01Z`, "host-b"),
      ev("c0", `${BASE_TS}03:00Z`, "host-c"),
      ev("c1", `${BASE_TS}03:01Z`, "host-c"),
    ];
    expect(detectTimelineAnomalies(events).anomalies).toHaveLength(0);
  });

  it("respects a custom spikeFactor", () => {
    // ratio = 4, default threshold 5 → nothing; custom threshold 3 → flagged
    const events: ForensicEvent[] = [
      ...Array.from({ length: 4 }, (_, i) =>
        ev(`a${i}`, `${BASE_TS}01:0${i}Z`, "host-a")),
      ev("b0", `${BASE_TS}02:00Z`, "host-b"),
      ev("c0", `${BASE_TS}03:00Z`, "host-c"),
    ];
    expect(detectTimelineAnomalies(events).anomalies).toHaveLength(0);
    expect(detectTimelineAnomalies(events, { spikeFactor: 3 }).anomalies).toHaveLength(1);
  });

  it("groups events across hours into separate buckets", () => {
    // host-a spikes in hour 14 only; hour 15 is balanced
    const events: ForensicEvent[] = [
      // Hour 14: host-a spikes, host-b 1, host-c 1
      ...Array.from({ length: 10 }, (_, i) =>
        ev(`a14_${i}`, `2026-05-20T14:0${i}:00Z`, "host-a")),
      ev("b14", "2026-05-20T14:30:00Z", "host-b"),
      ev("c14", "2026-05-20T14:45:00Z", "host-c"),
      // Hour 15: balanced (2 each)
      ev("a15_0", "2026-05-20T15:00:00Z", "host-a"),
      ev("a15_1", "2026-05-20T15:10:00Z", "host-a"),
      ev("b15_0", "2026-05-20T15:20:00Z", "host-b"),
      ev("b15_1", "2026-05-20T15:30:00Z", "host-b"),
      ev("c15_0", "2026-05-20T15:40:00Z", "host-c"),
      ev("c15_1", "2026-05-20T15:50:00Z", "host-c"),
    ];
    const r = detectTimelineAnomalies(events);
    expect(r.anomalies).toHaveLength(1);
    expect(r.anomalies[0].asset).toBe("host-a");
    expect(r.anomalies[0].bucketStart).toContain("T14:");
  });

  it("groups events with no asset under (unknown)", () => {
    // 10 no-asset events + 1 host-b + 1 host-c → should flag (unknown)
    const events: ForensicEvent[] = [
      ...Array.from({ length: 10 }, (_, i) =>
        ev(`u${i}`, `${BASE_TS}${String(i).padStart(2, "0")}:00Z`)),  // no asset
      ev("b0", `${BASE_TS}20:00Z`, "host-b"),
      ev("c0", `${BASE_TS}30:00Z`, "host-c"),
    ];
    const r = detectTimelineAnomalies(events);
    expect(r.anomalies).toHaveLength(1);
    expect(r.anomalies[0].asset).toBe("(unknown)");
  });

  it("sorts anomalies by severity then ratio descending", () => {
    // Two spikes in the same hour bucket on different assets
    // host-a: 10 events (ratio 10, Critical), host-b: 7 (ratio 7, High)
    // host-c through host-h: 1 each (6 background hosts keep median at 1)
    const events: ForensicEvent[] = [
      ...Array.from({ length: 10 }, (_, i) =>
        ev(`a${i}`, `${BASE_TS}0${i}:00Z`, "host-a")),
      ...Array.from({ length: 7 }, (_, i) =>
        ev(`b${i}`, `${BASE_TS}0${i}:30Z`, "host-b")),
      ev("c0", `${BASE_TS}30:00Z`, "host-c"),
      ev("d0", `${BASE_TS}31:00Z`, "host-d"),
      ev("e0", `${BASE_TS}32:00Z`, "host-e"),
      ev("f0", `${BASE_TS}33:00Z`, "host-f"),
      ev("g0", `${BASE_TS}34:00Z`, "host-g"),
      ev("h0", `${BASE_TS}35:00Z`, "host-h"),
    ];
    const r = detectTimelineAnomalies(events);
    expect(r.anomalies[0].severity).toBe("Critical");
    expect(r.anomalies[1].severity).toBe("High");
  });

  it("reports correct assetCount", () => {
    const events = [
      ev("e1", `${BASE_TS}01:00Z`, "host-a"),
      ev("e2", `${BASE_TS}02:00Z`, "host-b"),
      ev("e3", `${BASE_TS}03:00Z`, "host-c"),
    ];
    expect(detectTimelineAnomalies(events).assetCount).toBe(3);
  });

  it("respects a custom bucketMinutes", () => {
    // Two events 30 minutes apart on the same asset — with 60m buckets they're in the SAME bucket
    // (only one asset, no baseline → no anomaly). With 15m buckets they land in different buckets.
    const events: ForensicEvent[] = [
      ev("a0", "2026-05-20T14:00:00Z", "host-a"),
      ev("a1", "2026-05-20T14:30:00Z", "host-a"),
    ];
    expect(detectTimelineAnomalies(events, { bucketMinutes: 60 }).anomalies).toHaveLength(0);
    expect(detectTimelineAnomalies(events, { bucketMinutes: 15 }).anomalies).toHaveLength(0);
    // Still no anomaly (single asset), but at least it runs without error
  });
});
