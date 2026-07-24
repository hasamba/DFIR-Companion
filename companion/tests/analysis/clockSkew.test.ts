import { describe, it, expect } from "vitest";
import {
  detectClockSkew,
  alignTimestamps,
  DEFAULT_SKEW_THRESHOLD_MS,
} from "../../src/analysis/clockSkew.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("detectClockSkew", () => {
  it("returns no skew when every host's anchors line up", () => {
    const events: ForensicEvent[] = [
      ev("a1", "2026-05-20T14:00:00Z", { asset: "hostA", sha256: "h", description: "drop" }),
      ev("b1", "2026-05-20T14:00:00Z", { asset: "hostB", sha256: "h", description: "drop" }),
      ev("a2", "2026-05-20T14:05:00Z", { asset: "hostA", sha256: "h2", description: "exec" }),
      ev("b2", "2026-05-20T14:05:00Z", { asset: "hostB", sha256: "h2", description: "exec" }),
    ];
    const results = detectClockSkew(events);
    expect(results).toHaveLength(2);
    expect(results[0].offsetMs).toBe(0);
    expect(results[1].offsetMs).toBe(0);
    expect(results[0].anchorCount).toBe(2);
    expect(results[0].confidence).toBe(2);
  });

  it("detects a constant skew when one host's clock is ahead", () => {
    // 30s ahead — within the default 60s pairing window so the anchors match. With two hosts the
    // consensus reference is the midpoint (14:00:15), so each host is ±15s from it; the relative
    // difference between the two hosts is the full 30s skew.
    const events: ForensicEvent[] = [
      ev("a1", "2026-05-20T14:00:00Z", { asset: "hostA", sha256: "h", description: "drop" }),
      ev("b1", "2026-05-20T14:00:30Z", { asset: "hostB", sha256: "h", description: "drop" }),
      ev("a2", "2026-05-20T14:05:00Z", { asset: "hostA", sha256: "h2", description: "exec" }),
      ev("b2", "2026-05-20T14:05:30Z", { asset: "hostB", sha256: "h2", description: "exec" }),
    ];
    const results = detectClockSkew(events);
    const byHost = new Map(results.map((r) => [r.host, r]));
    expect(byHost.get("hostB")!.offsetMs).toBe(15_000);
    expect(byHost.get("hostA")!.offsetMs).toBe(-15_000);
    expect(byHost.get("hostB")!.offsetMs - byHost.get("hostA")!.offsetMs).toBe(30_000);
    expect(byHost.get("hostB")!.anchorCount).toBe(2);
  });

  it("alignTimestamps virtually shifts events by the detected offset", () => {
    const skewResults = [
      { host: "hostB", offsetMs: 120_000, anchorCount: 2, confidence: 2 },
    ];
    const events: ForensicEvent[] = [
      ev("a1", "2026-05-20T14:00:00Z", { asset: "hostA" }),
      ev("b1", "2026-05-20T14:02:00Z", { asset: "hostB" }),
      ev("b2", "2026-05-20T14:05:00Z", { asset: "hostB", endTimestamp: "2026-05-20T14:06:00Z" }),
    ];
    const aligned = alignTimestamps(events, skewResults);
    expect(aligned[0].timestamp).toBe("2026-05-20T14:00:00Z");
    expect(aligned[1].timestamp).toBe("2026-05-20T14:00:00.000Z");
    expect(aligned[2].timestamp).toBe("2026-05-20T14:03:00.000Z");
    expect(aligned[2].endTimestamp).toBe("2026-05-20T14:04:00.000Z");
  });

  it("respects the threshold: anchors farther apart than threshold are ignored", () => {
    const events: ForensicEvent[] = [
      ev("a1", "2026-05-20T14:00:00Z", { asset: "hostA", sha256: "h", description: "drop" }),
      ev("b1", "2026-05-20T14:05:00Z", { asset: "hostB", sha256: "h", description: "drop" }),
    ];
    expect(detectClockSkew(events)).toHaveLength(0);
  });

  it("honors a custom threshold when anchors are close within it", () => {
    const events: ForensicEvent[] = [
      ev("a1", "2026-05-20T14:00:00Z", { asset: "hostA", sha256: "h", description: "drop" }),
      ev("b1", "2026-05-20T14:05:00Z", { asset: "hostB", sha256: "h", description: "drop" }),
    ];
    expect(detectClockSkew(events, { thresholdMs: 600_000 })).toHaveLength(2);
    expect(detectClockSkew(events, { thresholdMs: 60_000 })).toHaveLength(0);
  });

  it("detects skew across multiple hosts against the consensus reference", () => {
    // Three hosts: hostA 0s, hostB +10s, hostC -20s (spread 30s, within the 60s default). The
    // consensus reference per anchor is the median of the three host times = hostA's time, so
    // hostA's offset is 0 and the others are their raw deltas.
    const base = "2026-05-20T14:00:00Z";
    function anchor(i: number, host: string, deltaSec: number): ForensicEvent {
      return ev(`${host}-${i}`, new Date(Date.parse(base) + i * 600_000 + deltaSec * 1000).toISOString(), {
        asset: host, sha256: `hash${i}`, description: `event${i}`,
      });
    }
    const events: ForensicEvent[] = [
      anchor(0, "hostA", 0), anchor(0, "hostB", 10), anchor(0, "hostC", -20),
      anchor(1, "hostA", 0), anchor(1, "hostB", 10), anchor(1, "hostC", -20),
    ];
    const results = detectClockSkew(events);
    const byHost = new Map(results.map((r) => [r.host, r]));
    expect(results).toHaveLength(3);
    expect(byHost.get("hostA")!.offsetMs).toBe(0);
    expect(byHost.get("hostB")!.offsetMs).toBe(10_000);
    expect(byHost.get("hostC")!.offsetMs).toBe(-20_000);
    for (const r of results) expect(r.anchorCount).toBe(2);
  });

  it("ignores single-host anchors (nothing to compare)", () => {
    const events: ForensicEvent[] = [
      ev("a1", "2026-05-20T14:00:00Z", { asset: "hostA", sha256: "h", description: "drop" }),
      ev("a2", "2026-05-20T14:01:00Z", { asset: "hostA", sha256: "h2", description: "exec" }),
    ];
    expect(detectClockSkew(events)).toHaveLength(0);
  });

  it("defaults the threshold to 60 seconds", () => {
    expect(DEFAULT_SKEW_THRESHOLD_MS).toBe(60_000);
  });
});
