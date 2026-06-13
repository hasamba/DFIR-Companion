import { describe, it, expect } from "vitest";
import {
  detectBeacons,
  beaconEnvOptions,
  DEFAULT_BEACON_MIN_COUNT,
  DEFAULT_BEACON_MAX_JITTER_PCT,
} from "../../src/analysis/beaconDetect.js";
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

// Build N connection events from `host` to `dst:port`, spaced `intervalS` seconds apart starting at
// `startMs`, with an optional per-step jitter array (seconds) added to each gap.
function beaconEvents(
  prefix: string,
  host: string,
  dst: string,
  port: number | undefined,
  startISO: string,
  intervalS: number,
  count: number,
  jitterS: number[] = [],
): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  let ms = Date.parse(startISO);
  for (let i = 0; i < count; i++) {
    out.push(
      ev(`${prefix}${i}`, new Date(ms).toISOString(), {
        asset: host,
        dstIp: dst,
        ...(port !== undefined ? { port } : {}),
        action: "network_send",
        description: `${host} → ${dst}`,
      }),
    );
    const j = jitterS[i] ?? 0;
    ms += (intervalS + j) * 1000;
  }
  return out;
}

describe("detectBeacons", () => {
  it("returns nothing for an empty or non-network timeline", () => {
    expect(detectBeacons([])).toEqual([]);
    expect(
      detectBeacons([ev("e1", "2026-05-20T14:00:00Z"), ev("e2", "2026-05-20T14:05:00Z")]),
    ).toEqual([]);
  });

  it("flags a perfectly periodic outbound channel as a beacon", () => {
    const events = beaconEvents("b", "ALClient07", "185.10.20.30", 443, "2026-05-20T00:00:00Z", 60, 6);
    const beacons = detectBeacons(events);
    expect(beacons).toHaveLength(1);
    const b = beacons[0];
    expect(b.id).toBe("beacon-1");
    expect(b.source).toBe("ALClient07");
    expect(b.destIp).toBe("185.10.20.30");
    expect(b.destPort).toBe(443);
    expect(b.eventCount).toBe(6);
    expect(b.intervalSeconds).toBe(60);
    expect(b.jitterSeconds).toBe(0);
    expect(b.jitterPct).toBe(0);
    expect(b.severity).toBe("High"); // public destination
    expect(b.external).toBe(true);
    expect(b.eventIds).toEqual(["b0", "b1", "b2", "b3", "b4", "b5"]);
    expect(b.firstSeen).toBe("2026-05-20T00:00:00.000Z");
  });

  it("stays robust to a few off-cadence check-ins (median/MAD, not mean/stddev)", () => {
    // A clean hourly beacon, then one connection a full day later (operator burst / missed beacons).
    // Mean/stddev would be wrecked by the outlier; median/MAD shrugs it off and still flags it.
    const hourly = beaconEvents("h", "WKSTN-1", "185.220.101.47", 443, "2026-05-15T10:00:00Z", 3600, 10);
    const outlier = ev("late", "2026-05-16T09:30:00Z", {
      asset: "WKSTN-1", dstIp: "185.220.101.47", port: 443, action: "network_send",
    });
    const beacons = detectBeacons([...hourly, outlier]);
    expect(beacons).toHaveLength(1);
    expect(beacons[0].eventCount).toBe(11);
    expect(beacons[0].intervalSeconds).toBe(3600); // median period unaffected by the outlier
    expect(beacons[0].jitterPct).toBeLessThanOrEqual(20);
    expect(beacons[0].severity).toBe("High");
  });

  it("tolerates small jitter under the threshold but rejects irregular traffic", () => {
    // ~5% jitter around a 60s beacon → kept.
    const regular = beaconEvents(
      "r", "host1", "203.0.113.5", 8443, "2026-05-20T00:00:00Z", 60, 6,
      [3, -2, 2, -3, 1, 0],
    );
    expect(detectBeacons(regular)).toHaveLength(1);

    // Wildly varying gaps → human browsing, not a beacon.
    const irregular = beaconEvents(
      "i", "host1", "203.0.113.6", 80, "2026-05-20T00:00:00Z", 60, 6,
      [600, 5, 1200, 30, 900, 0],
    );
    expect(detectBeacons(irregular)).toEqual([]);
  });

  it("marks an internal destination Medium and a public destination High", () => {
    const internal = beaconEvents("in", "host1", "10.0.0.5", 445, "2026-05-20T00:00:00Z", 30, 6);
    const external = beaconEvents("ex", "host1", "91.92.93.94", 443, "2026-05-21T00:00:00Z", 30, 6);
    const beacons = detectBeacons([...internal, ...external]);
    expect(beacons).toHaveLength(2);
    // External sorts first (worst-first).
    expect(beacons[0].destIp).toBe("91.92.93.94");
    expect(beacons[0].severity).toBe("High");
    expect(beacons[1].destIp).toBe("10.0.0.5");
    expect(beacons[1].severity).toBe("Medium");
    expect(beacons.map((b) => b.id)).toEqual(["beacon-1", "beacon-2"]);
  });

  it("separates channels by (source, dest, port) tuple", () => {
    const a = beaconEvents("a", "hostA", "185.1.1.1", 443, "2026-05-20T00:00:00Z", 60, 6);
    const b = beaconEvents("b", "hostB", "185.1.1.1", 443, "2026-05-20T00:00:00Z", 60, 6);
    const c = beaconEvents("c", "hostA", "185.1.1.1", 8080, "2026-05-20T00:00:00Z", 60, 6);
    const beacons = detectBeacons([...a, ...b, ...c]);
    expect(beacons).toHaveLength(3);
    const keys = beacons.map((x) => `${x.source}:${x.destIp}:${x.destPort}`).sort();
    expect(keys).toEqual(["hostA:185.1.1.1:443", "hostA:185.1.1.1:8080", "hostB:185.1.1.1:443"]);
  });

  it("ignores tuples below the minimum event count", () => {
    const few = beaconEvents("f", "host1", "185.10.20.30", 443, "2026-05-20T00:00:00Z", 60, 4);
    expect(detectBeacons(few, { minCount: 5 })).toEqual([]);
    expect(detectBeacons(few, { minCount: 4 })).toHaveLength(1);
  });

  it("excludes inbound (network_receive) and destination-less events", () => {
    const inbound = beaconEvents("rx", "host1", "185.10.20.30", 443, "2026-05-20T00:00:00Z", 60, 6)
      .map((e) => ({ ...e, action: "network_receive" as const }));
    expect(detectBeacons(inbound)).toEqual([]);

    const noDest = Array.from({ length: 6 }, (_, i) =>
      ev(`n${i}`, new Date(Date.parse("2026-05-20T00:00:00Z") + i * 60_000).toISOString(), {
        asset: "host1",
      }),
    );
    expect(detectBeacons(noDest)).toEqual([]);
  });

  it("skips events with an unparseable timestamp", () => {
    const events = beaconEvents("b", "host1", "185.10.20.30", 443, "2026-05-20T00:00:00Z", 60, 6);
    events[2] = { ...events[2], timestamp: "not-a-date" };
    // One event drops → 5 remain, still ≥ minCount, but the gap across the hole widens the jitter.
    // The detector should still operate on the surviving 5 without throwing.
    const beacons = detectBeacons(events, { maxJitterPct: 100 });
    expect(beacons).toHaveLength(1);
    expect(beacons[0].eventCount).toBe(5);
  });

  it("falls back to srcIp for the source when asset is absent, else (unknown)", () => {
    const bySrc = beaconEvents("s", "", "185.10.20.30", 443, "2026-05-20T00:00:00Z", 60, 6).map(
      (e) => ({ ...e, asset: undefined, srcIp: "10.1.2.3" }),
    );
    expect(detectBeacons(bySrc)[0].source).toBe("10.1.2.3");

    const none = beaconEvents("u", "", "185.10.20.30", 443, "2026-05-20T00:00:00Z", 60, 6).map(
      (e) => ({ ...e, asset: undefined, srcIp: undefined }),
    );
    expect(detectBeacons(none)[0].source).toBe("(unknown)");
  });

  it("does not flag many events fired at the same instant (zero median interval)", () => {
    const sameTime = Array.from({ length: 6 }, (_, i) =>
      ev(`z${i}`, "2026-05-20T00:00:00Z", { asset: "host1", dstIp: "185.10.20.30", port: 443 }),
    );
    expect(detectBeacons(sameTime)).toEqual([]);
  });
});

describe("beaconEnvOptions", () => {
  it("defaults when env is unset", () => {
    delete process.env.DFIR_BEACON_MIN_COUNT;
    delete process.env.DFIR_BEACON_MAX_JITTER_PCT;
    expect(beaconEnvOptions()).toEqual({
      minCount: DEFAULT_BEACON_MIN_COUNT,
      maxJitterPct: DEFAULT_BEACON_MAX_JITTER_PCT,
    });
  });

  it("reads overrides from the environment", () => {
    process.env.DFIR_BEACON_MIN_COUNT = "8";
    process.env.DFIR_BEACON_MAX_JITTER_PCT = "10";
    expect(beaconEnvOptions()).toEqual({ minCount: 8, maxJitterPct: 10 });
    delete process.env.DFIR_BEACON_MIN_COUNT;
    delete process.env.DFIR_BEACON_MAX_JITTER_PCT;
  });
});
