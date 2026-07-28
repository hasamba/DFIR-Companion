import { describe, it, expect } from "vitest";
import {
  detectClockSkew,
  detectClockSkewFromTimeline,
  alignTimestamps,
  effectiveOffsets,
  stripAlignment,
  DEFAULT_SKEW_ALERT_MS,
  DEFAULT_MIN_ANCHORS,
} from "../../src/analysis/clockSkew.js";
import { correlationGroups } from "../../src/analysis/correlate.js";
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

// One anchor = the SAME artifact observed by the endpoint (on `host`) and by the DC. Each call makes
// a distinct artifact so correlate groups them pairwise rather than collapsing everything into one.
function anchorPair(i: number, host: string, hostSkewSec: number): ForensicEvent[] {
  const at = Date.parse("2026-05-20T14:00:00Z") + i * 600_000;
  return [
    ev(`${host}-${i}`, new Date(at + hostSkewSec * 1000).toISOString(), {
      asset: host, sha256: `hash${i}`, description: `logon ${i}`, sources: ["Velociraptor"],
    }),
    ev(`dc-${host}-${i}`, new Date(at).toISOString(), {
      asset: "DC01", sha256: `hash${i}`, description: `logon ${i}`, sources: ["Windows Security"],
    }),
  ];
}

const groupsOf = (events: ForensicEvent[]) => correlationGroups(events);

describe("detectClockSkew", () => {
  it("reports a zero offset when every host's anchors line up", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostA", 0));
    const { results } = detectClockSkew(groupsOf(events));
    expect(results.map((r) => r.hostKey)).toEqual(["dc01", "hosta"]);
    for (const r of results) {
      expect(r.offsetMs).toBe(0);
      expect(r.skewed).toBe(false);
      expect(r.qualified).toBe(true);
    }
  });

  it("detects a sub-minute skew and keeps it under the alert threshold", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostB", 30));
    const report = detectClockSkew(groupsOf(events));
    const byHost = new Map(report.results.map((r) => [r.hostKey, r]));
    // Offsets are expressed against the reference clock, which does not move.
    expect(report.referenceHost).toBe("DC01");
    expect(byHost.get("dc01")!.offsetMs).toBe(0);
    expect(byHost.get("hostb")!.offsetMs).toBe(30_000);
    expect(byHost.get("hostb")!.skewed).toBe(false);   // 30s < 60s alert threshold
    expect(byHost.get("hostb")!.anchorCount).toBe(3);
  });

  // The review's PROBE 1: the old detector discarded any anchor whose members were more than 60s
  // apart, so the multi-hour offsets it exists to catch were invisible.
  it("detects an hours-scale timezone offset (regression: 60s matching window)", () => {
    const events = [0, 1, 2, 3].flatMap((i) => anchorPair(i, "hostTZ", 2 * 3600));
    const byHost = new Map(detectClockSkew(groupsOf(events)).results.map((r) => [r.hostKey, r]));
    expect(byHost.get("hosttz")!.offsetMs).toBe(2 * 3_600_000);
    expect(byHost.get("dc01")!.offsetMs).toBe(0);
    expect(byHost.get("hosttz")!.skewed).toBe(true);
    expect(byHost.get("hosttz")!.confidence).not.toBe("low");
  });

  it("detects the 7-minute NTP drift from the issue", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostNtp", 7 * 60));
    const byHost = new Map(detectClockSkew(groupsOf(events)).results.map((r) => [r.hostKey, r]));
    expect(byHost.get("hostntp")!.offsetMs).toBe(420_000);
    expect(byHost.get("hostntp")!.skewed).toBe(true);
  });

  // The review's PROBE 3: two unrelated events sharing a generic description used to be reported as
  // a confident skew. Anchors now come from correlation groups, which never match on description.
  it("ignores unrelated events that merely share a description (regression: false anchors)", () => {
    const events = [
      ev("a1", "2026-05-20T14:00:00Z", { asset: "hostA", description: "Suspicious PowerShell execution", sources: ["Velociraptor"] }),
      ev("b1", "2026-05-20T14:00:20Z", { asset: "hostB", description: "Suspicious PowerShell execution", sources: ["THOR"] }),
    ];
    expect(detectClockSkew(groupsOf(events)).results).toEqual([]);
  });

  // The review's PROBE 4: a host that logged an artifact three times used to outvote a host that
  // logged it once, dragging the consensus onto itself.
  it("weights the consensus by host, not by event count (regression: count weighting)", () => {
    const events = [0, 1, 2].flatMap((i) => {
      const at = Date.parse("2026-05-20T14:00:00Z") + i * 600_000;
      return [
        // hostA reports the same artifact three times, a couple of seconds apart.
        ev(`a-${i}-1`, new Date(at).toISOString(), { asset: "hostA", sha256: `h${i}`, sources: ["Velociraptor"] }),
        ev(`a-${i}-2`, new Date(at + 2_000).toISOString(), { asset: "hostA", sha256: `h${i}`, sources: ["Velociraptor"] }),
        ev(`a-${i}-3`, new Date(at + 4_000).toISOString(), { asset: "hostA", sha256: `h${i}`, sources: ["Velociraptor"] }),
        ev(`b-${i}`, new Date(at + 30_000).toISOString(), { asset: "hostB", sha256: `h${i}`, sources: ["THOR"] }),
      ];
    });
    const byHost = new Map(detectClockSkew(groupsOf(events)).results.map((r) => [r.hostKey, r]));
    // hostA's representative is its median (at+2s), NOT its earliest — so hostB sits 28s after it,
    // where event-count weighting would have dragged the gap toward 30s.
    expect(byHost.get("hosta")!.offsetMs).toBe(0);
    expect(byHost.get("hostb")!.offsetMs).toBe(28_000);
  });

  it("needs corroboration from a second tool before calling a gap skew", () => {
    // One tool reporting the same file on two hosts: this is file propagation, not two clocks.
    const events = [0, 1, 2].flatMap((i) => {
      const at = Date.parse("2026-05-20T14:00:00Z") + i * 600_000;
      return [
        ev(`a-${i}`, new Date(at).toISOString(), { asset: "hostA", sha256: `h${i}`, sources: ["Velociraptor"] }),
        ev(`b-${i}`, new Date(at + 30_000).toISOString(), { asset: "hostB", sha256: `h${i}`, sources: ["Velociraptor"] }),
      ];
    });
    expect(detectClockSkew(groupsOf(events)).results).toEqual([]);
  });

  it("refuses to align a host whose samples scatter (propagation, not skew)", () => {
    // Same artifact, two tools, but the gap varies wildly run to run — that is travel time.
    const events = [4, 260, 35, 610, 90].flatMap((gapSec, i) => anchorPair(i, "hostVar", gapSec));
    const host = detectClockSkew(groupsOf(events)).results.find((r) => r.hostKey === "hostvar")!;
    expect(host.anchorCount).toBe(5);
    expect(host.dispersionMs).toBeGreaterThan(5_000);
    expect(host.qualified).toBe(false);
    expect(host.confidence).toBe("low");
    expect(host.skewed).toBe(false);
    // ...and nothing scattered ever reaches alignment.
    expect(effectiveOffsets([host]).size).toBe(0);
  });

  it("holds back an offset until it has the minimum number of anchors", () => {
    const events = [0, 1].flatMap((i) => anchorPair(i, "hostThin", 300));
    const byHost = new Map(detectClockSkew(groupsOf(events)).results.map((r) => [r.hostKey, r]));
    expect(byHost.get("hostthin")!.anchorCount).toBe(2);
    expect(byHost.get("hostthin")!.qualified).toBe(false);
    expect(byHost.get("hostthin")!.skewed).toBe(false);
    // Lowering the bar surfaces the same measurement.
    const relaxed = detectClockSkew(groupsOf(events), { minAnchors: 2 });
    expect(relaxed.results.find((r) => r.hostKey === "hostthin")!.qualified).toBe(true);
  });

  it("treats FQDN and short hostnames as one clock", () => {
    const events = [0, 1, 2].flatMap((i) => {
      const at = Date.parse("2026-05-20T14:00:00Z") + i * 600_000;
      const asset = i === 0 ? "FILE-BO-01" : "FILE-BO-01.northstar.local";
      return [
        ev(`h-${i}`, new Date(at + 120_000).toISOString(), { asset, sha256: `h${i}`, sources: ["Velociraptor"] }),
        ev(`dc-${i}`, new Date(at).toISOString(), { asset: "DC01", sha256: `h${i}`, sources: ["Windows Security"] }),
      ];
    });
    const results = detectClockSkew(groupsOf(events)).results;
    expect(results.map((r) => r.hostKey).sort()).toEqual(["dc01", "file-bo-01"]);
    expect(results.find((r) => r.hostKey === "file-bo-01")!.anchorCount).toBe(3);
  });

  it("ignores an anchor group whose members sit implausibly far apart", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostOld", 60 * 24 * 3600));
    expect(detectClockSkew(groupsOf(events)).results).toEqual([]);
  });

  it("reports how much evidence it had", () => {
    const report = detectClockSkew(groupsOf([0, 1, 2].flatMap((i) => anchorPair(i, "hostA", 30))));
    expect(report.anchorGroups).toBe(3);
    expect(report.groupsExamined).toBe(3);
  });

  it("exposes the documented defaults", () => {
    expect(DEFAULT_SKEW_ALERT_MS).toBe(60_000);
    expect(DEFAULT_MIN_ANCHORS).toBe(3);
  });

  it("derives its own groups from a raw timeline", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostA", 30));
    expect(detectClockSkewFromTimeline(events).results).toEqual(detectClockSkew(groupsOf(events)).results);
  });
});

describe("effectiveOffsets", () => {
  const detected = {
    host: "hostB", hostKey: "hostb", offsetMs: 15_000, anchorCount: 4, dispersionMs: 0,
    confidence: "medium" as const, qualified: true, skewed: false, sources: ["THOR"],
  };

  it("uses qualified detections", () => {
    expect([...effectiveOffsets([detected])]).toEqual([["hostb", 15_000]]);
  });

  it("lets an analyst override a detected offset", () => {
    expect(effectiveOffsets([detected], { hostB: 42_000 }).get("hostb")).toBe(42_000);
  });

  it("lets an analyst set an offset the detector never found", () => {
    expect(effectiveOffsets([], { "HOST-C.corp.local": -7_000 }).get("host-c")).toBe(-7_000);
  });

  it("treats an explicit zero override as 'this clock is correct'", () => {
    expect(effectiveOffsets([detected], { hostB: 0 }).has("hostb")).toBe(false);
  });

  it("ignores unqualified detections", () => {
    expect(effectiveOffsets([{ ...detected, qualified: false }]).size).toBe(0);
  });
});

describe("alignTimestamps", () => {
  const events: ForensicEvent[] = [
    ev("a1", "2026-05-20T14:00:00.000Z", { asset: "hostA" }),
    ev("b1", "2026-05-20T14:02:00.000Z", { asset: "hostB" }),
    ev("b2", "2026-05-20T14:05:00.000Z", { asset: "hostB", endTimestamp: "2026-05-20T14:06:00.000Z" }),
  ];

  it("shifts a host's events and keeps the recorded time as evidence", () => {
    const byId = new Map(alignTimestamps(events, new Map([["hostb", 120_000]])).map((e) => [e.id, e]));
    expect(byId.get("b1")!.timestamp).toBe("2026-05-20T14:00:00.000Z");
    expect(byId.get("b1")!.originalTimestamp).toBe("2026-05-20T14:02:00.000Z");
    expect(byId.get("b1")!.skewOffsetMs).toBe(120_000);
    expect(byId.get("b2")!.endTimestamp).toBe("2026-05-20T14:04:00.000Z");
    // An unshifted host is untouched — no projection fields at all.
    expect(byId.get("a1")!.originalTimestamp).toBeUndefined();
  });

  it("re-sorts the timeline it returns", () => {
    const aligned = alignTimestamps(events, new Map([["hostb", 600_000]]));
    expect(aligned.map((e) => e.id)).toEqual(["b1", "b2", "a1"]);
    const times = aligned.map((e) => Date.parse(e.timestamp));
    expect([...times].sort((x, y) => x - y)).toEqual(times);
  });

  it("leaves undated events at the end rather than at the epoch", () => {
    const withUndated = [...events, ev("u1", "", { asset: "hostA" })];
    expect(alignTimestamps(withUndated, new Map([["hostb", 120_000]])).at(-1)!.id).toBe("u1");
  });

  it("is a no-op when no host qualifies", () => {
    expect(alignTimestamps(events, new Map())).toEqual(events);
  });

  it("round-trips through stripAlignment", () => {
    const restored = stripAlignment(alignTimestamps(events, new Map([["hostb", 120_000]])));
    expect([...restored].sort((a, b) => a.id.localeCompare(b.id)))
      .toEqual([...events].sort((a, b) => a.id.localeCompare(b.id)));
    for (const e of restored) {
      expect(e.originalTimestamp).toBeUndefined();
      expect(e.skewOffsetMs).toBeUndefined();
    }
  });
});
