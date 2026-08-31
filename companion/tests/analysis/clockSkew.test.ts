import { describe, it, expect } from "vitest";
import {
  detectClockSkew,
  detectClockSkewFromTimeline,
  detectHostTimeGaps,
  hostKey,
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
      asset: host,
      sha256: `hash${i}`,
      description: `logon ${i}`,
      sources: ["Velociraptor"],
    }),
    ev(`dc-${host}-${i}`, new Date(at).toISOString(), {
      asset: "DC01",
      sha256: `hash${i}`,
      description: `logon ${i}`,
      sources: ["Windows Security"],
    }),
  ];
}

// Anchors are cross-host by definition — one artifact stamped by two machines' clocks — so skew
// detection asks correlate for the cross-host view that merging deliberately does not use (#345).
const groupsOf = (events: ForensicEvent[]) => correlationGroups(events, { crossHostArtifacts: true });

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
    expect(byHost.get("hostb")!.skewed).toBe(false); // 30s < 60s alert threshold
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
      ev("a1", "2026-05-20T14:00:00Z", {
        asset: "hostA",
        description: "Suspicious PowerShell execution",
        sources: ["Velociraptor"],
      }),
      ev("b1", "2026-05-20T14:00:20Z", {
        asset: "hostB",
        description: "Suspicious PowerShell execution",
        sources: ["THOR"],
      }),
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
        ev(`a-${i}-1`, new Date(at).toISOString(), {
          asset: "hostA",
          sha256: `h${i}`,
          sources: ["Velociraptor"],
        }),
        ev(`a-${i}-2`, new Date(at + 2_000).toISOString(), {
          asset: "hostA",
          sha256: `h${i}`,
          sources: ["Velociraptor"],
        }),
        ev(`a-${i}-3`, new Date(at + 4_000).toISOString(), {
          asset: "hostA",
          sha256: `h${i}`,
          sources: ["Velociraptor"],
        }),
        ev(`b-${i}`, new Date(at + 30_000).toISOString(), {
          asset: "hostB",
          sha256: `h${i}`,
          sources: ["THOR"],
        }),
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
        ev(`a-${i}`, new Date(at).toISOString(), {
          asset: "hostA",
          sha256: `h${i}`,
          sources: ["Velociraptor"],
        }),
        ev(`b-${i}`, new Date(at + 30_000).toISOString(), {
          asset: "hostB",
          sha256: `h${i}`,
          sources: ["Velociraptor"],
        }),
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
        ev(`h-${i}`, new Date(at + 120_000).toISOString(), {
          asset,
          sha256: `h${i}`,
          sources: ["Velociraptor"],
        }),
        ev(`dc-${i}`, new Date(at).toISOString(), {
          asset: "DC01",
          sha256: `h${i}`,
          sources: ["Windows Security"],
        }),
      ];
    });
    const results = detectClockSkew(groupsOf(events)).results;
    expect(results.map((r) => r.hostKey).sort()).toEqual(["dc01", "file-bo-01"]);
    expect(results.find((r) => r.hostKey === "file-bo-01")!.anchorCount).toBe(3);
  });

  // The cap is a sanity bound on "these two records describe one real-world event", not a bound on
  // how wrong a clock may be — a 60-day offset used to be rejected here, which is what made #740's
  // multi-month VM skew undetectable by construction. Consistency across anchors is the real
  // discriminator, so the cap now sits at a year and 60 days is measured like any other offset.
  it("ignores an anchor group whose members sit implausibly far apart", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostOld", 500 * 24 * 3600));
    expect(detectClockSkew(groupsOf(events)).results).toEqual([]);
  });

  it("measures a two-month offset that the old 48-hour cap threw away", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostOld", 60 * 24 * 3600));
    const old = detectClockSkew(groupsOf(events)).results.find((r) => r.hostKey === "hostold")!;
    expect(old.qualified).toBe(true);
    expect(Math.round(old.offsetMs / 86_400_000)).toBe(60);
  });

  // Codex review of #740: three files deployed in bulk and re-observed by a second tool months
  // later produce one anchor group each, and those propagation intervals can agree well inside the
  // 5s dispersion ceiling. Consistency alone therefore cannot license a year-scale correction, so a
  // large offset is measured and flagged but never aligned on without the analyst saying so.
  it("reports a months-large offset but refuses to align on it unattended", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostOld", 60 * 24 * 3600));
    const old = detectClockSkew(groupsOf(events)).results.find((r) => r.hostKey === "hostold")!;
    expect(old.qualified).toBe(true);
    expect(old.skewed).toBe(true);
    expect(old.alignable).toBe(false);
    expect(effectiveOffsets([old]).size).toBe(0);
  });

  it("still aligns on an ordinary offset inside the auto-align ceiling", () => {
    const events = [0, 1, 2].flatMap((i) => anchorPair(i, "hostA", 120));
    const a = detectClockSkew(groupsOf(events)).results.find((r) => r.hostKey === "hosta")!;
    expect(a.alignable).toBe(true);
    expect(effectiveOffsets([a]).get("hosta")).toBe(120_000);
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
    host: "hostB",
    hostKey: "hostb",
    offsetMs: 15_000,
    anchorCount: 4,
    dispersionMs: 0,
    confidence: "medium" as const,
    qualified: true,
    alignable: true,
    skewed: false,
    sources: ["THOR"],
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
    expect(effectiveOffsets([{ ...detected, qualified: false, alignable: false }]).size).toBe(0);
  });

  // A months-wrong clock is measured and flagged, but applying it rewrites every timestamp on the
  // host — too consequential to do unasked when consistency alone cannot rule out a propagation
  // pattern that merely looks consistent. The analyst turns it on with an override.
  it("does not auto-apply a qualified offset that is too large to align on", () => {
    const huge = { ...detected, offsetMs: 268 * 86_400_000, skewed: true, alignable: false };
    expect(effectiveOffsets([huge]).size).toBe(0);
    expect(effectiveOffsets([huge], { hostB: 268 * 86_400_000 }).get("hostb")).toBe(268 * 86_400_000);
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
    expect([...restored].sort((a, b) => a.id.localeCompare(b.id))).toEqual(
      [...events].sort((a, b) => a.id.localeCompare(b.id)),
    );
    for (const e of restored) {
      expect(e.originalTimestamp).toBeUndefined();
      expect(e.skewOffsetMs).toBeUndefined();
    }
  });
});

describe("detectHostTimeGaps (#740)", () => {
  // A host's own distribution, no second clock involved: 17 of 214 events dated ~9 months early,
  // the shape of the lab VM on case INC-2026-020.
  function host(name: string, iso: string, count: number, startId: number): ForensicEvent[] {
    const at = Date.parse(iso);
    return Array.from({ length: count }, (_, i) =>
      ev(`${name}-${startId + i}`, new Date(at + i * 60_000).toISOString(), {
        asset: name,
        sources: ["Velociraptor"],
      }),
    );
  }

  it("warns when a small minority of a host's events sits months from the rest", () => {
    const events = [
      ...host("WIN-UK1GV882OK6", "2026-08-30T09:00:00Z", 197, 0),
      ...host("WIN-UK1GV882OK6", "2025-12-05T03:27:00Z", 17, 500),
    ];
    const [gap] = detectHostTimeGaps(events);
    expect(gap.hostKey).toBe("win-uk1gv882ok6");
    expect(gap.minorityCount).toBe(17);
    expect(gap.totalCount).toBe(214);
    expect(gap.minoritySide).toBe("before");
    expect(Math.round(gap.gapMs / 86_400_000)).toBe(268);
    expect(gap.sources).toEqual(["Velociraptor"]);
  });

  it("stays silent on a host whose evidence legitimately spans years", () => {
    // An MFT or registry collection always splits wide. Half the evidence on each side is normal.
    const events = [
      ...host("FILE01", "2024-01-01T00:00:00Z", 30, 0),
      ...host("FILE01", "2026-01-01T00:00:00Z", 30, 500),
    ];
    expect(detectHostTimeGaps(events)).toEqual([]);
  });

  it("stays silent below the gap and event-count thresholds", () => {
    const tight = [
      ...host("WS01", "2026-08-30T09:00:00Z", 40, 0),
      ...host("WS01", "2026-08-25T09:00:00Z", 4, 500),
    ];
    expect(detectHostTimeGaps(tight)).toEqual([]); // 5 days apart — under the 30-day floor
    const tiny = [
      ...host("WS02", "2026-08-30T09:00:00Z", 8, 0),
      ...host("WS02", "2025-01-01T09:00:00Z", 1, 500),
    ];
    expect(detectHostTimeGaps(tiny)).toEqual([]); // 9 dated events — under the min-events floor
  });

  it("ignores events with no asset or no parseable time", () => {
    const events = [
      ...host("WS03", "2026-08-30T09:00:00Z", 20, 0),
      ...host("WS03", "2025-01-01T09:00:00Z", 3, 500),
      ev("noasset", "2020-01-01T00:00:00Z"),
      ev("undated", "", { asset: "WS03" }),
    ];
    const [gap] = detectHostTimeGaps(events);
    expect(gap.totalCount).toBe(23);
    expect(gap.minorityCount).toBe(3);
  });

  it("reports the widest gap first", () => {
    const events = [
      ...host("A", "2026-08-30T09:00:00Z", 20, 0),
      ...host("A", "2026-05-01T09:00:00Z", 3, 500),
      ...host("B", "2026-08-30T09:00:00Z", 20, 0),
      ...host("B", "2024-01-01T09:00:00Z", 3, 500),
    ];
    expect(detectHostTimeGaps(events).map((g) => g.hostKey)).toEqual(["b", "a"]);
  });
});

// Codex review of #740: hostKey truncated at the first dot, so every address on a /8 collapsed onto
// the key "10" — one machine's offsets and gaps reported under another machine's name, and (through
// correlate's shortHost, the same rule) two hosts merged where the split IS the lateral movement.
describe("hostKey on IP-literal assets", () => {
  it("keeps distinct IPv4 assets distinct", () => {
    expect(hostKey("10.1.1.5")).toBe("10.1.1.5");
    expect(hostKey("10.2.2.6")).toBe("10.2.2.6");
    expect(hostKey("10.1.1.5")).not.toBe(hostKey("10.2.2.6"));
  });

  it("keeps IPv6 literals whole, dotted-quad tail included", () => {
    expect(hostKey("FE80::1")).toBe("fe80::1");
    expect(hostKey("::ffff:10.0.0.1")).toBe("::ffff:10.0.0.1");
  });

  it("still folds an FQDN onto its short hostname", () => {
    expect(hostKey("FILE-BO-01.corp.local")).toBe("file-bo-01");
    expect(hostKey("  WS-01  ")).toBe("ws-01");
  });

  it("does not fold two hosts on one subnet into a single gap warning", () => {
    const rows = (asset: string, iso: string, n: number, seed: number) =>
      Array.from({ length: n }, (_, i) =>
        ev(`${seed + i}`, new Date(Date.parse(iso) + i * 60_000).toISOString(), { asset }),
      );
    // Two DIFFERENT machines, each internally consistent. Folded onto "10" their combined rows
    // straddle a nine-month gap and manufacture a warning about a clock that is perfectly fine.
    const events = [
      ...rows("10.1.1.5", "2026-08-30T09:00:00Z", 20, 0),
      ...rows("10.2.2.6", "2025-12-05T03:27:00Z", 3, 500),
    ];
    expect(detectHostTimeGaps(events)).toEqual([]);
  });
});
