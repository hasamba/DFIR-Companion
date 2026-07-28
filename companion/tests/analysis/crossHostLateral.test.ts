import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { buildEvidenceGraph } from "../../src/analysis/evidenceGraph.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// The failure #345 was filed for, end to end: correlation used to eat the lateral_move edge that
// the evidence graph derives from one binary appearing on two hosts.
const SHA = "a".repeat(64);
function ev(id: string, timestamp: string, asset: string, source: string): ForensicEvent {
  return {
    id, timestamp, description: `beacon.exe dropped on ${asset}`, severity: "High",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    asset, sha256: SHA, sources: [source],
  };
}
const raw = [
  ev("e1", "2026-05-20T14:00:00Z", "WS-01", "Velociraptor"),
  ev("e2", "2026-05-20T14:40:00Z", "SRV-02", "THOR"),
];
const lateral = (timeline: ForensicEvent[]) =>
  buildEvidenceGraph({ ...emptyState("c1"), forensicTimeline: timeline })
    .edges.filter((e) => e.type === "lateral_move");

describe("cross-host lateral movement survives correlation (#345)", () => {
  it("is present on the raw timeline", () => {
    expect(lateral(raw)).toHaveLength(1);
  });

  it("is still present after correlation", () => {
    const correlated = correlateEvents(raw);
    expect(correlated).toHaveLength(2);
    expect(lateral(correlated)).toHaveLength(1);
    expect(lateral(correlated)[0].basis).toContain("SRV-02");
    expect(lateral(correlated)[0].basis).toContain("WS-01");
  });

  it("keeps each host's own observation time, not one borrowed from the other", () => {
    const byHost = new Map(correlateEvents(raw).map((e) => [e.asset, e.timestamp]));
    expect(byHost.get("WS-01")).toBe("2026-05-20T14:00:00Z");
    expect(byHost.get("SRV-02")).toBe("2026-05-20T14:40:00Z");
  });

  it("both hosts remain in the case's host set", () => {
    expect(new Set(correlateEvents(raw).map((e) => e.asset))).toEqual(new Set(["WS-01", "SRV-02"]));
  });
});
