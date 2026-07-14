import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { groundAndScoreFindings, LOW_TRUST_CONFIDENCE_CAP } from "../../src/analysis/findingGrounding.js";
import { effectiveTrustMap } from "../../src/analysis/sourceTrust.js";
import type { ForensicEvent, Finding } from "../../src/analysis/stateTypes.js";

function ev(partial: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T10:00:00Z", description: "", severity: "High", mitreTechniques: [],
    relatedFindingIds: [], sourceScreenshots: [], ...partial,
  };
}

function finding(partial: Partial<Finding> & { id: string }): Finding {
  return {
    severity: "High", title: "t", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [],
    firstSeen: "2026-06-01T00:00:00Z", lastUpdated: "2026-06-01T00:00:00Z", status: "open", ...partial,
  };
}

describe("correlate mergeGroup prefers the high-trust description (#66)", () => {
  it("takes the higher-trust tool's wording over a longer low-trust one (same severity)", () => {
    const sha = "a".repeat(64);
    const velo = ev({ id: "e1", sources: ["Velociraptor"], sha256: sha, description: "velociraptor raw artifact row with a very long verbose descriptive text here" });
    const cs = ev({ id: "e2", sources: ["CrowdStrike Falcon"], sha256: sha, description: "CrowdStrike: credential theft" });
    const [merged] = correlateEvents([velo, cs], { sourceTrust: effectiveTrustMap() });
    expect(merged.description).toBe("CrowdStrike: credential theft");   // trust beats length
    expect(merged.sources).toEqual(expect.arrayContaining(["Velociraptor", "CrowdStrike Falcon"]));
  });

  it("severity still dominates trust (a Critical low-trust row wins the wording over an Info high-trust one)", () => {
    const sha = "b".repeat(64);
    const critLow = ev({ id: "e1", severity: "Critical", sources: ["generic log"], sha256: sha, description: "ransomware note dropped" });
    const infoHigh = ev({ id: "e2", severity: "Info", sources: ["CrowdStrike"], sha256: sha, description: "benign file access" });
    const [merged] = correlateEvents([critLow, infoHigh], { sourceTrust: effectiveTrustMap() });
    expect(merged.description).toBe("ransomware note dropped");
    expect(merged.severity).toBe("Critical");
  });
});

describe("groundAndScoreFindings low-trust cap (#66)", () => {
  const graphLinkedEventIds = new Set<string>();

  it("caps confidence for a finding supported only by low-trust sources", () => {
    // Two distinct hosts + two distinct tools so neither the ungrounded nor single-source cap fires —
    // isolating the trust cap. Both sources are below the 0.7 trust threshold (generic logs).
    const scopedEvents = [
      ev({ id: "e1", asset: "HOST-A", sources: ["syslog"], relatedFindingIds: ["f1"] }),
      ev({ id: "e2", asset: "HOST-B", sources: ["firewall log"], relatedFindingIds: ["f1"] }),
    ];
    const [scored] = groundAndScoreFindings({
      findings: [finding({ id: "f1", confidence: 95 })],
      scopedEvents, iocs: [], graphLinkedEventIds, sourceTrust: effectiveTrustMap(),
    });
    expect(scored.confidence).toBe(LOW_TRUST_CONFIDENCE_CAP);
    expect(scored.confidenceReason).toMatch(/low-trust source/);
  });

  it("does NOT cap a finding backed by a high-trust source", () => {
    const scopedEvents = [
      ev({ id: "e1", asset: "HOST-A", sources: ["CrowdStrike"], relatedFindingIds: ["f1"] }),
      ev({ id: "e2", asset: "HOST-B", sources: ["THOR"], relatedFindingIds: ["f1"] }),
    ];
    const [scored] = groundAndScoreFindings({
      findings: [finding({ id: "f1", confidence: 95 })],
      scopedEvents, iocs: [], graphLinkedEventIds, sourceTrust: effectiveTrustMap(),
    });
    expect(scored.confidence).toBe(95);   // untouched
  });

  it("never applies the trust cap when no trust map is supplied (back-compat)", () => {
    const scopedEvents = [
      ev({ id: "e1", asset: "HOST-A", sources: ["generic log"], relatedFindingIds: ["f1"] }),
      ev({ id: "e2", asset: "HOST-B", sources: ["screenshot"], relatedFindingIds: ["f1"] }),
    ];
    const [scored] = groundAndScoreFindings({
      findings: [finding({ id: "f1", confidence: 95 })],
      scopedEvents, iocs: [], graphLinkedEventIds,   // no sourceTrust
    });
    expect(scored.confidence).toBe(95);
  });
});
