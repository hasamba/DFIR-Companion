import { describe, it, expect } from "vitest";
import { mergeIocs } from "../../src/analysis/iocMerge.js";
import { buildAssetGraph } from "../../src/analysis/assetGraph.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

function baseState() {
  const s = emptyState("c1");
  s.iocs.push(
    { id: "i1", type: "domain", value: "evil.com", firstSeen: "2026-01-02T00:00:00Z", extractedFrom: ["e1"] },
    { id: "i2", type: "domain", value: "www.evil.com", firstSeen: "2026-01-01T00:00:00Z", extractedFrom: ["e2"],
      enrichments: [{ source: "VirusTotal", verdict: "malicious", fetchedAt: "2026-01-01T00:00:00Z" }],
      enrichedBy: ["VirusTotal"] },
  );
  s.findings.push({
    id: "f1", severity: "High", title: "C2 beacon", description: "beacon to evil.com",
    relatedIocs: ["i1"], mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open",
  });
  s.forensicTimeline.push(
    { id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "connection to evil.com", severity: "High",
      mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WIN-01" },
  );
  return s;
}

describe("mergeIocs", () => {
  it("throws on self-merge or a missing id", () => {
    const s = baseState();
    expect(() => mergeIocs(s, "i1", "i1")).toThrow(/itself/);
    expect(() => mergeIocs(s, "i1", "nope")).toThrow(/not found/);
    expect(() => mergeIocs(s, "nope", "i1")).toThrow(/not found/);
  });

  it("folds the duplicate's data onto the canonical IOC and drops the duplicate row", () => {
    const s = baseState();
    const { state, into } = mergeIocs(s, "i1", "i2");
    expect(state.iocs.map((i) => i.id)).toEqual(["i2"]);
    expect(into.aliasValues).toContain("evil.com");
    expect(into.extractedFrom?.sort()).toEqual(["e1", "e2"]);
    expect(into.enrichments?.length).toBe(1); // union preserved from the canonical side
    // Earlier firstSeen wins
    expect(into.firstSeen).toBe("2026-01-01T00:00:00Z");
  });

  it("rewrites finding.relatedIocs from the duplicate id to the canonical id", () => {
    const s = baseState();
    const { state } = mergeIocs(s, "i1", "i2");
    expect(state.findings[0].relatedIocs).toEqual(["i2"]);
  });

  it("keeps the merged IOC's alias value discoverable in the asset graph", () => {
    const s = baseState();
    const { state } = mergeIocs(s, "i1", "i2");
    const graph = buildAssetGraph(state);
    // e1's description mentions "evil.com" (the pre-merge duplicate value) — it should still
    // resolve onto the canonical IOC i2 via the alias, linking WIN-01 to i2.
    const win01 = graph.assets.find((a) => a.name === "WIN-01");
    expect(win01?.iocIds).toContain("i2");
  });
});
