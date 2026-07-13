import { describe, it, expect } from "vitest";
import { buildEvidenceGraph, connectedComponents, mainComponent } from "../../src/analysis/evidenceGraph.js";
import { scoreFindingsRelevance, relevanceBucket, type AiRelevance } from "../../src/analysis/findingRelevance.js";
import { emptyState, type Finding, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

function ev(partial: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-01-02T10:00:00Z", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...partial };
}
function finding(partial: Partial<Finding> & { id: string }): Finding {
  return {
    severity: "High", title: "f", description: "", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [],
    firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open", ...partial,
  };
}

// Two disconnected islands: a HOST-A process tree (the corroborated Critical mass = main component) and
// a separate HOST-B tree (a lesser, unconnected island).
function twoIslandState(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline = [
    ev({ id: "e1", asset: "HOST-A", parentName: "excel.exe", processName: "powershell.exe", severity: "Critical" }),
    ev({ id: "e2", asset: "HOST-A", parentName: "powershell.exe", processName: "cmd.exe", severity: "High" }),
    ev({ id: "e3", asset: "HOST-B", parentName: "chrome.exe", processName: "updater.exe", severity: "Medium" }),
  ];
  return s;
}

describe("connectedComponents / mainComponent", () => {
  it("splits the graph into the two islands and picks the Crit/High mass as main", () => {
    const graph = buildEvidenceGraph(twoIslandState());
    const comps = connectedComponents(graph);
    expect(comps.length).toBe(2);
    const main = mainComponent(graph)!;
    expect(main).not.toBeNull();
    // The main component carries HOST-A's events (the Critical/High tree), not HOST-B's.
    expect(main.eventIds.has("e1")).toBe(true);
    expect(main.eventIds.has("e2")).toBe(true);
    expect(main.eventIds.has("e3")).toBe(false);
  });

  it("returns null main for a graph with no edges", () => {
    expect(mainComponent(buildEvidenceGraph(emptyState("c1")))).toBeNull();
  });
});

describe("scoreFindingsRelevance (#13)", () => {
  const state = twoIslandState();
  const graph = buildEvidenceGraph(state);

  it("marks a finding on the main path 'connected' (connectedness 1)", () => {
    const [f] = scoreFindingsRelevance({ findings: [finding({ id: "fA", relatedEventIds: ["e1"] })], scopedEvents: state.forensicTimeline, graph });
    expect(f.relevance).toBe("connected");
    expect(f.connectedness).toBe(1);
    expect(f.relevanceDiscriminator).toBeUndefined();
  });

  it("marks a finding whose evidence sits in a SEPARATE component 'disconnected' with a discriminator", () => {
    const [f] = scoreFindingsRelevance({ findings: [finding({ id: "fB", relatedEventIds: ["e3"] })], scopedEvents: state.forensicTimeline, graph });
    expect(f.relevance).toBe("disconnected");
    expect(f.connectedness).toBe(0);
    expect(f.relevanceDiscriminator).toContain("to link it, look for");
    expect(relevanceBucket(f.relevance)).toBe("rabbit-hole");
  });

  it("marks a finding whose evidence is NOT in the causal graph 'undetermined' (never a false rabbit hole)", () => {
    const [f] = scoreFindingsRelevance({ findings: [finding({ id: "fC", relatedEventIds: ["e9"] })], scopedEvents: state.forensicTimeline, graph });
    expect(f.relevance).toBe("undetermined");
    expect(relevanceBucket(f.relevance)).toBe("lead"); // undetermined stays a possible lead, not hidden
  });

  it("lets the AI refine a disconnected finding into 'unrelated-but-real' (Parked), but never a rabbit hole into a lead", () => {
    const ai = new Map<string, AiRelevance>([["fB", "unrelated-but-real"], ["fA", "unrelated-but-real"]]);
    const scored = scoreFindingsRelevance({ findings: [finding({ id: "fA", relatedEventIds: ["e1"] }), finding({ id: "fB", relatedEventIds: ["e3"] })], scopedEvents: state.forensicTimeline, graph, aiRelevanceById: ai });
    expect(scored.find((f) => f.id === "fB")!.relevance).toBe("unrelated-but-real"); // disconnected + AI → parked
    expect(scored.find((f) => f.id === "fA")!.relevance).toBe("connected");           // graph linkage wins over AI
  });

  it("resolves reverse finding links (event → finding) as evidence too", () => {
    const s2 = twoIslandState();
    s2.forensicTimeline[0].relatedFindingIds = ["fRev"]; // e1 (main) names fRev, which has no forward links
    const [f] = scoreFindingsRelevance({ findings: [finding({ id: "fRev" })], scopedEvents: s2.forensicTimeline, graph: buildEvidenceGraph(s2) });
    expect(f.relevance).toBe("connected");
  });
});
