import { describe, it, expect } from "vitest";
import { buildAttackLayer } from "../../src/reports/attackLayer.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1", severity: "High", title: "A finding", description: "d",
    relatedIocs: [], sourceScreenshots: [], mitreTechniques: [],
    firstSeen: "t0", lastUpdated: "t1", status: "open",
    ...overrides,
  };
}

function event(overrides: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "ev", severity: "Medium",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    ...overrides,
  };
}

describe("buildAttackLayer", () => {
  it("produces a valid empty layer with no techniques", () => {
    const layer = buildAttackLayer(emptyState("c1"));
    expect(layer.domain).toBe("enterprise-attack");
    expect(layer.versions.layer).toBe("4.5");
    expect(layer.versions.attack).toBe("19"); // current ATT&CK release — avoids the Navigator upgrade prompt
    expect(layer.techniques).toEqual([]);
    expect(layer.legendItems).toEqual([]);
    expect(layer.name).toBe("DFIR Companion — c1");
  });

  it("maps a finding's techniques to colored, scored cells with the title as comment", () => {
    const state = emptyState("c1");
    state.findings.push(finding({ severity: "Critical", title: "Ransomware deployed", mitreTechniques: ["T1486"] }));
    const layer = buildAttackLayer(state);
    const t = layer.techniques.find((x) => x.techniqueID === "T1486");
    expect(t).toBeDefined();
    expect(t!.score).toBe(100);
    expect(t!.color).toBe("#b30000");
    expect(t!.comment).toContain("Ransomware deployed");
    expect(layer.legendItems).toContainEqual({ label: "Critical severity", color: "#b30000" });
  });

  it("takes the WORST severity when several findings/events share a technique", () => {
    const state = emptyState("c1");
    state.findings.push(
      finding({ id: "f1", severity: "Low", title: "low view", mitreTechniques: ["T1059"] }),
      finding({ id: "f2", severity: "High", title: "high view", mitreTechniques: ["T1059"] }),
    );
    state.forensicTimeline.push(event({ severity: "Medium", mitreTechniques: ["T1059"] }));
    const layer = buildAttackLayer(state);
    const t = layer.techniques.find((x) => x.techniqueID === "T1059")!;
    expect(t.score).toBe(75); // High wins
    expect(t.comment).toContain("low view");
    expect(t.comment).toContain("high view");
    expect(t.comment).toContain("1 forensic event");
  });

  it("normalizes/uppercases ids and drops non-technique strings (tactic ids, garbage)", () => {
    const state = emptyState("c1");
    state.findings.push(finding({ mitreTechniques: [" t1003.001 ", "TA0001", "not-a-technique", ""] }));
    const layer = buildAttackLayer(state);
    const ids = layer.techniques.map((t) => t.techniqueID);
    expect(ids).toContain("T1003.001");
    expect(ids).not.toContain("TA0001");
    expect(ids).not.toContain("not-a-technique");
  });

  it("expands the parent of a sub-technique so its score is visible in the Navigator", () => {
    const state = emptyState("c1");
    state.findings.push(finding({ mitreTechniques: ["T1059.001"] }));
    const layer = buildAttackLayer(state);
    const sub = layer.techniques.find((t) => t.techniqueID === "T1059.001")!;
    expect(sub.score).toBe(75); // the sub-technique itself is scored
    // showSubtechniques is a PARENT-level Navigator property — the parent carries the expand flag.
    const parent = layer.techniques.find((t) => t.techniqueID === "T1059")!;
    expect(parent).toBeDefined();
    expect(parent.showSubtechniques).toBe(true);
    expect(parent.score).toBeUndefined(); // neutral parent, no severity of its own
  });

  it("does not add a neutral parent when the parent is itself scored", () => {
    const state = emptyState("c1");
    state.findings.push(finding({ mitreTechniques: ["T1059", "T1059.001"] }));
    const layer = buildAttackLayer(state);
    const parents = layer.techniques.filter((t) => t.techniqueID === "T1059");
    expect(parents).toHaveLength(1); // single entry, scored AND expanded
    expect(parents[0].score).toBe(75);
    expect(parents[0].showSubtechniques).toBe(true);
  });

  it("dedupes repeated finding titles and counts forensic-only events", () => {
    const state = emptyState("c1");
    state.findings.push(
      finding({ id: "f1", title: "same", mitreTechniques: ["T1071"] }),
      finding({ id: "f2", title: "same", mitreTechniques: ["T1071"] }),
    );
    state.forensicTimeline.push(
      event({ id: "e1", mitreTechniques: ["T1071"] }),
      event({ id: "e2", mitreTechniques: ["T1071"] }),
    );
    const layer = buildAttackLayer(state);
    const t = layer.techniques.find((x) => x.techniqueID === "T1071")!;
    expect(t.comment).toBe("same • 2 forensic events");
  });

  it("sorts scored techniques worst→least severe", () => {
    const state = emptyState("c1");
    state.findings.push(
      finding({ id: "f1", severity: "Low", mitreTechniques: ["T1018"] }),
      finding({ id: "f2", severity: "Critical", mitreTechniques: ["T1486"] }),
      finding({ id: "f3", severity: "Medium", mitreTechniques: ["T1083"] }),
    );
    const layer = buildAttackLayer(state);
    const scored = layer.techniques.filter((t) => t.score !== undefined);
    expect(scored[0].techniqueID).toBe("T1486"); // Critical first
    expect(scored[scored.length - 1].techniqueID).toBe("T1018"); // Low last
  });

  it("honours a custom name and attack version", () => {
    const layer = buildAttackLayer(emptyState("c1"), { name: "Engagement X", attackVersion: "15" });
    expect(layer.name).toBe("Engagement X");
    expect(layer.versions.attack).toBe("15");
  });
});
