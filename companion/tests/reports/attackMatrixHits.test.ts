import { describe, it, expect } from "vitest";
import { buildMatrixHits } from "../../src/reports/attackMatrixHits.js";
import { buildAttackLayer } from "../../src/reports/attackLayer.js";
import { applyFalsePositive, type FalsePositiveMarker } from "../../src/analysis/falsePositive.js";
import { withEventTechniques } from "../../src/analysis/eventTechniques.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

// The server half of the MatrixHit contract (#1764). The matrix must highlight exactly what the
// List view lists and color it exactly as the Navigator layer export does, so every assertion here
// is made against buildAttackLayer() over the same filtered state rather than a hand-typed answer.

function finding(over: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "A finding",
    description: "d",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "t0",
    lastUpdated: "t1",
    status: "open",
    ...over,
  };
}

function event(over: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-05-20T09:00:00Z",
    description: "ev",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

// The projection loadFilteredState() applies to the MITRE table, in its order (#893, #917).
function filtered(state: InvestigationState, markers: FalsePositiveMarker[] = []): InvestigationState {
  return withEventTechniques(applyFalsePositive(state, markers));
}

function fpFinding(title: string): FalsePositiveMarker {
  return {
    id: `finding:${title}`,
    kind: "finding",
    ref: title,
    reason: "authorized-test",
    note: "",
    markedAt: "2026-05-20T00:00:00Z",
    markedBy: "analyst",
  };
}

function fixture(): InvestigationState {
  const state = emptyState("c1");
  state.findings.push(
    finding({ id: "f1", title: "Encoded PowerShell", severity: "Critical", mitreTechniques: ["T1059.001"] }),
    finding({ id: "f2", title: "Pentest scan", severity: "High", mitreTechniques: ["T1046"] }),
    finding({
      id: "f3",
      title: "Valid account logon",
      severity: "Low",
      mitreTechniques: ["T1078", "T1059.001"],
    }),
  );
  state.mitreTechniques.push(
    { id: "T1059.001", name: "PowerShell", findingIds: ["f3", "f1"] },
    { id: "T1046", name: "Network Service Discovery", findingIds: ["f2"] },
    { id: "T1078", name: "Valid Accounts", findingIds: ["f3"] },
  );
  state.forensicTimeline.push(
    event({ id: "e3", timestamp: "2026-05-20T11:00:00Z", severity: "High", mitreTechniques: ["T1059.001"] }),
    event({
      id: "e1",
      timestamp: "2026-05-20T09:00:00Z",
      severity: "Medium",
      mitreTechniques: ["T1059.001", "T1105"],
    }),
    event({ id: "e2", timestamp: "2026-05-20T09:00:00Z", severity: "Low", mitreTechniques: ["T1059.001"] }),
    event({ id: "e0", timestamp: "not a date", severity: "Info", mitreTechniques: ["T1059.001"] }),
  );
  return state;
}

function layerSeverities(state: InvestigationState): Map<string, string> {
  const colorToSev: Record<string, string> = {
    "#b30000": "Critical",
    "#e8590c": "High",
    "#f1c40f": "Medium",
    "#2e86de": "Low",
    "#7f8c8d": "Info",
  };
  return new Map(
    buildAttackLayer(state)
      .techniques.filter((t) => t.score !== undefined)
      .map((t) => [t.techniqueID, colorToSev[t.color ?? ""]]),
  );
}

describe("buildMatrixHits", () => {
  it("highlights exactly the layer export's scored ids, each with the layer's worst severity", () => {
    for (const markers of [[], [fpFinding("Pentest scan")], [fpFinding("Encoded PowerShell")]]) {
      const state = filtered(fixture(), markers);
      const hits = buildMatrixHits(state);
      const layer = layerSeverities(state);
      expect(new Set(hits.map((h) => h.id))).toEqual(new Set(layer.keys()));
      for (const h of hits) expect(h.worst).toBe(layer.get(h.id));
    }
  });

  it("drops a technique whose only support is a false-positive finding", () => {
    const hits = buildMatrixHits(filtered(fixture(), [fpFinding("Pentest scan")]));
    expect(hits.map((h) => h.id)).not.toContain("T1046");
    // A technique with other support stays, and loses only the benign finding's link and severity.
    const ps = buildMatrixHits(filtered(fixture(), [fpFinding("Encoded PowerShell")])).find(
      (h) => h.id === "T1059.001",
    );
    expect(ps?.findingIds).toEqual(["f3"]);
    expect(ps?.worst).toBe("High");
  });

  it("colors an analyst-accepted row with no finding or event Info, and flags it", () => {
    const state = fixture();
    state.mitreTechniques.push({
      id: "T1003",
      name: "OS Credential Dumping",
      findingIds: [],
      analystAccepted: true,
    });
    const hit = buildMatrixHits(filtered(state)).find((h) => h.id === "T1003");
    expect(hit).toMatchObject({ worst: "Info", findingIds: [], eventIds: [], analystAccepted: true });
    // Only accepted rows carry the flag.
    expect(buildMatrixHits(filtered(state)).find((h) => h.id === "T1078")?.analystAccepted).toBeUndefined();
  });

  it("keeps List order for finding ids and sorts event ids by timestamp, then id, undated last", () => {
    const ps = buildMatrixHits(filtered(fixture())).find((h) => h.id === "T1059.001");
    expect(ps?.findingIds).toEqual(["f3", "f1"]);
    expect(ps?.eventIds).toEqual(["e1", "e2", "e3", "e0"]);
  });

  it("de-duplicates an event that repeats an id, and adds event-only techniques as rows", () => {
    const state = fixture();
    state.forensicTimeline.push(event({ id: "e9", mitreTechniques: ["T1105", "t1105 "] }));
    const hit = buildMatrixHits(filtered(state)).find((h) => h.id === "T1105");
    expect(hit?.eventIds).toEqual(["e1", "e9"]);
    expect(hit?.findingIds).toEqual([]);
  });
});
