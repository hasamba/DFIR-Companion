import { describe, it, expect } from "vitest";
import {
  d3fendTechniqueUrl,
  buildD3fendResult,
  DEFAULT_MAX_PER_TECHNIQUE,
  D3FEND_TACTIC_ORDER,
  type D3fendDatasetView,
  type D3fendCountermeasure,
} from "../../src/analysis/d3fendMap.js";
import { loadD3fendDataset } from "../../src/analysis/d3fendData.js";
import { emptyState, type InvestigationState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const finding = (id: string, mitreTechniques: string[]): Finding => ({
  id,
  severity: "High",
  title: id,
  description: "",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques,
  firstSeen: "2026-01-01T00:00:00Z",
  lastUpdated: "2026-01-01T00:00:00Z",
  status: "open",
});

const ev = (id: string, mitreTechniques: string[]): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: id,
  severity: "High",
  mitreTechniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const cm = (id: string, tactic: string, name = id, category = "Cat"): D3fendCountermeasure => ({ id, name, tactic, category });

function dataset(map: Record<string, D3fendCountermeasure[]>, over: Partial<D3fendDatasetView> = {}): D3fendDatasetView {
  const ids = new Set<string>();
  for (const cms of Object.values(map)) for (const c of cms) ids.add(c.id);
  return {
    d3fendVersion: "1.4.0",
    generated: "2026-06-28",
    source: "MITRE D3FEND",
    note: "",
    countermeasureCount: ids.size,
    map,
    ...over,
  };
}

function stateWith(techniques: string[]): InvestigationState {
  return { ...emptyState(), findings: [finding("F1", techniques)] };
}

describe("d3fendTechniqueUrl", () => {
  it("builds the d3fend.mitre.org technique link", () => {
    expect(d3fendTechniqueUrl("TokenBinding")).toBe("https://d3fend.mitre.org/technique/d3f:TokenBinding/");
    expect(d3fendTechniqueUrl("  TokenBinding ")).toBe("https://d3fend.mitre.org/technique/d3f:TokenBinding/");
  });
});

describe("buildD3fendResult", () => {
  it("resolves a case technique to its countermeasures, with d3fend urls", () => {
    const ds = dataset({ "T1059.001": [cm("ScriptExecutionAnalysis", "Detect")] });
    const result = buildD3fendResult(stateWith(["T1059.001"]), ds);
    expect(result.caseTechniqueCount).toBe(1);
    expect(result.coveredTechniqueCount).toBe(1);
    expect(result.techniques).toHaveLength(1);
    expect(result.techniques[0].technique).toBe("T1059.001");
    expect(result.techniques[0].countermeasures[0]).toMatchObject({
      id: "ScriptExecutionAnalysis",
      url: "https://d3fend.mitre.org/technique/d3f:ScriptExecutionAnalysis/",
    });
  });

  it("falls back to the base technique when the sub-technique is unmapped", () => {
    // D3FEND only maps the base T1059, but the case observed T1059.003.
    const ds = dataset({ T1059: [cm("ProcessSpawnAnalysis", "Detect")] });
    const result = buildD3fendResult(stateWith(["T1059.003"]), ds);
    expect(result.techniques).toHaveLength(1);
    expect(result.techniques[0].technique).toBe("T1059.003");
    expect(result.techniques[0].countermeasures.map((c) => c.id)).toEqual(["ProcessSpawnAnalysis"]);
  });

  it("aggregates sub-technique countermeasures for a base-tagged case technique", () => {
    // D3FEND maps brute-force only at the sub-technique level; the case is tagged at the base T1110.
    const ds = dataset({
      "T1110.001": [cm("MultifactorAuthentication", "Harden")],
      "T1110.003": [cm("AccountLockout", "Harden")],
    });
    const result = buildD3fendResult(stateWith(["T1110"]), ds);
    expect(result.coveredTechniqueCount).toBe(1);
    expect(result.techniques[0].countermeasures.map((c) => c.id).sort()).toEqual([
      "AccountLockout",
      "MultifactorAuthentication",
    ]);
  });

  it("merges exact + base countermeasures and dedupes by id", () => {
    const ds = dataset({
      "T1059.001": [cm("ScriptExecutionAnalysis", "Detect")],
      T1059: [cm("ScriptExecutionAnalysis", "Detect"), cm("ExecutableDenylisting", "Harden")],
    });
    const result = buildD3fendResult(stateWith(["T1059.001"]), ds);
    const ids = result.techniques[0].countermeasures.map((c) => c.id);
    expect(ids).toContain("ScriptExecutionAnalysis");
    expect(ids).toContain("ExecutableDenylisting");
    expect(new Set(ids).size).toBe(ids.length); // no dupes
  });

  it("orders countermeasures by D3FEND lifecycle tactic then name", () => {
    const ds = dataset({
      T1110: [cm("Zeta", "Restore"), cm("Alpha", "Harden"), cm("Beta", "Harden"), cm("Mid", "Detect")],
    });
    const result = buildD3fendResult(stateWith(["T1110"]), ds);
    expect(result.techniques[0].countermeasures.map((c) => c.id)).toEqual(["Alpha", "Beta", "Mid", "Zeta"]);
  });

  it("caps countermeasures per technique but keeps all in the tactic rollup", () => {
    const many = Array.from({ length: 20 }, (_, i) => cm(`H${String(i).padStart(2, "0")}`, "Harden"));
    const ds = dataset({ T1110: many });
    const result = buildD3fendResult(stateWith(["T1110"]), ds, { maxPerTechnique: 5 });
    expect(result.techniques[0].countermeasures).toHaveLength(5);
    const hardenGroup = result.byTactic.find((g) => g.tactic === "Harden")!;
    expect(hardenGroup.countermeasures).toHaveLength(20); // rollup keeps the full set
  });

  it("groups distinct countermeasures across techniques by tactic, in lifecycle order", () => {
    const ds = dataset({
      T1059: [cm("Shared", "Harden"), cm("DetectA", "Detect")],
      T1110: [cm("Shared", "Harden"), cm("IsolateA", "Isolate")],
    });
    const result = buildD3fendResult(stateWith(["T1059", "T1110"]), ds);
    expect(result.byTactic.map((g) => g.tactic)).toEqual(["Harden", "Detect", "Isolate"]);
    const harden = result.byTactic.find((g) => g.tactic === "Harden")!;
    expect(harden.countermeasures.map((c) => c.id)).toEqual(["Shared"]); // deduped across techniques
  });

  it("omits techniques with no mapping and counts coverage", () => {
    const ds = dataset({ T1059: [cm("DetectA", "Detect")] });
    const result = buildD3fendResult(stateWith(["T1059", "T9999"]), ds);
    expect(result.caseTechniqueCount).toBe(2);
    expect(result.coveredTechniqueCount).toBe(1);
    expect(result.techniques.map((t) => t.technique)).toEqual(["T1059"]);
  });

  it("collects techniques from findings, events, and the mitre table", () => {
    const ds = dataset({ T1003: [cm("CredHard", "Harden")], T1486: [cm("BackupRestore", "Restore")] });
    const state: InvestigationState = {
      ...emptyState(),
      findings: [finding("F1", ["T1003"])],
      forensicTimeline: [ev("E1", ["T1486"])],
    };
    const result = buildD3fendResult(state, ds);
    expect(result.techniques.map((t) => t.technique).sort()).toEqual(["T1003", "T1486"]);
  });

  it("returns empty (but well-formed) when the case has no techniques", () => {
    const ds = dataset({ T1059: [cm("DetectA", "Detect")] });
    const result = buildD3fendResult(emptyState(), ds);
    expect(result.caseTechniqueCount).toBe(0);
    expect(result.techniques).toEqual([]);
    expect(result.byTactic).toEqual([]);
    expect(result.note).toBeTruthy();
  });

  it("carries dataset provenance and the standing note through", () => {
    const ds = dataset({ T1059: [cm("DetectA", "Detect")] }, { d3fendVersion: "1.4.0", countermeasureCount: 149 });
    const result = buildD3fendResult(stateWith(["T1059"]), ds);
    expect(result.d3fendVersion).toBe("1.4.0");
    expect(result.mappedTechniqueCount).toBe(1);
    expect(result.countermeasureCount).toBe(149);
    expect(result.note).toMatch(/D3FEND/i);
  });

  it("defaults the per-technique cap to DEFAULT_MAX_PER_TECHNIQUE", () => {
    const many = Array.from({ length: DEFAULT_MAX_PER_TECHNIQUE + 5 }, (_, i) => cm(`H${i}`, "Harden"));
    const ds = dataset({ T1110: many });
    const result = buildD3fendResult(stateWith(["T1110"]), ds);
    expect(result.techniques[0].countermeasures).toHaveLength(DEFAULT_MAX_PER_TECHNIQUE);
  });
});

describe("D3FEND_TACTIC_ORDER", () => {
  it("is the canonical D3FEND defensive lifecycle", () => {
    expect(D3FEND_TACTIC_ORDER).toEqual(["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]);
  });
});

// Integration: the committed dataset must load and resolve a well-known technique. This guards the
// bundled d3fend-map.json staying valid + present (the offline feature depends on it).
describe("bundled d3fend dataset", () => {
  it("loads and resolves a known ATT&CK technique to countermeasures", () => {
    const ds = loadD3fendDataset();
    expect(ds.countermeasureCount).toBeGreaterThan(0);
    expect(Object.keys(ds.map).length).toBeGreaterThan(0);
    // T1059 (Command and Scripting Interpreter) is mapped at the base level; T1110 (Brute Force)
    // only at sub-technique level — both must resolve (the latter via downward sub-aggregation).
    const result = buildD3fendResult(stateWith(["T1059", "T1110"]), ds);
    expect(result.coveredTechniqueCount).toBe(2);
    for (const t of result.techniques) expect(t.countermeasures.length).toBeGreaterThan(0);
    expect(result.byTactic.length).toBeGreaterThan(0);
  });
});
