import { describe, it, expect } from "vitest";
import {
  buildMitigationsResult,
  type MitigationsDatasetView,
  type AttackMitigation,
  type MitigationMapLink,
} from "../../src/analysis/attackMitigations.js";
import { loadMitigationsDataset } from "../../src/analysis/attackMitigationsData.js";
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

const mit = (id: string, name = id, description = "desc " + id): AttackMitigation => ({
  id,
  name,
  description,
  url: `https://attack.mitre.org/mitigations/${id}`,
});

function dataset(
  mitigations: AttackMitigation[],
  map: Record<string, MitigationMapLink[]>,
  over: Partial<MitigationsDatasetView> = {},
): MitigationsDatasetView {
  const dict: Record<string, AttackMitigation> = {};
  for (const m of mitigations) dict[m.id] = m;
  return {
    attackVersion: "19.1",
    generated: "2026-06-28",
    source: "MITRE ATT&CK",
    note: "",
    mitigationCount: mitigations.length,
    mitigations: dict,
    map,
    ...over,
  };
}

const stateWith = (techniques: string[]): InvestigationState => ({ ...emptyState(), findings: [finding("F1", techniques)] });

describe("buildMitigationsResult", () => {
  it("resolves a case technique to its mitigations with name/url/detail", () => {
    const ds = dataset([mit("M1043", "Credential Access Protection")], {
      "T1003.001": [{ id: "M1043", detail: "Enable Credential Guard." }],
    });
    const r = buildMitigationsResult(stateWith(["T1003.001"]), ds);
    expect(r.coveredTechniqueCount).toBe(1);
    expect(r.techniques[0].mitigations[0]).toMatchObject({
      id: "M1043",
      name: "Credential Access Protection",
      url: "https://attack.mitre.org/mitigations/M1043",
      detail: "Enable Credential Guard.",
    });
  });

  it("falls back to the mitigation's general description when a link has no detail", () => {
    const ds = dataset([mit("M1026", "Privileged Account Management", "Manage privileged accounts.")], {
      T1003: [{ id: "M1026", detail: "" }],
    });
    const r = buildMitigationsResult(stateWith(["T1003"]), ds);
    expect(r.techniques[0].mitigations[0].detail).toBe("Manage privileged accounts.");
  });

  it("ranks the by-mitigation rollup by how many case techniques each addresses", () => {
    const ds = dataset([mit("M1026"), mit("M1043"), mit("M1017")], {
      T1003: [{ id: "M1026", detail: "a" }, { id: "M1043", detail: "b" }],
      T1078: [{ id: "M1026", detail: "c" }, { id: "M1017", detail: "d" }],
      T1021: [{ id: "M1026", detail: "e" }],
    });
    const r = buildMitigationsResult(stateWith(["T1003", "T1078", "T1021"]), ds);
    // M1026 covers all 3 → first; M1043 and M1017 cover 1 each → after, by id.
    expect(r.byMitigation.map((m) => m.id)).toEqual(["M1026", "M1017", "M1043"]);
    expect(r.byMitigation[0].techniques).toEqual(["T1003", "T1021", "T1078"]);
  });

  it("aggregates sub-technique mitigations for a base-tagged case technique", () => {
    const ds = dataset([mit("M1032"), mit("M1030")], {
      "T1110.001": [{ id: "M1032", detail: "MFA" }],
      "T1110.003": [{ id: "M1030", detail: "Network segmentation" }],
    });
    const r = buildMitigationsResult(stateWith(["T1110"]), ds);
    expect(r.techniques[0].mitigations.map((m) => m.id).sort()).toEqual(["M1030", "M1032"]);
  });

  it("pulls the base technique's mitigations for a sub-technique", () => {
    const ds = dataset([mit("M1026")], { T1059: [{ id: "M1026", detail: "x" }] });
    const r = buildMitigationsResult(stateWith(["T1059.001"]), ds);
    expect(r.techniques[0].mitigations.map((m) => m.id)).toEqual(["M1026"]);
  });

  it("collects techniques from findings, events, and the mitre table; counts coverage", () => {
    const ds = dataset([mit("M1049")], { T1486: [{ id: "M1049", detail: "AV" }] });
    const state: InvestigationState = {
      ...emptyState(),
      findings: [finding("F1", ["T1486"])],
      forensicTimeline: [ev("E1", ["T9999"])], // unmapped
    };
    const r = buildMitigationsResult(state, ds);
    expect(r.caseTechniqueCount).toBe(2);
    expect(r.coveredTechniqueCount).toBe(1);
    expect(r.techniques.map((t) => t.technique)).toEqual(["T1486"]);
  });

  it("returns an empty but well-formed result when the case has no techniques", () => {
    const ds = dataset([mit("M1026")], { T1003: [{ id: "M1026", detail: "x" }] });
    const r = buildMitigationsResult(emptyState(), ds);
    expect(r.caseTechniqueCount).toBe(0);
    expect(r.byMitigation).toEqual([]);
    expect(r.techniques).toEqual([]);
    expect(r.note).toMatch(/ATT&CK/i);
  });
});

// Integration: the committed dataset must load and resolve a well-known technique.
describe("bundled attack-mitigations dataset", () => {
  it("loads and resolves T1003.001 to concrete mitigations", () => {
    const ds = loadMitigationsDataset();
    expect(ds.mitigationCount).toBeGreaterThan(0);
    expect(Object.keys(ds.map).length).toBeGreaterThan(0);
    const r = buildMitigationsResult(stateWith(["T1003.001"]), ds);
    expect(r.coveredTechniqueCount).toBe(1);
    expect(r.techniques[0].mitigations.length).toBeGreaterThan(0);
    expect(r.byMitigation[0].techniques.length).toBeGreaterThan(0);
    // every resolved mitigation carries a non-empty actionable detail
    for (const m of r.techniques[0].mitigations) expect(m.detail.length).toBeGreaterThan(0);
  });
});
