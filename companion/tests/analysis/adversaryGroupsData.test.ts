import { describe, it, expect } from "vitest";
import { loadAdversaryGroupsDataset } from "../../src/analysis/adversaryGroupsData.js";
import { normalizeTechniqueId } from "../../src/analysis/adversaryHints.js";

// Validates that the COMMITTED companion/data/attack-groups.json is present, resolves from the
// module, and is well-formed — so a corrupt regeneration is caught in CI rather than at runtime.
describe("loadAdversaryGroupsDataset (bundled file)", () => {
  const ds = loadAdversaryGroupsDataset();

  it("loads a non-empty dataset with provenance metadata", () => {
    expect(ds.groups.length).toBeGreaterThan(50);
    expect(ds.groupCount).toBe(ds.groups.length);
    expect(ds.attackVersion).not.toBe("unknown");
    expect(ds.source).toMatch(/ATT&CK/i);
  });

  it("includes well-known groups keyed by ATT&CK id", () => {
    const apt29 = ds.groups.find((g) => g.id === "G0016");
    expect(apt29).toBeDefined();
    expect(apt29?.name).toMatch(/APT29/i);
    expect(apt29?.techniques.length).toBeGreaterThan(0);
  });

  it("stores techniques as valid full ids, keeping sub-technique granularity", () => {
    let subTechniqueSeen = 0;
    for (const g of ds.groups) {
      for (const t of g.techniques) {
        expect(normalizeTechniqueId(t)).toBe(t); // already a valid, normalized full id
        if (t.includes(".")) subTechniqueSeen++;
      }
    }
    // the whole point of the hybrid scorer: the slim file must retain sub-techniques
    expect(subTechniqueSeen).toBeGreaterThan(100);
  });

  it("caches — repeated calls return the same instance", () => {
    expect(loadAdversaryGroupsDataset()).toBe(ds);
  });
});
