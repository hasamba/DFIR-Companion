import { describe, it, expect, beforeEach } from "vitest";
import {
  loadKnownPlaybooks,
  _resetKnownPlaybooksCache,
} from "../../src/analysis/knownPlaybooksData.js";
import { normalizeTechniqueId } from "../../src/analysis/adversaryHints.js";
import { matchPlaybook, observedSequences } from "../../src/analysis/playbookMatch.js";

// The dataset is a committed file the SEA build stages next to the binary, so these guard both the
// loader's contract and the shipped JSON itself — a malformed entry is silently dropped at load
// time, which would otherwise show up only as a playbook quietly missing from the UI.
describe("loadKnownPlaybooks", () => {
  beforeEach(() => _resetKnownPlaybooksCache());

  it("loads the bundled catalog with provenance", () => {
    const ds = loadKnownPlaybooks();
    expect(ds.playbooks.length).toBeGreaterThan(0);
    expect(ds.source).not.toBe("");
    expect(ds.generated).not.toBe("");
  });

  it("caches — a second call returns the very same object without re-reading", () => {
    expect(loadKnownPlaybooks()).toBe(loadKnownPlaybooks());
    _resetKnownPlaybooksCache();
    expect(loadKnownPlaybooks()).not.toBe(undefined);
  });

  it("ships every catalogued playbook intact (none silently dropped by validation)", () => {
    const ds = loadKnownPlaybooks();
    // Named in the shipped file; if validation drops one, this list stops matching.
    expect(ds.playbooks.map((p) => p.name).sort()).toEqual(["Akira", "BlackCat", "Conti", "LockBit"]);
    for (const p of ds.playbooks) {
      expect(p.description.length).toBeGreaterThan(0);
      expect(p.steps.length).toBeGreaterThan(1); // a one-step "chain" has no order to match
      for (const s of p.steps) {
        expect(s.name.length).toBeGreaterThan(0);
        // Every step id must survive normalization, or the matcher skips the step entirely.
        expect(normalizeTechniqueId(s.technique)).toBe(s.technique);
      }
    }
  });

  it("scores its own steps at 100 — the catalog is matchable end to end", () => {
    for (const p of loadKnownPlaybooks().playbooks) {
      const events = p.steps.map((s, i) => ({
        id: `e${i}`,
        timestamp: new Date(Date.UTC(2026, 0, 1, 0, i)).toISOString(),
        description: s.name,
        severity: "High" as const,
        mitreTechniques: [s.technique],
        relatedFindingIds: [],
        sourceScreenshots: [],
      }));
      expect(matchPlaybook(p, observedSequences(events)[0]).score).toBe(100);
    }
  });
});
