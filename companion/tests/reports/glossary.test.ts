import { describe, it, expect } from "vitest";
import { deriveGlossary } from "../../src/reports/glossary.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("deriveGlossary", () => {
  it("returns nothing for an empty case", () => {
    expect(deriveGlossary(emptyState("c1"))).toEqual([]);
  });

  it("matches whole-token terms (case-insensitively) across the investigation text", () => {
    const state = emptyState("c1");
    state.lastSummary = "An EDR alert fired.";
    state.attackerPath = "RDP brute force, then lateral movement and a cobalt strike beacon.";
    state.findings.push({ id: "f1", severity: "High", title: "Ransomware", description: "lsass dumped",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });

    const terms = deriveGlossary(state).map((g) => g.term);
    expect(terms).toContain("EDR");
    expect(terms).toContain("RDP");
    expect(terms).toContain("lateral movement");
    expect(terms).toContain("Cobalt Strike");
    expect(terms).toContain("beacon");
    expect(terms).toContain("LSASS");      // case-insensitive ("lsass")
    expect(terms).toContain("ransomware"); // from the finding title
    // Sorted alphabetically.
    expect(terms).toEqual([...terms].sort((a, b) => a.localeCompare(b)));
  });

  it("does not match a term embedded in a larger alphanumeric token", () => {
    const state = emptyState("c1");
    state.lastSummary = "The value AC2D and MFTX appeared in a hash-like token.";
    const terms = deriveGlossary(state).map((g) => g.term);
    expect(terms).not.toContain("C2");
    expect(terms).not.toContain("MFT");
  });
});
