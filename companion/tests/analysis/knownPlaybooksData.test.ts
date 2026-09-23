import { describe, it, expect, beforeEach } from "vitest";
import { loadKnownPlaybooks, _resetKnownPlaybooksCache } from "../../src/analysis/knownPlaybooksData.js";
import { normalizeTechniqueId } from "../../src/analysis/adversaryHints.js";
import {
  buildPlaybookMatchResult,
  matchPlaybook,
  observedSequences,
  stepTactic,
} from "../../src/analysis/playbookMatch.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

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
    expect(ds.playbooks.map((p) => p.name).sort()).toEqual([
      "Akira",
      "Black Basta",
      "BlackCat (ALPHV)",
      "BlackSuit (Royal)",
      "Conti",
      "Egg-Cellent Resume (more_eggs → Cobalt Strike → Pyramid)",
      "LockBit",
      "Play",
      "Scattered Spider",
    ]);
    for (const p of ds.playbooks) {
      expect(p.description.length).toBeGreaterThan(0);
      expect(p.steps.length).toBeGreaterThan(1); // a one-step "chain" has no order to match
      // Every chain cites the public advisory it was distilled from — the report and the panel
      // link to it, and an uncited chain is an unfalsifiable claim.
      expect(p.reference).toMatch(/^https:\/\//);
      for (const s of p.steps) {
        expect(s.name.length).toBeGreaterThan(0);
        // Every step id must survive normalization, or the matcher skips the step entirely.
        expect(normalizeTechniqueId(s.technique)).toBe(s.technique);
        for (const alt of s.alternatives ?? []) {
          expect(normalizeTechniqueId(alt)).toBe(alt);
          expect(alt).not.toBe(s.technique); // a self-alternative is a no-op typo
        }
      }
    }
  });

  it("maps every step to an ATT&CK tactic, so a missing step becomes a collection directive", () => {
    for (const p of loadKnownPlaybooks().playbooks) {
      for (const s of p.steps) {
        expect(stepTactic(s), `${p.name} / ${s.technique}`).toBeDefined();
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

// #1560: a resume-lure intrusion (The DFIR Report, 2024-12-02) had no catalog entry, so neither
// report named the campaign. The entry must surface for its own chain and stay quiet on a case
// that shares only a generic execution technique with it.
describe("Egg-Cellent Resume playbook (#1560)", () => {
  const EGG = "Egg-Cellent Resume (more_eggs → Cobalt Strike → Pyramid)";
  const events = (chain: string[][]): ForensicEvent[] =>
    chain.map((techniques, i) => ({
      id: `e${i}`,
      timestamp: new Date(Date.UTC(2026, 0, 1, 0, i)).toISOString(),
      description: techniques.join(","),
      severity: "High" as const,
      mitreTechniques: techniques,
      relatedFindingIds: [],
      sourceScreenshots: [],
    }));

  beforeEach(() => _resetKnownPlaybooksCache());

  it("cites The DFIR Report write-up", () => {
    const pb = loadKnownPlaybooks().playbooks.find((p) => p.name === EGG);
    expect(pb?.reference).toBe(
      "https://thedfirreport.com/2024/12/02/the-curious-case-of-an-egg-cellent-resume/",
    );
  });

  it("matches a case whose techniques cover the Egg-Cellent steps", () => {
    const result = buildPlaybookMatchResult(
      events([
        ["T1566.001", "T1204.002"], // resume ZIP lure
        ["T1218"], // ie4uinit.exe + .inf
        ["T1220"], // msxsl XSL script
        ["T1218.010"], // regsvr32 numbered .ocx
        ["T1053.005"], // scheduled task
        ["T1620"], // execute-assembly
        ["T1087.002", "T1018"], // AdFind / NetScan
        ["T1212", "T1136.001"], // VeeamHax + xp_cmdshell account
        ["T1572"], // cloudflared
        ["T1059.006"], // Pyramid
      ]),
      loadKnownPlaybooks(),
    );
    const top = result.matches[0];
    expect(top?.name).toBe(EGG);
    expect(top?.score).toBe(100);
  });

  it("does not match a generic ransomware case that shares only T1059.001", () => {
    const result = buildPlaybookMatchResult(events([["T1059.001"], ["T1486"]]), loadKnownPlaybooks());
    expect(result.matches.map((m) => m.name)).not.toContain(EGG);
  });
});
