import { describe, it, expect } from "vitest";
import {
  deriveSignature,
  learnedPatternKey,
  mergeLearnedPattern,
  matchLearnedPatterns,
  buildLearnedPatternsBlock,
  type LearnedPattern,
} from "../../src/analysis/learnedPatterns.js";

const NOW = "2026-07-15T00:00:00Z";
const LATER = "2026-07-16T00:00:00Z";

describe("deriveSignature (#65)", () => {
  it("normalizes whitespace + case", () => {
    expect(deriveSignature("  BloodHound   Ingestor ")).toBe("bloodhound ingestor");
  });
  it("returns '' for too-short/opaque text (e.g. a bare event id)", () => {
    expect(deriveSignature("e12")).toBe("");
    expect(deriveSignature("   ")).toBe("");
  });
});

describe("learnedPatternKey (#65)", () => {
  it("is stable per (signature, reason) and distinguishes reasons", () => {
    expect(learnedPatternKey("bloodhound", "authorized-test")).toBe(learnedPatternKey("bloodhound", "authorized-test"));
    expect(learnedPatternKey("bloodhound", "authorized-test")).not.toBe(learnedPatternKey("bloodhound", "detection-misfire"));
  });
});

describe("mergeLearnedPattern (#65)", () => {
  it("creates a fresh pattern (count 1) then bumps count + refreshes lastSeen on recurrence", () => {
    const a = mergeLearnedPattern([], { text: "BloodHound collection", reason: "authorized-test" }, NOW);
    expect(a.changed).toBe(true);
    expect(a.patterns).toHaveLength(1);
    expect(a.patterns[0]).toMatchObject({ signature: "bloodhound collection", reason: "authorized-test", count: 1 });

    const b = mergeLearnedPattern(a.patterns, { text: "bloodhound collection", reason: "authorized-test", example: "BloodHound run #2" }, LATER);
    expect(b.patterns).toHaveLength(1);          // same key → upsert, not a new row
    expect(b.patterns[0].count).toBe(2);
    expect(b.patterns[0].lastSeen).toBe(LATER);
    expect(b.patterns[0].examples).toContain("BloodHound run #2");
  });

  it("keeps the same tool under different reasons as distinct patterns", () => {
    const a = mergeLearnedPattern([], { text: "psexec service", reason: "authorized-test" }, NOW);
    const b = mergeLearnedPattern(a.patterns, { text: "psexec service", reason: "detection-misfire" }, NOW);
    expect(b.patterns).toHaveLength(2);
  });

  it("is a no-op for an opaque/too-short dismissal (no signature)", () => {
    const r = mergeLearnedPattern([], { text: "e7", reason: "duplicate" }, NOW);
    expect(r.changed).toBe(false);
    expect(r.patterns).toEqual([]);
  });

  it("does not mutate the input array (immutability)", () => {
    const existing: LearnedPattern[] = [];
    mergeLearnedPattern(existing, { text: "mimikatz", reason: "authorized-test" }, NOW);
    expect(existing).toEqual([]);
  });
});

describe("matchLearnedPatterns (#65)", () => {
  const patterns = [
    mergeLearnedPattern([], { text: "bloodhound", reason: "authorized-test" }, NOW).patterns[0],
  ];
  it("matches a new finding whose title contains the pattern signature", () => {
    expect(matchLearnedPatterns("BloodHound SharpHound ingestor detected", patterns).map((p) => p.signature)).toEqual(["bloodhound"]);
  });
  it("does not match unrelated titles", () => {
    expect(matchLearnedPatterns("ransomware note dropped", patterns)).toEqual([]);
  });
});

describe("buildLearnedPatternsBlock (#65)", () => {
  function pat(partial: Partial<LearnedPattern> & { signature: string; count: number }): LearnedPattern {
    return { id: "x", reason: "authorized-test", examples: [], firstSeen: NOW, lastSeen: NOW, ...partial };
  }
  it("returns '' when nothing meets the recurrence threshold", () => {
    expect(buildLearnedPatternsBlock([pat({ signature: "a", count: 1 })], 2)).toBe("");
  });
  it("renders a lower-confidence (not exclude) instruction, sorted by recurrence", () => {
    const block = buildLearnedPatternsBlock([
      pat({ signature: "bloodhound", count: 3, reason: "authorized-test" }),
      pat({ signature: "nessus scan", count: 5, reason: "authorized-test" }),
    ], 1);
    expect(block).toMatch(/LOWER its confidence/);
    expect(block).toMatch(/do NOT exclude/);
    // Highest recurrence first.
    expect(block.indexOf("nessus scan")).toBeLessThan(block.indexOf("bloodhound"));
  });
});
