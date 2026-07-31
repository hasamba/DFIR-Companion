import { describe, expect, it } from "vitest";
import { loadGoldenCorpus } from "./corpus.js";
import { runCorpusCase } from "./harness.js";
import { mockProvider } from "./harness.js";
import { passesCaseQuality, scoreCaseQuality } from "./qualityScorer.js";

const REQUIRED_SCENARIOS = [
  "ransomware",
  "bec",
  "insider-threat",
  "lateral-movement",
  "linux",
  "cloud-identity",
  "email",
  "memory",
  "network",
  "clean",
];

describe("versioned production golden corpus (#378)", () => {
  it("documents safe provenance and covers the required investigative scenarios", async () => {
    const corpus = await loadGoldenCorpus();
    expect(corpus.schemaVersion).toBe(1);
    expect(corpus.version).toBe("1.0.0");
    expect(new Set(corpus.cases.map((fixture) => fixture.scenario))).toEqual(new Set(REQUIRED_SCENARIOS));
    expect(corpus.cases.every((fixture) => fixture.provenance.origin === "synthetic")).toBe(true);
    expect(corpus.cases.every((fixture) => fixture.provenance.containsClientData === false)).toBe(true);
    expect(corpus.license).toBe("AGPL-3.0-only");
  });

  it("includes clean abstention, incomplete evidence, contradictions, and prompt injection", async () => {
    const corpus = await loadGoldenCorpus();
    const traits = new Set(corpus.cases.flatMap((fixture) => fixture.traits));
    expect(corpus.cases.some((fixture) => fixture.golden.expectAbstention)).toBe(true);
    expect(traits.has("incomplete-evidence")).toBe(true);
    expect(traits.has("contradictory-sources")).toBe(true);
    expect(traits.has("prompt-injection")).toBe(true);
  });

  for (const scenario of REQUIRED_SCENARIOS) {
    it(`${scenario}: canned output passes exact evidence-grounded quality gates`, async () => {
      const corpus = await loadGoldenCorpus();
      const fixture = corpus.cases.find((candidate) => candidate.scenario === scenario);
      expect(fixture).toBeDefined();
      if (!fixture) return;
      const output = await runCorpusCase(fixture, mockProvider(fixture.canned));
      expect(passesCaseQuality(scoreCaseQuality(fixture.golden, output))).toBe(true);
    });
  }
});
