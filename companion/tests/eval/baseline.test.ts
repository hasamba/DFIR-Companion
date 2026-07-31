import { describe, expect, it } from "vitest";
import { baselineFileName, compareWithBaseline, createBaseline, type EvaluationSummary } from "./baseline.js";

const SUMMARY: EvaluationSummary = {
  claimPrecision: 1,
  claimRecall: 0.9,
  eventPrecision: 0.8,
  eventRecall: 0.9,
  iocPrecision: 1,
  iocRecall: 1,
  abstentionRate: 1,
  forbiddenConclusions: 0,
  danglingEvidenceRefs: 0,
  confidenceIssues: 0,
  uncertaintyRecall: 1,
  nextStepRecall: 1,
  durationMs: 1000,
  inputTokens: 100,
  outputTokens: 50,
  costUsd: 0.01,
};

describe("pinned model/prompt baselines (#378)", () => {
  it("keys each baseline by provider, model, and prompt hash", () => {
    const baseline = createBaseline(
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      SUMMARY,
      "2026-07-31T00:00:00.000Z",
    );
    expect(baseline.key).toBe(`provider-a/model-1/${"a".repeat(64)}`);
    expect(baselineFileName(baseline)).toMatch(new RegExp(`^provider-a--model-1--${"a".repeat(12)}\\.json$`));
  });

  it("reports quality, cost, and latency regressions separately", () => {
    const baseline = createBaseline(
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      SUMMARY,
      "2026-07-31T00:00:00.000Z",
    );
    const comparison = compareWithBaseline(
      baseline,
      {
        ...SUMMARY,
        claimRecall: 0.7,
        durationMs: 1400,
        costUsd: 0.02,
      },
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "d".repeat(64),
        sourceHash: "e".repeat(64),
        corpusHash: "c".repeat(64),
      },
    );
    expect(comparison.status).toBe("regressed");
    expect(comparison.qualityRegressions).toContain("claimRecall");
    expect(comparison.resourceRegressions).toEqual(expect.arrayContaining(["durationMs", "costUsd"]));
  });

  it("refuses to compare a different model or corpus", () => {
    const baseline = createBaseline(
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      SUMMARY,
      "2026-07-31T00:00:00.000Z",
    );
    const comparison = compareWithBaseline(baseline, SUMMARY, {
      provider: "provider-a",
      model: "model-2",
      promptHash: "d".repeat(64),
      sourceHash: "e".repeat(64),
      corpusHash: "f".repeat(64),
    });
    expect(comparison.status).toBe("incompatible");
    expect(comparison.reasons).toEqual(expect.arrayContaining(["model changed", "corpus changed"]));
  });
});
