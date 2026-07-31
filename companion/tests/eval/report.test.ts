import { describe, expect, it } from "vitest";
import { buildEvaluationReport, reportExitCode, type EvaluationCaseResult } from "./report.js";

const BASE_CASE: EvaluationCaseResult = {
  id: "case-1",
  scenario: "clean",
  status: "passed",
  metrics: {
    claimPrecision: 1,
    claimRecall: 1,
    iocPrecision: 1,
    iocRecall: 1,
    uncertaintyRecall: 1,
    nextStepRecall: 1,
    abstained: true,
    forbiddenConclusions: 0,
    danglingEvidenceRefs: 0,
    confidenceIssues: 0,
  },
  resources: {
    durationMs: 10,
    calls: 1,
    failedCalls: 0,
    inputTokens: 2,
    outputTokens: 1,
    costUsd: 0,
  },
};

describe("machine-readable evaluation outcomes (#378)", () => {
  it.each([
    ["passed", 0],
    ["quality_failed", 1],
    ["runner_failed", 2],
    ["provider_failed", 3],
    ["skipped", 0],
  ] as const)("distinguishes %s with a stable exit code", (outcome, exitCode) => {
    expect(reportExitCode(outcome)).toBe(exitCode);
  });

  it("does not place evidence, prompts, model output, or credentials in the report artifact", () => {
    const report = buildEvaluationReport({
      identity: {
        provider: "mock",
        model: "mock-model",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      corpusVersion: "1.0.0",
      cases: [BASE_CASE],
      extraction: [],
      screenshot: [],
      createdAt: "2026-07-31T00:00:00.000Z",
    });
    const serialized = JSON.stringify(report);
    expect(report.outcome).toBe("passed");
    expect(serialized).not.toMatch(/systemPrompt|userPrompt|rawText|"apiKey":|Bearer\s/i);
  });

  it("does not confuse provider failure, skipped evaluation, and quality failure", () => {
    const providerFailed = buildEvaluationReport({
      identity: {
        provider: "mock",
        model: "mock-model",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      corpusVersion: "1.0.0",
      cases: [{ ...BASE_CASE, status: "provider_failed", errorKind: "timeout" }],
      extraction: [],
      screenshot: [],
      createdAt: "2026-07-31T00:00:00.000Z",
    });
    const qualityFailed = buildEvaluationReport({
      ...providerFailed,
      cases: [{ ...BASE_CASE, status: "quality_failed" }],
    });
    expect(providerFailed.outcome).toBe("provider_failed");
    expect(qualityFailed.outcome).toBe("quality_failed");
  });
});
