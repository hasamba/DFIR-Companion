import { describe, expect, it } from "vitest";
import {
  buildEvaluationReport,
  computeDirtyCaseAggregate,
  reportExitCode,
  type EvaluationCaseResult,
  type EvaluationReportInput,
} from "./report.js";
import { REAL_THRESHOLDS } from "./scorer.js";

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

// #1224: a real (non-deterministic) run failed the whole corpus if even ONE case missed an exact
// phrase on one dimension — unwinnable in practice, per #1217's own two captured real runs. On a
// real run, the outcome now gates on the CORPUS-WIDE aggregate recall (excluding the clean case)
// against scorer.ts's own REAL_THRESHOLDS.minRecall, not on every individual case passing. Hard
// violations (hallucination-adjacent) and a total-whiff case are still zero-tolerance, real or mock.
describe("production-corpus real-run outcome uses aggregate recall, not all-or-nothing (#1224)", () => {
  const IDENTITY = {
    provider: "mock",
    model: "mock-model",
    promptHash: "a".repeat(64),
    sourceHash: "b".repeat(64),
    corpusHash: "c".repeat(64),
  };

  const DIRTY_CASE: EvaluationCaseResult = {
    id: "dirty-1",
    scenario: "ransomware",
    status: "quality_failed", // per-case status is irrelevant on a real run except for hard fields
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
    resources: BASE_CASE.resources,
  };

  function dirtyCase(
    id: string,
    overrides: Partial<EvaluationCaseResult["metrics"]> = {},
  ): EvaluationCaseResult {
    return { ...DIRTY_CASE, id, metrics: { ...DIRTY_CASE.metrics, ...overrides } };
  }

  function realInput(cases: EvaluationCaseResult[]): EvaluationReportInput {
    return {
      identity: IDENTITY,
      corpusVersion: "1.0.0",
      cases,
      extraction: [],
      screenshot: [],
      createdAt: "2026-07-31T00:00:00.000Z",
      real: true,
    };
  }

  it("passes when every dirty-case aggregate clears the floor, even though every case's own status is quality_failed", () => {
    const report = buildEvaluationReport(realInput([dirtyCase("d1"), dirtyCase("d2"), dirtyCase("d3")]));
    expect(report.outcome).toBe("passed");
  });

  it("passes when the aggregate sits exactly AT the floor (boundary is >=, not >)", () => {
    // 7 of 10 cases claimRecall=1, 3 claimRecall=0 (other dims left at 1, so no total-whiff) →
    // claimRecall aggregate = 7/10 = 0.7 = REAL_THRESHOLDS.minRecall exactly.
    expect(REAL_THRESHOLDS.minRecall).toBe(0.7);
    const cases = [
      ...Array.from({ length: 7 }, (_, i) => dirtyCase(`hit-${i}`)),
      ...Array.from({ length: 3 }, (_, i) => dirtyCase(`miss-${i}`, { claimRecall: 0 })),
    ];
    expect(computeDirtyCaseAggregate(cases).claimRecall).toBeCloseTo(0.7, 5);
    const report = buildEvaluationReport(realInput(cases));
    expect(report.outcome).toBe("passed");
  });

  it.each(["claimRecall", "iocRecall", "uncertaintyRecall", "nextStepRecall"] as const)(
    "fails when ONLY %s drops below the floor, all other dimensions perfect (per-dimension isolation)",
    (dimension) => {
      // 2 hits + 1 miss (that one dimension = 0, others left at 1) → aggregate = 2/3 ≈ 0.667 < 0.7.
      const cases = [dirtyCase("hit-0"), dirtyCase("hit-1"), dirtyCase("low", { [dimension]: 0 })];
      expect(computeDirtyCaseAggregate(cases)[dimension]).toBeLessThan(REAL_THRESHOLDS.minRecall);
      const report = buildEvaluationReport(realInput(cases));
      expect(report.outcome).toBe("quality_failed");
    },
  );

  it("fails when one dirty case totally whiffs (claim/uncertainty/next-step recall all 0), even if the corpus-wide aggregate still clears the floor", () => {
    const cases = [
      ...Array.from({ length: 9 }, (_, i) => dirtyCase(`hit-${i}`)),
      dirtyCase("whiff", { claimRecall: 0, uncertaintyRecall: 0, nextStepRecall: 0 }),
    ];
    expect(computeDirtyCaseAggregate(cases).claimRecall).toBeGreaterThanOrEqual(REAL_THRESHOLDS.minRecall);
    const report = buildEvaluationReport(realInput(cases));
    expect(report.outcome).toBe("quality_failed");
  });

  it("excludes the clean-maintenance case from the dirty-case aggregate denominator", () => {
    const cleanCase: EvaluationCaseResult = {
      ...BASE_CASE,
      id: "clean-1",
      scenario: "clean",
      metrics: { ...BASE_CASE.metrics, claimRecall: 1 }, // vacuous — no claims expected
    };
    // Without exclusion, adding 9 more "clean" cases at recall=1 would mask a real dirty miss.
    const withoutClean = computeDirtyCaseAggregate([dirtyCase("miss", { claimRecall: 0 })]);
    const withClean = computeDirtyCaseAggregate([dirtyCase("miss", { claimRecall: 0 }), cleanCase]);
    expect(withClean.claimRecall).toBe(withoutClean.claimRecall);
    expect(withClean.claimRecall).toBe(0);
  });

  it("the clean case's exclusion actually changes the OUTCOME, not just the raw helper (would flip pass/fail if it weren't excluded)", () => {
    // 1 dirty miss + 9 clean cases at vacuous recall=1: WITH exclusion, the dirty-case aggregate
    // is 0/1 = 0 (fails). If the clean cases were wrongly included in the denominator, the
    // aggregate would be 9/10 = 0.9 (passes) — this proves the exclusion is wired all the way
    // through to buildEvaluationReport, not just present in the standalone helper.
    const cleanCases = Array.from({ length: 9 }, (_, i) => ({
      ...BASE_CASE,
      id: `clean-${i}`,
      scenario: "clean",
    }));
    const cases = [dirtyCase("miss", { claimRecall: 0 }), ...cleanCases];
    const report = buildEvaluationReport(realInput(cases));
    expect(report.outcome).toBe("quality_failed");
  });

  it.each(["forbiddenConclusions", "danglingEvidenceRefs", "confidenceIssues"] as const)(
    "still fails on a real run when %s is nonzero on any one case, regardless of perfect aggregates",
    (field) => {
      const cases = [
        ...Array.from({ length: 8 }, (_, i) => dirtyCase(`hit-${i}`)),
        dirtyCase("bad", { [field]: 1 }),
      ];
      const report = buildEvaluationReport(realInput(cases));
      expect(report.outcome).toBe("quality_failed");
    },
  );

  it("still fails on a real run when a clean case wrongly fails to abstain, regardless of aggregates", () => {
    const cleanCase: EvaluationCaseResult = {
      ...BASE_CASE,
      id: "clean-1",
      metrics: { ...BASE_CASE.metrics, abstained: false },
    };
    const report = buildEvaluationReport(realInput([dirtyCase("d1"), cleanCase]));
    expect(report.outcome).toBe("quality_failed");
  });

  it("still fails a real run on a runner/provider infrastructure failure, even with perfect aggregates", () => {
    const report = buildEvaluationReport(
      realInput([dirtyCase("d1"), { ...dirtyCase("d2"), status: "runner_failed" }]),
    );
    expect(report.outcome).toBe("runner_failed");
  });

  it("preserves original precedence when a runner failure and a provider failure land in DIFFERENT sections — runner_failed still wins", () => {
    // Regression guard: an earlier draft checked extraction/screenshot statuses before case
    // statuses, which silently reversed this precedence whenever the two failures came from
    // different sections. Case has runner_failed; extraction (a separate section) has
    // provider_failed — the combined-list check must still resolve to runner_failed.
    const report = buildEvaluationReport({
      ...realInput([{ ...dirtyCase("d1"), status: "runner_failed" }]),
      extraction: [
        {
          id: "ex-1",
          modality: "csv",
          status: "provider_failed",
          precision: 1,
          recall: 1,
          resources: BASE_CASE.resources,
          errorKind: "timeout",
        },
      ],
    });
    expect(report.outcome).toBe("runner_failed");
  });

  it("leaves the mock/deterministic path completely unchanged — a single quality_failed case still fails the whole run", () => {
    const mockInput: EvaluationReportInput = {
      identity: IDENTITY,
      corpusVersion: "1.0.0",
      cases: [dirtyCase("d1"), dirtyCase("d2", { claimRecall: 0 })], // real:false (default) — no aggregate tolerance
      extraction: [],
      screenshot: [],
      createdAt: "2026-07-31T00:00:00.000Z",
    };
    expect(buildEvaluationReport(mockInput).outcome).toBe("quality_failed");
  });

  it("returns a vacuously-satisfied (not NaN) aggregate when there are zero non-clean cases", () => {
    const cleanCase: EvaluationCaseResult = { ...BASE_CASE, id: "clean-1" };
    const aggregate = computeDirtyCaseAggregate([cleanCase]);
    expect(aggregate.claimRecall).toBe(1);
    expect(Number.isNaN(aggregate.claimRecall)).toBe(false);
    const report = buildEvaluationReport(realInput([cleanCase]));
    expect(report.outcome).toBe("passed");
  });
});
