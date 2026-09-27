import { describe, expect, it } from "vitest";
import {
  baseCaseId,
  buildEvaluationReport,
  computeDirtyCaseAggregate,
  passesWithoutRecallFloor,
  reportExitCode,
  type EvaluationCaseResult,
  type EvaluationExtractionResult,
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

  describe("a baseline replaces the recall floor on a real run (#1579)", () => {
    // 2 hits + 1 next-step miss → nextStepRecall aggregate 2/3, below the 0.7 floor.
    const belowFloor = (): EvaluationCaseResult[] => [
      dirtyCase("hit-0"),
      dirtyCase("hit-1"),
      dirtyCase("low", { nextStepRecall: 0 }),
    ];
    const comparison = (status: "passed" | "regressed") => ({
      status,
      baselineKey: "k",
      qualityRegressions: status === "regressed" ? ["nextStepRecall"] : [],
      resourceRegressions: [],
      reasons: [],
    });

    it("passes a below-floor run that did not regress against its baseline", () => {
      const report = buildEvaluationReport({
        ...realInput(belowFloor()),
        baselineComparison: comparison("passed"),
      });
      expect(report.outcome).toBe("passed");
    });

    it("still fails a run that regressed against its baseline", () => {
      const report = buildEvaluationReport({
        ...realInput(belowFloor()),
        baselineComparison: comparison("regressed"),
      });
      expect(report.outcome).toBe("quality_failed");
    });

    it("never relaxes a hard violation or a total whiff because a baseline is present", () => {
      const violation = [...belowFloor(), dirtyCase("bad", { confidenceIssues: 1 })];
      const whiff = [
        ...belowFloor(),
        dirtyCase("whiff", { claimRecall: 0, uncertaintyRecall: 0, nextStepRecall: 0 }),
      ];
      for (const cases of [violation, whiff]) {
        const report = buildEvaluationReport({
          ...realInput(cases),
          baselineComparison: comparison("passed"),
        });
        expect(report.outcome).toBe("quality_failed");
      }
    });

    it("without a baseline, fails the floor but still counts the run as recordable as the first baseline", () => {
      const report = buildEvaluationReport(realInput(belowFloor()));
      expect(report.outcome).toBe("quality_failed");
      expect(passesWithoutRecallFloor(report)).toBe(true);
    });

    it("a run with a hard violation is never recordable as a baseline", () => {
      const report = buildEvaluationReport(
        realInput([...belowFloor(), dirtyCase("bad", { forbiddenConclusions: 1 })]),
      );
      expect(passesWithoutRecallFloor(report)).toBe(false);
    });

    it("reports a provider failure as provider_failed, not as a regression it caused (#1579)", () => {
      // Protected run 36233745167: OpenRouter ran out of credits mid-run; the dead rows dragged the
      // summary below the baseline, and the outcome said quality_failed instead of provider_failed.
      const dead: EvaluationCaseResult = { ...dirtyCase("dead"), status: "provider_failed" };
      const report = buildEvaluationReport({
        ...realInput([...belowFloor(), dead]),
        baselineComparison: comparison("regressed"),
      });
      expect(report.outcome).toBe("provider_failed");
    });

    it("a mock run is never recordable past a failed case", () => {
      const report = buildEvaluationReport({ ...realInput(belowFloor()), real: false });
      expect(passesWithoutRecallFloor(report)).toBe(false);
    });
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

// #1579: a real run repeats the corpus 3 times. The summary is the per-run mean (so a 3-run
// baseline stays on the 1-run scale), and an extraction fixture passes on its MEAN over the runs,
// not on every single run. Infra failures and hard violations in any one run still fail.
describe("pooled multi-run reports (#1579)", () => {
  const IDENTITY = {
    provider: "mock",
    model: "mock-model",
    promptHash: "a".repeat(64),
    sourceHash: "b".repeat(64),
    corpusHash: "c".repeat(64),
  };
  const GATE = { minPrecision: 0.7, minRecall: 0.7 };

  function runId(id: string, run: number): string {
    return run === 1 ? id : `${id}#run${run}`;
  }

  function dirtyRun(id: string, run: number, overrides: Partial<EvaluationCaseResult["metrics"]> = {}) {
    return {
      ...BASE_CASE,
      id: runId(id, run),
      runIndex: run,
      scenario: "ransomware",
      status: "passed",
      metrics: { ...BASE_CASE.metrics, ...overrides },
      resources: {
        durationMs: 30,
        calls: 3,
        failedCalls: 0,
        inputTokens: 90,
        outputTokens: 30,
        costUsd: 0.3,
      },
    } satisfies EvaluationCaseResult;
  }

  function extractionRun(
    id: string,
    run: number,
    recall: number,
    extra: Partial<EvaluationExtractionResult> = {},
  ): EvaluationExtractionResult {
    return {
      id: runId(id, run),
      runIndex: run,
      modality: "csv",
      status: recall >= GATE.minRecall ? "passed" : "quality_failed",
      precision: 1,
      recall,
      resources: { ...BASE_CASE.resources },
      gate: GATE,
      ...extra,
    };
  }

  function pooled(overrides: Partial<EvaluationReportInput> = {}): EvaluationReportInput {
    return {
      identity: IDENTITY,
      corpusVersion: "1.0.0",
      cases: [1, 2, 3].map((run) => dirtyRun("d1", run)),
      extraction: [],
      screenshot: [],
      createdAt: "2026-07-31T00:00:00.000Z",
      real: true,
      runs: 3,
      mode: "all",
      expected: { cases: 1, extraction: 0, screenshot: 0 },
      ...overrides,
    };
  }

  it("strips the run suffix to find the fixture", () => {
    expect(baseCaseId("csv-1#run2")).toBe("csv-1");
    expect(baseCaseId("csv-1#run10")).toBe("csv-1");
    expect(baseCaseId("csv-1")).toBe("csv-1");
  });

  it("averages ratios, divides counts and summary resources by the run count, and keeps the total resources", () => {
    const cases = [
      dirtyRun("d1", 1, { claimRecall: 0.9 }),
      dirtyRun("d2", 1, { claimRecall: 0.7 }),
      dirtyRun("d1", 2, { claimRecall: 0.8 }),
      dirtyRun("d2", 2, { claimRecall: 1 }),
      dirtyRun("d1", 3, { claimRecall: 0.6, confidenceIssues: 1 }),
      dirtyRun("d2", 3, { claimRecall: 0.9 }),
    ];
    const report = buildEvaluationReport(pooled({ cases, real: false }));
    const perRunMeans = [(0.9 + 0.7) / 2, (0.8 + 1) / 2, (0.6 + 0.9) / 2];
    expect(report.summary.claimRecall).toBeCloseTo(perRunMeans.reduce((a, b) => a + b, 0) / 3, 10);
    expect(report.summary.confidenceIssues).toBeCloseTo(1 / 3, 10);
    expect(report.resources).toMatchObject({
      durationMs: 180,
      inputTokens: 540,
      outputTokens: 180,
      calls: 18,
    });
    expect(report.resources.costUsd).toBeCloseTo(1.8, 10);
    expect(report.summary.durationMs).toBeCloseTo(60, 10);
    expect(report.summary.inputTokens).toBeCloseTo(180, 10);
    expect(report.summary.outputTokens).toBeCloseTo(60, 10);
    expect(report.summary.costUsd).toBeCloseTo(0.6, 10);
    expect(report.runs).toBe(3);
    expect(report.mode).toBe("all");
    expect(report.expected).toEqual({ cases: 1, extraction: 0, screenshot: 0 });
  });

  it("passes an extraction fixture on its mean recall (0.9, 0.9, 0.5 → 0.767) though one run failed", () => {
    const extraction = [
      extractionRun("csv-1", 1, 0.9),
      extractionRun("csv-1", 2, 0.9),
      extractionRun("csv-1", 3, 0.5),
    ];
    expect(extraction[2]?.status).toBe("quality_failed");
    expect(buildEvaluationReport(pooled({ extraction })).outcome).toBe("passed");
  });

  it("fails an extraction fixture whose mean recall (0.9, 0.5, 0.5 → 0.633) is under its gate", () => {
    const extraction = [
      extractionRun("csv-1", 1, 0.9),
      extractionRun("csv-1", 2, 0.5),
      extractionRun("csv-1", 3, 0.5),
    ];
    expect(buildEvaluationReport(pooled({ extraction })).outcome).toBe("quality_failed");
  });

  it("judges each fixture on its own mean — a good fixture cannot carry a bad one", () => {
    const extraction = [
      ...[1, 2, 3].map((run) => extractionRun("csv-good", run, 1)),
      ...[1, 2, 3].map((run) => extractionRun("csv-bad", run, 0.5)),
    ];
    expect(buildEvaluationReport(pooled({ extraction })).outcome).toBe("quality_failed");
  });

  it("judges screenshot fixtures on their mean too", () => {
    const screenshot = [1, 2, 3].map((run) =>
      extractionRun("shot-1", run, run === 3 ? 0.5 : 0.9, { modality: "screenshot" }),
    );
    expect(buildEvaluationReport(pooled({ screenshot })).outcome).toBe("passed");
  });

  it("falls back to the row status when a row has no gate", () => {
    const extraction = [1, 2, 3].map((run) => {
      const { gate: _gate, ...row } = extractionRun("csv-1", run, run === 3 ? 0.5 : 0.9);
      return row;
    });
    expect(buildEvaluationReport(pooled({ extraction })).outcome).toBe("quality_failed");
  });

  it("fails on a hard violation in run 2 only", () => {
    const cases = [dirtyRun("d1", 1), dirtyRun("d1", 2, { danglingEvidenceRefs: 1 }), dirtyRun("d1", 3)];
    expect(buildEvaluationReport(pooled({ cases })).outcome).toBe("quality_failed");
  });

  it("reports provider_failed when any one run's row failed at the provider", () => {
    const extraction = [
      extractionRun("csv-1", 1, 0.9),
      extractionRun("csv-1", 2, 0.9, { status: "provider_failed", errorKind: "timeout" }),
      extractionRun("csv-1", 3, 0.9),
    ];
    expect(buildEvaluationReport(pooled({ extraction })).outcome).toBe("provider_failed");
  });

  it("defaults to one run in mode all and divides nothing", () => {
    const report = buildEvaluationReport({
      identity: IDENTITY,
      corpusVersion: "1.0.0",
      cases: [BASE_CASE],
      extraction: [],
      screenshot: [],
      createdAt: "2026-07-31T00:00:00.000Z",
    });
    expect(report.runs).toBe(1);
    expect(report.mode).toBe("all");
    expect(report.expected).toBeUndefined();
    expect(report.summary.durationMs).toBe(BASE_CASE.resources.durationMs);
    expect(report.summary.inputTokens).toBe(BASE_CASE.resources.inputTokens);
  });

  it("keeps per-row verdicts on a mock run — one failed run fails the fixture", () => {
    const extraction = [
      extractionRun("csv-1", 1, 0.9),
      extractionRun("csv-1", 2, 0.9),
      extractionRun("csv-1", 3, 0.5),
    ];
    expect(buildEvaluationReport(pooled({ extraction, real: false })).outcome).toBe("quality_failed");
  });
});
