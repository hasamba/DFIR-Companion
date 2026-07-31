import { performance } from "node:perf_hooks";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";
import { runCorpusCase } from "./harness.js";
import { MeteredProvider } from "./meter.js";
import {
  formatCaseQualityReport,
  passesCaseQuality,
  scoreCaseQuality,
  type CaseQualityScore,
} from "./qualityScorer.js";
import type { CorpusCase, GoldenCorpus } from "./corpus.js";
import type {
  EvaluationCaseMetrics,
  EvaluationCaseResult,
  EvaluationCaseStatus,
  EvaluationResources,
} from "./report.js";

type ProviderForCorpus = (fixture: CorpusCase) => AIProvider;

const FAILED_METRICS: EvaluationCaseMetrics = {
  claimPrecision: 0,
  claimRecall: 0,
  iocPrecision: 0,
  iocRecall: 0,
  uncertaintyRecall: 0,
  nextStepRecall: 0,
  abstained: false,
  forbiddenConclusions: 0,
  danglingEvidenceRefs: 0,
  confidenceIssues: 0,
};

function metrics(score: CaseQualityScore, fixture: CorpusCase): EvaluationCaseMetrics {
  return {
    claimPrecision: score.claims.precision,
    claimRecall: score.claims.recall,
    iocPrecision: score.iocs.precision,
    iocRecall: score.iocs.recall,
    uncertaintyRecall: score.uncertainties.recall,
    nextStepRecall: score.nextSteps.recall,
    abstained: !fixture.golden.expectAbstention || score.abstentionPassed,
    forbiddenConclusions: score.forbiddenConclusions.length,
    danglingEvidenceRefs: score.danglingEvidenceRefs.length,
    confidenceIssues: score.confidenceIssues.length,
  };
}

function errorStatus(
  error: unknown,
  real: boolean,
): {
  status: EvaluationCaseStatus;
  errorKind: string;
} {
  if (error instanceof ProviderError) {
    return { status: "provider_failed", errorKind: error.kind };
  }
  if (real) return { status: "quality_failed", errorKind: "invalid-model-output" };
  return { status: "runner_failed", errorKind: "deterministic-runner-error" };
}

function withTotalDuration(resources: EvaluationResources, started: number): EvaluationResources {
  return { ...resources, durationMs: performance.now() - started };
}

async function runOne(
  fixture: CorpusCase,
  provider: AIProvider,
  real: boolean,
): Promise<EvaluationCaseResult> {
  const metered = new MeteredProvider(provider);
  const started = performance.now();
  try {
    const output = await runCorpusCase(fixture, metered);
    const score = scoreCaseQuality(fixture.golden, output);
    console.log(formatCaseQualityReport(fixture.id, score));
    return {
      id: fixture.id,
      scenario: fixture.scenario,
      status: passesCaseQuality(score) ? "passed" : "quality_failed",
      metrics: metrics(score, fixture),
      resources: withTotalDuration(metered.snapshot(), started),
    };
  } catch (error) {
    const classified = errorStatus(error, real);
    console.log(`[FAIL] production: ${fixture.id} — ${classified.errorKind}`);
    console.log(`  ${error instanceof Error ? error.message : String(error)}`);
    return {
      id: fixture.id,
      scenario: fixture.scenario,
      status: classified.status,
      metrics: { ...FAILED_METRICS },
      resources: withTotalDuration(metered.snapshot(), started),
      errorKind: classified.errorKind,
    };
  }
}

export async function runCorpusSuite(
  corpus: GoldenCorpus,
  providerFor: ProviderForCorpus,
  real: boolean,
): Promise<EvaluationCaseResult[]> {
  const results: EvaluationCaseResult[] = [];
  for (const fixture of corpus.cases) {
    results.push(await runOne(fixture, providerFor(fixture), real));
  }
  return results;
}
