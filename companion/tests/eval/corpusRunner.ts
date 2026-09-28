import { performance } from "node:perf_hooks";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";
import { runCorpusCase } from "./harness.js";
import { JudgeFailure, judgeForbiddenConclusions, type JudgeOutcome } from "./forbiddenJudge.js";
import { MeteredProvider } from "./meter.js";
import { TimeoutRetryProvider } from "./timeoutRetry.js";
import {
  forbiddenConclusionFindings,
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
  confidenceBandMisses: 0,
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
    confidenceBandMisses: score.confidenceBandMisses.length,
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
  // #1704: a judge that cannot grade is an evaluation-infrastructure failure, never a quiet pass
  // and never a fall-back to the word list.
  if (error instanceof JudgeFailure) return { status: "provider_failed", errorKind: error.kind };
  if (real) return { status: "quality_failed", errorKind: "invalid-model-output" };
  return { status: "runner_failed", errorKind: "deterministic-runner-error" };
}

// #1747: `lostMs` is wall time spent in a timed-out attempt that was retried; it is not the case's
// own cost, so it is left out of the measured duration.
function withTotalDuration(resources: EvaluationResources, started: number, lostMs = 0): EvaluationResources {
  return { ...resources, durationMs: Math.max(0, performance.now() - started - lostMs) };
}

// #1704: job log only — the judge's verdict beside the word list's, with the finding text and the
// judge's reason when either side says "asserted". Model text is JSON-escaped, never raw.
function logJudged(judged: JudgeOutcome): void {
  for (const detail of judged.details) {
    if (!detail.asserts && !detail.wordList) continue;
    console.log(
      `  judge ${detail.forbiddenId} in ${detail.findingId}: asserts=${detail.asserts} word-list=${detail.wordList}` +
        ` reason=${JSON.stringify(detail.reason)} text=${JSON.stringify(detail.text)}`,
    );
  }
}

async function runOne(
  fixture: CorpusCase,
  provider: AIProvider,
  real: boolean,
): Promise<EvaluationCaseResult> {
  const metered = new MeteredProvider(provider);
  // #1747: a real run retries one timed-out call; the meter underneath still counts both calls.
  const retry = new TimeoutRetryProvider(metered);
  const caller = real ? retry : metered;
  const started = performance.now();
  try {
    const output = await runCorpusCase(fixture, caller);
    const judged = real ? await judgeForbiddenConclusions(fixture.golden, output, caller) : undefined;
    const score = scoreCaseQuality(
      fixture.golden,
      output,
      judged ? { forbiddenIds: judged.assertedIds } : {},
    );
    console.log(formatCaseQualityReport(fixture.id, score, { real }));
    if (judged) logJudged(judged);
    else {
      for (const hit of forbiddenConclusionFindings(fixture.golden, output)) {
        console.log(`  forbidden ${hit.forbiddenId} in ${hit.findingId}: ${JSON.stringify(hit.text)}`);
      }
    }
    return {
      id: fixture.id,
      scenario: fixture.scenario,
      status: passesCaseQuality(score, { real }) ? "passed" : "quality_failed",
      metrics: metrics(score, fixture),
      resources: withTotalDuration(metered.snapshot(), started, retry.lostMs()),
      ...(judged && judged.stats.pairs > 0 ? { judge: { ...judged.stats } } : {}),
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
      resources: withTotalDuration(metered.snapshot(), started, retry.lostMs()),
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
