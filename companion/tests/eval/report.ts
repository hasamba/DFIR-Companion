import type { BaselineComparison, EvaluationIdentity, EvaluationSummary } from "./baseline.js";
import { REAL_THRESHOLDS } from "./scorer.js";

export type EvaluationOutcome = "passed" | "quality_failed" | "provider_failed" | "runner_failed" | "skipped";

export type EvaluationCaseStatus =
  "passed" | "quality_failed" | "provider_failed" | "runner_failed" | "skipped";

export interface EvaluationResources {
  durationMs: number;
  calls: number;
  failedCalls: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

export interface EvaluationCaseMetrics {
  claimPrecision: number;
  claimRecall: number;
  iocPrecision: number;
  iocRecall: number;
  uncertaintyRecall: number;
  nextStepRecall: number;
  abstained: boolean;
  forbiddenConclusions: number;
  danglingEvidenceRefs: number;
  confidenceIssues: number;
}

export interface EvaluationCaseResult {
  id: string;
  scenario: string;
  status: EvaluationCaseStatus;
  metrics: EvaluationCaseMetrics;
  resources: EvaluationResources;
  errorKind?: string;
}

export interface EvaluationExtractionResult {
  id: string;
  modality: "csv" | "log" | "screenshot";
  status: EvaluationCaseStatus;
  precision: number;
  recall: number;
  resources: EvaluationResources;
  errorKind?: string;
}

export interface EvaluationReportInput {
  identity: EvaluationIdentity;
  corpusVersion: string;
  cases: EvaluationCaseResult[];
  extraction: EvaluationExtractionResult[];
  screenshot: EvaluationExtractionResult[];
  createdAt: string;
  skippedReason?: string;
  providerFailureReason?: string;
  runnerError?: string;
  baselineComparison?: BaselineComparison;
  // Single source of truth: the SAME options.real already threaded into runCorpusSuite for the
  // #1217/#1226 precision relaxation — never set independently (#1224).
  real?: boolean;
}

export interface EvaluationReport extends EvaluationReportInput {
  schemaVersion: 1;
  outcome: EvaluationOutcome;
  summary: EvaluationSummary;
  resources: EvaluationResources;
  privacy: {
    containsEvidence: false;
    containsModelOutput: false;
    containsCredentials: false;
  };
}

const EMPTY_RESOURCES: EvaluationResources = {
  durationMs: 0,
  calls: 0,
  failedCalls: 0,
  inputTokens: 0,
  outputTokens: 0,
  costUsd: 0,
};

function addResources(left: EvaluationResources, right: EvaluationResources): EvaluationResources {
  return {
    durationMs: left.durationMs + right.durationMs,
    calls: left.calls + right.calls,
    failedCalls: left.failedCalls + right.failedCalls,
    inputTokens: left.inputTokens + right.inputTokens,
    outputTokens: left.outputTokens + right.outputTokens,
    costUsd: left.costUsd + right.costUsd,
  };
}

function average(values: readonly number[]): number {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 1;
}

// #1224: the production corpus's own single clean-abstention fixture would otherwise contribute a
// vacuous recall=1 to every aggregate (ratio(0,0)=1, since it has no golden claims/IOCs/etc to
// miss), silently inflating the floor every OTHER case is actually held to. Excluded here so the
// aggregate reflects only the cases that are supposed to produce findings.
export interface DirtyCaseAggregate {
  claimRecall: number;
  iocRecall: number;
  uncertaintyRecall: number;
  nextStepRecall: number;
}

export function computeDirtyCaseAggregate(cases: readonly EvaluationCaseResult[]): DirtyCaseAggregate {
  const dirty = cases.filter((result) => result.scenario !== "clean");
  return {
    claimRecall: average(dirty.map((result) => result.metrics.claimRecall)),
    iocRecall: average(dirty.map((result) => result.metrics.iocRecall)),
    uncertaintyRecall: average(dirty.map((result) => result.metrics.uncertaintyRecall)),
    nextStepRecall: average(dirty.map((result) => result.metrics.nextStepRecall)),
  };
}

function meetsRecallFloor(aggregate: DirtyCaseAggregate): boolean {
  const floor = REAL_THRESHOLDS.minRecall;
  return (
    aggregate.claimRecall >= floor &&
    aggregate.iocRecall >= floor &&
    aggregate.uncertaintyRecall >= floor &&
    aggregate.nextStepRecall >= floor
  );
}

// A hard violation is never relaxed, real run or not — these catch invention (a fabricated
// attribution, a citation to an event that doesn't exist, a confidence score with no stated
// reason), never a phrasing-variance false negative, so aggregate tolerance never applies to them.
function hasHardViolation(cases: readonly EvaluationCaseResult[]): boolean {
  return cases.some(
    (result) =>
      result.metrics.forbiddenConclusions > 0 ||
      result.metrics.danglingEvidenceRefs > 0 ||
      result.metrics.confidenceIssues > 0 ||
      !result.metrics.abstained,
  );
}

// A single case scoring 0 recall on EVERY dimension (the model produced nothing useful for it at
// all) must fail the run even if the corpus-wide aggregate still clears the floor — otherwise one
// genuinely broken case can hide behind several others scoring near-perfectly, which is exactly
// the failure mode the OLD all-or-nothing gate caught and pure averaging would not (#1224).
function hasTotalWhiff(cases: readonly EvaluationCaseResult[]): boolean {
  return cases.some(
    (result) =>
      result.scenario !== "clean" &&
      result.metrics.claimRecall === 0 &&
      result.metrics.uncertaintyRecall === 0 &&
      result.metrics.nextStepRecall === 0,
  );
}

function determineOutcome(input: EvaluationReportInput): EvaluationOutcome {
  if (input.runnerError) return "runner_failed";
  if (input.providerFailureReason) return "provider_failed";
  if (input.skippedReason) return "skipped";
  if (input.baselineComparison?.status === "incompatible") return "runner_failed";
  if (input.baselineComparison?.status === "regressed") return "quality_failed";

  const caseStatuses = input.cases.map((result) => result.status);
  const otherStatuses = [
    ...input.extraction.map((result) => result.status),
    ...input.screenshot.map((result) => result.status),
  ];
  // Checked across cases AND extraction/screenshot TOGETHER, in this order — matches the original
  // (pre-#1224) precedence exactly: an infrastructure failure anywhere always beats a provider
  // failure anywhere, regardless of which section it came from. Checking each section's own
  // statuses independently first (an earlier draft) silently reversed that precedence whenever an
  // infra failure and a provider failure land in DIFFERENT sections.
  const allInfraStatuses = [...caseStatuses, ...otherStatuses];
  if (allInfraStatuses.includes("runner_failed")) return "runner_failed";
  if (allInfraStatuses.includes("provider_failed")) return "provider_failed";

  // On a real run, aggregate recall (mirroring scorer.ts's REAL_THRESHOLDS) replaces requiring
  // every case's own status to be "passed" — the exact bug #1224 was filed for. Mock/deterministic
  // runs are completely unchanged: every case's exact per-case verdict still gates.
  const casesOk = input.real
    ? !hasHardViolation(input.cases) &&
      !hasTotalWhiff(input.cases) &&
      meetsRecallFloor(computeDirtyCaseAggregate(input.cases))
    : !caseStatuses.includes("quality_failed");
  if (!casesOk || otherStatuses.includes("quality_failed")) return "quality_failed";

  const allStatuses = [...caseStatuses, ...otherStatuses];
  if (allStatuses.length > 0 && allStatuses.every((status) => status === "skipped")) return "skipped";
  return "passed";
}

function reportResources(input: EvaluationReportInput): EvaluationResources {
  return [
    ...input.cases.map((result) => result.resources),
    ...input.extraction.map((result) => result.resources),
    ...input.screenshot.map((result) => result.resources),
  ].reduce(addResources, EMPTY_RESOURCES);
}

function reportSummary(input: EvaluationReportInput, resources: EvaluationResources): EvaluationSummary {
  const extraction = [...input.extraction, ...input.screenshot];
  const abstentionCases = input.cases.filter((result) => result.scenario === "clean");
  return {
    claimPrecision: average(input.cases.map((result) => result.metrics.claimPrecision)),
    claimRecall: average(input.cases.map((result) => result.metrics.claimRecall)),
    eventPrecision: average(extraction.map((result) => result.precision)),
    eventRecall: average(extraction.map((result) => result.recall)),
    iocPrecision: average(input.cases.map((result) => result.metrics.iocPrecision)),
    iocRecall: average(input.cases.map((result) => result.metrics.iocRecall)),
    abstentionRate: average(abstentionCases.map((result) => (result.metrics.abstained ? 1 : 0))),
    forbiddenConclusions: input.cases.reduce((sum, result) => sum + result.metrics.forbiddenConclusions, 0),
    danglingEvidenceRefs: input.cases.reduce((sum, result) => sum + result.metrics.danglingEvidenceRefs, 0),
    confidenceIssues: input.cases.reduce((sum, result) => sum + result.metrics.confidenceIssues, 0),
    uncertaintyRecall: average(input.cases.map((result) => result.metrics.uncertaintyRecall)),
    nextStepRecall: average(input.cases.map((result) => result.metrics.nextStepRecall)),
    durationMs: resources.durationMs,
    inputTokens: resources.inputTokens,
    outputTokens: resources.outputTokens,
    costUsd: resources.costUsd,
  };
}

export function buildEvaluationReport(input: EvaluationReportInput): EvaluationReport {
  const resources = reportResources(input);
  return {
    schemaVersion: 1,
    identity: { ...input.identity },
    corpusVersion: input.corpusVersion,
    cases: input.cases.map((result) => ({ ...result })),
    extraction: input.extraction.map((result) => ({ ...result })),
    screenshot: input.screenshot.map((result) => ({ ...result })),
    createdAt: input.createdAt,
    ...(input.skippedReason ? { skippedReason: input.skippedReason } : {}),
    ...(input.providerFailureReason ? { providerFailureReason: input.providerFailureReason } : {}),
    ...(input.runnerError ? { runnerError: input.runnerError } : {}),
    ...(input.baselineComparison ? { baselineComparison: { ...input.baselineComparison } } : {}),
    outcome: determineOutcome(input),
    summary: reportSummary(input, resources),
    resources,
    privacy: {
      containsEvidence: false,
      containsModelOutput: false,
      containsCredentials: false,
    },
  };
}

export function reportExitCode(outcome: EvaluationOutcome): number {
  switch (outcome) {
    case "passed":
    case "skipped":
      return 0;
    case "quality_failed":
      return 1;
    case "runner_failed":
      return 2;
    case "provider_failed":
      return 3;
  }
}
