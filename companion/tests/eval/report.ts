import type { BaselineComparison, EvaluationIdentity, EvaluationSummary } from "./baseline.js";
import { REAL_THRESHOLDS } from "./scorer.js";

export type EvaluationOutcome = "passed" | "quality_failed" | "provider_failed" | "runner_failed" | "skipped";

export type EvaluationCaseStatus =
  "passed" | "quality_failed" | "provider_failed" | "runner_failed" | "skipped";

export type EvaluationMode = "all" | "extraction" | "synthesis" | "screenshots";

// Fixture and case counts for ONE run; a report of N runs holds N times these rows (#1579).
export interface EvaluationExpectedCounts {
  cases: number;
  extraction: number;
  screenshot: number;
}

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
  // 1-based run number; absent = run 1. Run k >= 2 also suffixes the id with `#run${k}`.
  runIndex?: number;
}

export interface EvaluationExtractionResult {
  id: string;
  modality: "csv" | "log" | "screenshot";
  status: EvaluationCaseStatus;
  precision: number;
  recall: number;
  resources: EvaluationResources;
  errorKind?: string;
  runIndex?: number;
  // The thresholds this row was scored against. Absent → the row's own status decides.
  gate?: { minPrecision: number; minRecall: number };
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
  runs?: number;
  mode?: EvaluationMode;
  expected?: EvaluationExpectedCounts;
}

export interface EvaluationReport extends EvaluationReportInput {
  schemaVersion: 1;
  runs: number;
  mode: EvaluationMode;
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

const RUN_SUFFIX = /#run\d+$/;

export function baseCaseId(id: string): string {
  return id.replace(RUN_SUFFIX, "");
}

function runCount(input: EvaluationReportInput): number {
  return input.runs ?? 1;
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

function meetsGate(rows: readonly EvaluationExtractionResult[]): boolean {
  const scored = rows.filter((row) => row.status !== "skipped");
  const gate = scored[0]?.gate;
  if (!gate) return true;
  return (
    average(scored.map((row) => row.precision)) >= gate.minPrecision &&
    average(scored.map((row) => row.recall)) >= gate.minRecall
  );
}

// #1579: on a real run one fixture is extracted once per run, and a real model can miss on one
// run and hit on the next. A gated fixture passes on its MEAN precision/recall over the runs vs
// the thresholds it was scored against; a row without a gate keeps its own status. Mock runs
// never reach this: every row's own verdict still gates.
function hasFixtureQualityFailure(rows: readonly EvaluationExtractionResult[]): boolean {
  const ungated = rows.filter((row) => !row.gate);
  if (ungated.some((row) => row.status === "quality_failed")) return true;
  const fixtures = new Map<string, EvaluationExtractionResult[]>();
  for (const row of rows.filter((candidate) => candidate.gate)) {
    const key = `${row.modality}:${baseCaseId(row.id)}`;
    fixtures.set(key, [...(fixtures.get(key) ?? []), row]);
  }
  return [...fixtures.values()].some((fixture) => !meetsGate(fixture));
}

// #1579: the fixed recall floor is a stand-in for "good enough" until a human accepts a real
// baseline. Once a real run is compared against one, "no worse than the accepted baseline" is the
// bar, so a model that sits below the floor (next-step recall, today) can still attest a prompt
// fix. Hard violations and a total whiff are never relaxed.
function determineOutcome(
  input: EvaluationReportInput,
  recallFloor = !input.baselineComparison,
): EvaluationOutcome {
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
      (!recallFloor || meetsRecallFloor(computeDirtyCaseAggregate(input.cases)))
    : !caseStatuses.includes("quality_failed");
  const otherOk = input.real
    ? !hasFixtureQualityFailure([...input.extraction, ...input.screenshot])
    : !otherStatuses.includes("quality_failed");
  if (!casesOk || !otherOk) return "quality_failed";

  const allStatuses = [...caseStatuses, ...otherStatuses];
  if (allStatuses.length > 0 && allStatuses.every((status) => status === "skipped")) return "skipped";
  return "passed";
}

// True when the run fails, if at all, only on the recall floor. Such a real run may still be
// written as the FIRST candidate baseline, so today's real scores can be accepted as the bar.
export function passesWithoutRecallFloor(input: EvaluationReportInput): boolean {
  return determineOutcome(input, false) === "passed";
}

function reportResources(input: EvaluationReportInput): EvaluationResources {
  return [
    ...input.cases.map((result) => result.resources),
    ...input.extraction.map((result) => result.resources),
    ...input.screenshot.map((result) => result.resources),
  ].reduce(addResources, EMPTY_RESOURCES);
}

// #1579: ratios are the mean over every pooled row (equal to the mean of the per-run means, since
// each run holds the same rows). Counts and resources are divided by the run count so a 3-run
// summary sits on the same per-run scale as a 1-run baseline. report.resources stays the total.
function reportSummary(input: EvaluationReportInput, resources: EvaluationResources): EvaluationSummary {
  const extraction = [...input.extraction, ...input.screenshot];
  const runs = runCount(input);
  const perRun = (value: number): number => value / runs;
  const abstentionCases = input.cases.filter((result) => result.scenario === "clean");
  return {
    claimPrecision: average(input.cases.map((result) => result.metrics.claimPrecision)),
    claimRecall: average(input.cases.map((result) => result.metrics.claimRecall)),
    eventPrecision: average(extraction.map((result) => result.precision)),
    eventRecall: average(extraction.map((result) => result.recall)),
    iocPrecision: average(input.cases.map((result) => result.metrics.iocPrecision)),
    iocRecall: average(input.cases.map((result) => result.metrics.iocRecall)),
    abstentionRate: average(abstentionCases.map((result) => (result.metrics.abstained ? 1 : 0))),
    forbiddenConclusions: perRun(
      input.cases.reduce((sum, result) => sum + result.metrics.forbiddenConclusions, 0),
    ),
    danglingEvidenceRefs: perRun(
      input.cases.reduce((sum, result) => sum + result.metrics.danglingEvidenceRefs, 0),
    ),
    confidenceIssues: perRun(input.cases.reduce((sum, result) => sum + result.metrics.confidenceIssues, 0)),
    uncertaintyRecall: average(input.cases.map((result) => result.metrics.uncertaintyRecall)),
    nextStepRecall: average(input.cases.map((result) => result.metrics.nextStepRecall)),
    durationMs: perRun(resources.durationMs),
    inputTokens: perRun(resources.inputTokens),
    outputTokens: perRun(resources.outputTokens),
    costUsd: perRun(resources.costUsd),
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
    runs: runCount(input),
    mode: input.mode ?? "all",
    ...(input.expected ? { expected: { ...input.expected } } : {}),
    ...(input.real !== undefined ? { real: input.real } : {}),
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
