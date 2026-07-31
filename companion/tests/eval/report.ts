import type { BaselineComparison, EvaluationIdentity, EvaluationSummary } from "./baseline.js";

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

function determineOutcome(input: EvaluationReportInput): EvaluationOutcome {
  if (input.runnerError) return "runner_failed";
  if (input.providerFailureReason) return "provider_failed";
  if (input.skippedReason) return "skipped";
  if (input.baselineComparison?.status === "incompatible") return "runner_failed";
  if (input.baselineComparison?.status === "regressed") return "quality_failed";
  const statuses = [
    ...input.cases.map((result) => result.status),
    ...input.extraction.map((result) => result.status),
    ...input.screenshot.map((result) => result.status),
  ];
  if (statuses.includes("runner_failed")) return "runner_failed";
  if (statuses.includes("provider_failed")) return "provider_failed";
  if (statuses.includes("quality_failed")) return "quality_failed";
  if (statuses.length > 0 && statuses.every((status) => status === "skipped")) return "skipped";
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
