import { readFile } from "node:fs/promises";
import { z } from "zod";
import { compareWithBaseline, evaluationIdentitySchema, type EvaluationBaseline } from "./baseline.js";
import { verifyAttestedReportShape } from "./changeGate.js";
import { buildEvaluationReport, type EvaluationReport, type EvaluationReportInput } from "./report.js";

// #1747: a candidate run that finished cleanly is kept even when its baseline could not be read
// (the report then carries `baselineError`). This module reads such a saved report back and
// compares it with a baseline later, with NO model call:
//   tsx tests/eval/run.ts --compare-report <saved.json> --baseline <b.json> --output <o.json> --attestation <a.json>
// Only a run that really finished is accepted. Every derived field (summary, resources, outcome,
// comparison) is dropped and recomputed by buildEvaluationReport, so a comparison made this way
// cannot differ from one made at the end of the live run.

const measure = z.number().finite().min(0);
const ratio = z.number().finite().min(0).max(1);
const status = z.enum(["passed", "quality_failed", "provider_failed", "runner_failed", "skipped"]);

const resourcesSchema = z
  .object({
    durationMs: measure,
    calls: measure,
    failedCalls: measure,
    inputTokens: measure,
    outputTokens: measure,
    costUsd: measure,
  })
  .strict();

const caseRowSchema = z
  .object({
    id: z.string().min(1),
    scenario: z.string().min(1),
    status,
    metrics: z
      .object({
        claimPrecision: ratio,
        claimRecall: ratio,
        iocPrecision: ratio,
        iocRecall: ratio,
        uncertaintyRecall: ratio,
        nextStepRecall: ratio,
        abstained: z.boolean(),
        forbiddenConclusions: measure,
        danglingEvidenceRefs: measure,
        confidenceIssues: measure,
        // Absent on rows written before #1747: read as zero.
        confidenceBandMisses: measure.default(0),
      })
      .strict(),
    resources: resourcesSchema,
    errorKind: z.string().optional(),
    runIndex: z.number().int().min(1).optional(),
    judge: z.object({ pairs: measure, asserted: measure, disagreements: measure }).strict().optional(),
  })
  .strict();

const extractionRowSchema = z
  .object({
    id: z.string().min(1),
    modality: z.enum(["csv", "log", "screenshot"]),
    status,
    precision: ratio,
    recall: ratio,
    resources: resourcesSchema,
    errorKind: z.string().optional(),
    runIndex: z.number().int().min(1).optional(),
    gate: z.object({ minPrecision: ratio, minRecall: ratio }).strict().optional(),
  })
  .strict();

// The saved report's own fields; derived ones are accepted here only so they can be dropped.
const savedReportSchema = z.object({
  identity: evaluationIdentitySchema,
  corpusVersion: z.string().min(1),
  cases: z.array(caseRowSchema),
  extraction: z.array(extractionRowSchema),
  screenshot: z.array(extractionRowSchema),
  createdAt: z.string().datetime(),
  real: z.literal(true, { errorMap: () => ({ message: "only a real (--real) run can be compared" }) }),
  runs: z.number().int().min(1),
  mode: z.string(),
  // An attestation must rest on real work: at least one case and one extraction check per run
  // (Codex review — zero of each scored as a vacuous perfect run). Screenshots may be absent.
  expected: z
    .object({
      cases: z.number().int().min(1),
      extraction: z.number().int().min(1),
      screenshot: z.number().int().min(0),
    })
    .strict(),
  skippedReason: z.string().optional(),
  providerFailureReason: z.string().optional(),
  runnerError: z.string().optional(),
  baselineError: z.string().optional(),
});

export async function loadSavedCandidate(path: string): Promise<EvaluationReportInput> {
  const saved = savedReportSchema.parse(JSON.parse(await readFile(path, "utf8")) as unknown);
  if (saved.runnerError) throw new Error(`${path}: the run ended with a runner error: ${saved.runnerError}`);
  if (saved.providerFailureReason) throw new Error(`${path}: the run ended with a provider failure`);
  if (saved.skippedReason) throw new Error(`${path}: the run was skipped`);
  const failedRow = [...saved.cases, ...saved.extraction, ...saved.screenshot].find(
    (row) => row.status === "provider_failed" || row.status === "runner_failed",
  );
  if (failedRow)
    throw new Error(`${path}: row ${failedRow.id} is ${failedRow.status}; the run did not finish cleanly`);
  const shape = verifyAttestedReportShape(saved, { runs: saved.runs }, { visionChanged: false });
  if (shape.length) throw new Error(`${path}: ${shape.join("; ")}`);
  return {
    identity: saved.identity,
    corpusVersion: saved.corpusVersion,
    cases: saved.cases,
    extraction: saved.extraction,
    screenshot: saved.screenshot,
    createdAt: saved.createdAt,
    real: true,
    runs: saved.runs,
    mode: "all",
    expected: saved.expected,
  };
}

export function recompareReport(
  input: EvaluationReportInput,
  baseline: EvaluationBaseline,
): EvaluationReport {
  const preliminary = buildEvaluationReport(input);
  return buildEvaluationReport({
    ...input,
    baselineComparison: compareWithBaseline(baseline, preliminary.summary, preliminary.identity, {
      real: true,
      runs: input.runs ?? 1,
      mode: "all",
    }),
  });
}
