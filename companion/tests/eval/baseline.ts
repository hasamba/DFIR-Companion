export interface EvaluationIdentity {
  provider: string;
  model: string;
  promptHash: string;
  sourceHash: string;
  corpusHash: string;
}

export interface EvaluationSummary {
  claimPrecision: number;
  claimRecall: number;
  eventPrecision: number;
  eventRecall: number;
  iocPrecision: number;
  iocRecall: number;
  abstentionRate: number;
  forbiddenConclusions: number;
  danglingEvidenceRefs: number;
  confidenceIssues: number;
  uncertaintyRecall: number;
  nextStepRecall: number;
  durationMs: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

export interface EvaluationBaseline {
  schemaVersion: 1;
  key: string;
  identity: EvaluationIdentity;
  recordedAt: string;
  summary: EvaluationSummary;
}

export interface BaselineComparison {
  status: "passed" | "regressed" | "incompatible";
  baselineKey: string;
  qualityRegressions: string[];
  resourceRegressions: string[];
  reasons: string[];
}

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const evaluationIdentitySchema: z.ZodType<EvaluationIdentity> = z
  .object({
    provider: z.string().min(1),
    model: z.string().min(1),
    promptHash: sha256Schema,
    sourceHash: sha256Schema,
    corpusHash: sha256Schema,
  })
  .strict();

const evaluationSummarySchema: z.ZodType<EvaluationSummary> = z
  .object({
    claimPrecision: z.number().min(0).max(1),
    claimRecall: z.number().min(0).max(1),
    eventPrecision: z.number().min(0).max(1),
    eventRecall: z.number().min(0).max(1),
    iocPrecision: z.number().min(0).max(1),
    iocRecall: z.number().min(0).max(1),
    abstentionRate: z.number().min(0).max(1),
    forbiddenConclusions: z.number().int().nonnegative(),
    danglingEvidenceRefs: z.number().int().nonnegative(),
    confidenceIssues: z.number().int().nonnegative(),
    uncertaintyRecall: z.number().min(0).max(1),
    nextStepRecall: z.number().min(0).max(1),
    durationMs: z.number().nonnegative(),
    inputTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    costUsd: z.number().nonnegative(),
  })
  .strict();

const evaluationBaselineSchema: z.ZodType<EvaluationBaseline> = z
  .object({
    schemaVersion: z.literal(1),
    key: z.string().min(1),
    identity: evaluationIdentitySchema,
    recordedAt: z.string().datetime(),
    summary: evaluationSummarySchema,
  })
  .strict();

const QUALITY_HIGHER_IS_BETTER = [
  "claimPrecision",
  "claimRecall",
  "eventPrecision",
  "eventRecall",
  "iocPrecision",
  "iocRecall",
  "abstentionRate",
  "uncertaintyRecall",
  "nextStepRecall",
] as const;

const QUALITY_LOWER_IS_BETTER = ["forbiddenConclusions", "danglingEvidenceRefs", "confidenceIssues"] as const;

const RESOURCE_KEYS = ["durationMs", "inputTokens", "outputTokens", "costUsd"] as const;
const QUALITY_TOLERANCE = 0.02;
const RESOURCE_MULTIPLIER = 1.25;

export function baselineKey(identity: EvaluationIdentity): string {
  return `${identity.provider}/${identity.model}/${identity.promptHash}`;
}

export function createBaseline(
  identity: EvaluationIdentity,
  summary: EvaluationSummary,
  recordedAt: string,
): EvaluationBaseline {
  return {
    schemaVersion: 1,
    key: baselineKey(identity),
    identity: { ...identity },
    recordedAt,
    summary: { ...summary },
  };
}

function safePart(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function baselineFileName(baseline: EvaluationBaseline): string {
  return (
    [
      safePart(baseline.identity.provider),
      safePart(baseline.identity.model),
      baseline.identity.promptHash.slice(0, 12),
    ].join("--") + ".json"
  );
}

function incompatibleReasons(baseline: EvaluationBaseline, identity: EvaluationIdentity): string[] {
  const reasons: string[] = [];
  if (baseline.identity.provider !== identity.provider) reasons.push("provider changed");
  if (baseline.identity.model !== identity.model) reasons.push("model changed");
  if (baseline.identity.corpusHash !== identity.corpusHash) reasons.push("corpus changed");
  return reasons;
}

function qualityRegressions(baseline: EvaluationSummary, current: EvaluationSummary): string[] {
  return [
    ...QUALITY_HIGHER_IS_BETTER.filter((key) => current[key] < baseline[key] - QUALITY_TOLERANCE),
    ...QUALITY_LOWER_IS_BETTER.filter((key) => current[key] > baseline[key]),
  ];
}

function resourceRegressions(baseline: EvaluationSummary, current: EvaluationSummary): string[] {
  return RESOURCE_KEYS.filter((key) => {
    if (baseline[key] === 0) return current[key] > 0;
    return current[key] > baseline[key] * RESOURCE_MULTIPLIER;
  });
}

export function compareWithBaseline(
  baseline: EvaluationBaseline,
  current: EvaluationSummary,
  identity: EvaluationIdentity,
): BaselineComparison {
  const reasons = incompatibleReasons(baseline, identity);
  if (reasons.length) {
    return {
      status: "incompatible",
      baselineKey: baseline.key,
      qualityRegressions: [],
      resourceRegressions: [],
      reasons,
    };
  }
  const quality = qualityRegressions(baseline.summary, current);
  const resources = resourceRegressions(baseline.summary, current);
  return {
    status: quality.length || resources.length ? "regressed" : "passed",
    baselineKey: baseline.key,
    qualityRegressions: quality,
    resourceRegressions: resources,
    reasons: [],
  };
}

export async function readBaseline(path: string): Promise<EvaluationBaseline> {
  const raw = await readFile(path, "utf8");
  const parsed = evaluationBaselineSchema.parse(JSON.parse(raw) as unknown);
  if (parsed.key !== baselineKey(parsed.identity)) {
    throw new Error(`${path}: baseline key does not match its pinned provider/model/prompt`);
  }
  return parsed;
}

export async function writeBaseline(directory: string, baseline: EvaluationBaseline): Promise<string> {
  await mkdir(directory, { recursive: true });
  const path = join(directory, baselineFileName(baseline));
  await writeFile(path, `${JSON.stringify(baseline, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  return path;
}
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
