export interface EvaluationIdentity {
  provider: string;
  model: string;
  promptHash: string;
  sourceHash: string;
  corpusHash: string;
  // #1579: set only when the screenshot section ran against a real vision provider.
  // setHash pins WHICH screenshots were graded, so a swapped or reduced set is not comparable.
  vision?: { provider: string; model: string; setHash?: string };
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
  // #1579: the evaluation profile the summary was measured under. Absent = 1 run, mode "all".
  runs?: number;
  mode?: string;
}

// The profile a candidate run is compared under: its real/mock tolerance, run count, and mode.
export interface BaselineProfile {
  real: boolean;
  runs: number;
  mode: string;
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
    vision: z
      .object({ provider: z.string().min(1), model: z.string().min(1), setHash: sha256Schema.optional() })
      .strict()
      .optional(),
  })
  .strict();

// #1579: summary counts and tokens are per-run means, so a 3-run summary can be fractional.
const nonNegativeMeasure = z.number().finite().min(0);

const evaluationSummarySchema: z.ZodType<EvaluationSummary> = z
  .object({
    claimPrecision: z.number().min(0).max(1),
    claimRecall: z.number().min(0).max(1),
    eventPrecision: z.number().min(0).max(1),
    eventRecall: z.number().min(0).max(1),
    iocPrecision: z.number().min(0).max(1),
    iocRecall: z.number().min(0).max(1),
    abstentionRate: z.number().min(0).max(1),
    forbiddenConclusions: nonNegativeMeasure,
    danglingEvidenceRefs: nonNegativeMeasure,
    confidenceIssues: nonNegativeMeasure,
    uncertaintyRecall: z.number().min(0).max(1),
    nextStepRecall: z.number().min(0).max(1),
    durationMs: z.number().nonnegative(),
    inputTokens: nonNegativeMeasure,
    outputTokens: nonNegativeMeasure,
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
    runs: z.number().int().min(1).optional(),
    mode: z.string().min(1).optional(),
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
// #1579: a real model moves a few points between runs even on unchanged input, so a real run
// (averaged over MIN_ATTESTED_RUNS runs) gets a wider tolerance. This is a policy that damps
// noise, not a statistical guarantee. Mock runs are deterministic and keep the tight tolerance.
const REAL_QUALITY_TOLERANCE = 0.05;
export const MIN_ATTESTED_RUNS = 3;
const DEFAULT_MODE = "all";
const RESOURCE_MULTIPLIER = 1.25;

// A 1-run key is unchanged so existing baselines still match; a multi-run key is suffixed so a
// 3-run baseline never collides with a 1-run one.
export function baselineKey(identity: EvaluationIdentity, runs = 1): string {
  const key = `${identity.provider}/${identity.model}/${identity.promptHash}`;
  return runs > 1 ? `${key}/r${runs}` : key;
}

export function createBaseline(
  identity: EvaluationIdentity,
  summary: EvaluationSummary,
  recordedAt: string,
  profile?: { runs: number; mode: string },
): EvaluationBaseline {
  return {
    schemaVersion: 1,
    key: baselineKey(identity, profile?.runs),
    identity: { ...identity, ...(identity.vision ? { vision: { ...identity.vision } } : {}) },
    recordedAt,
    summary: { ...summary },
    ...(profile ? { runs: profile.runs, mode: profile.mode } : {}),
  };
}

function runsOf(baseline: EvaluationBaseline): number {
  return baseline.runs ?? 1;
}

function sameVision(left: EvaluationIdentity["vision"], right: EvaluationIdentity["vision"]): boolean {
  if (!left || !right) return left === right;
  return left.provider === right.provider && left.model === right.model && left.setHash === right.setHash;
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
      ...(runsOf(baseline) > 1 ? [`r${runsOf(baseline)}`] : []),
    ].join("--") + ".json"
  );
}

function incompatibleReasons(
  baseline: EvaluationBaseline,
  identity: EvaluationIdentity,
  profile: BaselineProfile,
): string[] {
  const reasons: string[] = [];
  if (baseline.identity.provider !== identity.provider) reasons.push("provider changed");
  if (baseline.identity.model !== identity.model) reasons.push("model changed");
  if (baseline.identity.corpusHash !== identity.corpusHash) reasons.push("corpus changed");
  if (!sameVision(baseline.identity.vision, identity.vision))
    reasons.push("vision model or screenshot set changed");
  if (runsOf(baseline) !== profile.runs) reasons.push("run count changed");
  if ((baseline.mode ?? DEFAULT_MODE) !== profile.mode) reasons.push("evaluation mode changed");
  return reasons;
}

function qualityRegressions(
  baseline: EvaluationSummary,
  current: EvaluationSummary,
  tolerance: number,
): string[] {
  return [
    ...QUALITY_HIGHER_IS_BETTER.filter((key) => current[key] < baseline[key] - tolerance),
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
  profile: BaselineProfile,
): BaselineComparison {
  const reasons = incompatibleReasons(baseline, identity, profile);
  if (reasons.length) {
    return {
      status: "incompatible",
      baselineKey: baseline.key,
      qualityRegressions: [],
      resourceRegressions: [],
      reasons,
    };
  }
  const tolerance = profile.real ? REAL_QUALITY_TOLERANCE : QUALITY_TOLERANCE;
  const quality = qualityRegressions(baseline.summary, current, tolerance);
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
  if (parsed.key !== baselineKey(parsed.identity, runsOf(parsed))) {
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
