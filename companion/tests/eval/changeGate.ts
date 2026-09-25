import { createHash } from "node:crypto";
import { z } from "zod";
import { MIN_ATTESTED_RUNS } from "./baseline.js";
import { baseCaseId } from "./report.js";

const PROMPT_CONSTANTS = [
  "SYSTEM_PROMPT",
  "CSV_SYSTEM_PROMPT",
  "LOG_SYSTEM_PROMPT",
  "SYNTHESIS_PROMPT",
] as const;

/**
 * Where the four hashed prompts live, relative to the repository root (#384).
 *
 * They moved out of pipeline.ts into src/analysis/ai/prompts/. The text is byte-identical, so the
 * hash this file computes is unchanged by the move -- which is the point: a refactor that does not
 * touch a prompt must not demand a fresh no-regression attestation.
 *
 * The legacy path is still consulted, because baseSourceHash() reads the MERGE BASE, and on any
 * revision from before the move the prompts are still in pipeline.ts. Without the fallback the gate
 * would compare a new-layout hash against nothing and report a spurious prompt change on every PR
 * until the move lands on master.
 */
export const PROMPT_SOURCE_FILES = [
  "companion/src/analysis/ai/prompts/extraction.ts",
  "companion/src/analysis/ai/prompts/synthesis.ts",
];
export const LEGACY_PROMPT_SOURCE_FILE = "companion/src/analysis/pipeline.ts";

/** Assemble the prompt source from whichever layout `read` can satisfy. */
export async function collectPromptSource(read: (path: string) => Promise<string>): Promise<string> {
  try {
    return (await Promise.all(PROMPT_SOURCE_FILES.map((f) => read(f)))).join("\n");
  } catch {
    return read(LEGACY_PROMPT_SOURCE_FILE);
  }
}

const ACTIVE_MODEL_LINE = /^(DFIR_(?:VISION_(?:PROVIDER|MODEL)|AI_SYNTH_(?:PROVIDER|MODEL)))=(.*)$/;

export interface NoRegressionAttestation {
  schemaVersion: 2;
  sourceHash: string;
  /** How many times the attested report ran each section (#1579). Copied from report.runs. */
  runs: number;
  status: "passed" | "failed";
  reportPath: string;
  reportSha256: string;
  baselineKey: string;
  evaluatedAt: string;
}

export const noRegressionAttestationSchema: z.ZodType<NoRegressionAttestation> = z
  .object({
    schemaVersion: z.literal(2),
    sourceHash: z.string().regex(/^[a-f0-9]{64}$/),
    runs: z.number().int().min(1),
    status: z.enum(["passed", "failed"]),
    reportPath: z.string().min(1),
    reportSha256: z.string().regex(/^[a-f0-9]{64}$/),
    baselineKey: z.string().min(1),
    evaluatedAt: z.string().datetime(),
  })
  .strict();

export interface ChangeGateAssessment {
  status: "not-required" | "missing" | "stale" | "failed" | "passed";
  message: string;
}

function extractConstant(source: string, name: string): string {
  const marker = `export const ${name} =`;
  const endMarker = `].join("\\n");`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`evaluation prompt constant not found: ${name}`);
  const end = source.indexOf(endMarker, start + marker.length);
  if (end < 0) throw new Error(`evaluation prompt constant has no join terminator: ${name}`);
  return source.slice(start, end + endMarker.length).trim();
}

function activeModelDefaults(envExample: string): string[] {
  return envExample
    .split(/\r?\n/)
    .map((line) => line.trim())
    .flatMap((line) => {
      const match = ACTIVE_MODEL_LINE.exec(line);
      return match ? [`${match[1]}=${match[2].trim()}`] : [];
    })
    .sort();
}

/**
 * True when an input to the screenshot (vision) path changed: the SYSTEM_PROMPT constant, or a
 * hashed DFIR_VISION_* default line in .env.example (#1579 item 2). A change here is only proven
 * safe by a report that actually ran real screenshots.
 */
export function visionInputsChanged(
  basePromptSource: string,
  baseEnv: string,
  currentPromptSource: string,
  currentEnv: string,
): boolean {
  if (
    extractConstant(basePromptSource, "SYSTEM_PROMPT") !==
    extractConstant(currentPromptSource, "SYSTEM_PROMPT")
  ) {
    return true;
  }
  const visionLines = (env: string): string =>
    activeModelDefaults(env)
      .filter((line) => line.startsWith("DFIR_VISION_"))
      .join("\n");
  return visionLines(baseEnv) !== visionLines(currentEnv);
}

export function evaluationSourceHash(promptSource: string, envExample: string): string {
  const evaluatedSource = {
    prompts: Object.fromEntries(PROMPT_CONSTANTS.map((name) => [name, extractConstant(promptSource, name)])),
    models: activeModelDefaults(envExample),
  };
  return createHash("sha256").update(JSON.stringify(evaluatedSource)).digest("hex");
}

export function assessNoRegressionGate(
  baseSourceHash: string,
  currentSourceHash: string,
  attestation: NoRegressionAttestation | undefined,
): ChangeGateAssessment {
  if (baseSourceHash === currentSourceHash) {
    return {
      status: "not-required",
      message: "default evaluation prompts and models are unchanged",
    };
  }
  if (!attestation) {
    return {
      status: "missing",
      message: "default prompts/models changed without a no-regression attestation",
    };
  }
  if (attestation.sourceHash !== currentSourceHash) {
    return {
      status: "stale",
      message: "no-regression attestation does not match the current defaults",
    };
  }
  if (attestation.status !== "passed") {
    return {
      status: "failed",
      message: "the matching no-regression report did not pass",
    };
  }
  return {
    status: "passed",
    message: "matching no-regression attestation found",
  };
}

/** The parts of an attested report that prove it is a full, real, multi-run evaluation (#1579). */
export interface AttestedReportShape {
  real?: boolean;
  mode?: string;
  runs?: number;
  identity?: { provider?: string };
  expected?: { cases: number; extraction: number; screenshot: number };
  cases: readonly AttestedRow[];
  extraction: readonly AttestedRow[];
  screenshot: readonly AttestedRow[];
}

/** The two row fields the completeness check reads; everything else a row carries is ignored. */
export interface AttestedRow {
  id?: string;
  runIndex?: number;
}

const attestedRowSchema: z.ZodType<AttestedRow> = z
  .object({ id: z.string().optional(), runIndex: z.number().int().min(1).optional() })
  .passthrough();

export const attestedReportShapeSchema: z.ZodType<AttestedReportShape> = z.object({
  real: z.boolean().optional(),
  mode: z.string().optional(),
  runs: z.number().int().min(1).optional(),
  expected: z
    .object({
      cases: z.number().int().min(1),
      extraction: z.number().int().min(1),
      screenshot: z.number().int().min(0),
    })
    .optional(),
  identity: z.object({ provider: z.string().optional() }).passthrough().optional(),
  cases: z.array(attestedRowSchema),
  extraction: z.array(attestedRowSchema),
  screenshot: z.array(attestedRowSchema),
});

export const VISION_SCREENSHOT_REQUIRED =
  "a SYSTEM_PROMPT or vision-model change needs a real screenshot set (#1579 item 2)";

/**
 * Every reason the attested report cannot stand as a no-regression proof. Empty means it can.
 * Pure, so the gate's policy is unit-testable without git or the filesystem.
 */
export function verifyAttestedReportShape(
  report: AttestedReportShape,
  attestation: Pick<NoRegressionAttestation, "runs">,
  options: { visionChanged: boolean },
): string[] {
  const errors: string[] = [];
  if (report.real !== true) errors.push("the attested report must be a real (--real) run");
  if (report.mode !== "all")
    errors.push(`the attested report must run every section (mode "all"), not "${report.mode ?? "unset"}"`);
  const runs = report.runs ?? 1;
  if (runs < MIN_ATTESTED_RUNS)
    errors.push(`the attested report must have at least ${MIN_ATTESTED_RUNS} runs, not ${runs}`);
  if (runs !== attestation.runs)
    errors.push(`the report ran ${runs} times but its attestation records ${attestation.runs}`);
  if ((report.identity?.provider ?? "mock") === "mock")
    errors.push("the attested report was produced by the mock provider, not a real model");
  if (!report.expected) {
    errors.push("the attested report has no expected row counts");
  } else {
    errors.push(...rowCompleteness("case", report.cases, report.expected.cases, runs));
    errors.push(...rowCompleteness("extraction", report.extraction, report.expected.extraction, runs));
    // Every screenshot the report says it ran must be there for every run — a partial set could
    // otherwise attest the vision path on whichever screenshots happened to load.
    errors.push(...rowCompleteness("screenshot", report.screenshot, report.expected.screenshot, runs));
  }
  const screenshotsPerRun = report.expected?.screenshot ?? 0;
  if (options.visionChanged && (report.screenshot.length === 0 || screenshotsPerRun === 0))
    errors.push(VISION_SCREENSHOT_REQUIRED);
  return errors;
}

/**
 * Every fixture exactly once in every run (#1579 review). A total row count alone lets one run be
 * short and another doubled — 2, 1, 3 adds up to 3 × 2 — and the per-fixture mean would then rest
 * on however many samples each fixture happened to get.
 */
function rowCompleteness(
  section: string,
  rows: readonly AttestedRow[],
  perRun: number,
  runs: number,
): string[] {
  const errors: string[] = [];
  if (rows.length !== perRun * runs)
    errors.push(`expected ${perRun * runs} ${section} rows, found ${rows.length}`);
  const seen = new Map<string, Set<number>>();
  for (const row of rows) {
    const base = baseCaseId(row.id ?? "");
    const run = row.runIndex ?? 1;
    const runsSeen = seen.get(base) ?? new Set<number>();
    if (runsSeen.has(run)) errors.push(`${section} "${base}" appears twice in run ${run}`);
    runsSeen.add(run);
    seen.set(base, runsSeen);
  }
  if (seen.size !== perRun)
    errors.push(`expected ${perRun} distinct ${section} fixtures, found ${seen.size}`);
  for (const [base, runsSeen] of seen) {
    for (let run = 1; run <= runs; run++)
      if (!runsSeen.has(run)) errors.push(`${section} "${base}" is missing from run ${run}`);
  }
  return errors;
}
