import { createHash } from "node:crypto";
import { z } from "zod";

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
  schemaVersion: 1;
  sourceHash: string;
  status: "passed" | "failed";
  reportPath: string;
  reportSha256: string;
  baselineKey: string;
  evaluatedAt: string;
}

export const noRegressionAttestationSchema: z.ZodType<NoRegressionAttestation> = z
  .object({
    schemaVersion: z.literal(1),
    sourceHash: z.string().regex(/^[a-f0-9]{64}$/),
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
