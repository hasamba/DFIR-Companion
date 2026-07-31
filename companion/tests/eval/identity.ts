import { readFile } from "node:fs/promises";
import { hashManifestValue } from "../../src/analysis/analysisRunHash.js";
import {
  getCsvPrompt,
  getLogPrompt,
  getSynthesisPrompt,
  getSystemPrompt,
} from "../../src/analysis/pipeline.js";
import type { AIProvider } from "../../src/providers/provider.js";
import type { EvaluationIdentity } from "./baseline.js";
import { evaluationSourceHash } from "./changeGate.js";

export function evaluationPromptHash(): string {
  return hashManifestValue({
    system: getSystemPrompt(),
    csv: getCsvPrompt(),
    log: getLogPrompt(),
    synthesis: getSynthesisPrompt(),
  });
}

export async function currentEvaluationSourceHash(): Promise<string> {
  const [pipelineSource, envExample] = await Promise.all([
    readFile(new URL("../../src/analysis/pipeline.ts", import.meta.url), "utf8"),
    readFile(new URL("../../.env.example", import.meta.url), "utf8"),
  ]);
  return evaluationSourceHash(pipelineSource, envExample);
}

export async function evaluationIdentity(
  provider: Pick<AIProvider, "name" | "model">,
  corpusHash: string,
): Promise<EvaluationIdentity> {
  return {
    provider: provider.name,
    model: provider.model,
    promptHash: evaluationPromptHash(),
    sourceHash: await currentEvaluationSourceHash(),
    corpusHash,
  };
}
