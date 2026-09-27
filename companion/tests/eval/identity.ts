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
import { collectPromptSource, evaluationSourceHash } from "./changeGate.js";
import { judgeContractHash } from "./forbiddenJudge.js";

export function evaluationPromptHash(): string {
  return hashManifestValue({
    system: getSystemPrompt(),
    csv: getCsvPrompt(),
    log: getLogPrompt(),
    synthesis: getSynthesisPrompt(),
  });
}

export async function currentEvaluationSourceHash(): Promise<string> {
  const repoRoot = new URL("../../../", import.meta.url);
  const [promptSource, envExample] = await Promise.all([
    collectPromptSource((path) => readFile(new URL(path, repoRoot), "utf8")),
    readFile(new URL("../../.env.example", import.meta.url), "utf8"),
  ]);
  return evaluationSourceHash(promptSource, envExample);
}

export async function evaluationIdentity(
  provider: Pick<AIProvider, "name" | "model">,
  corpusHash: string,
  // #1579: pass only when the screenshot section ran against a real vision provider.
  vision?: Pick<AIProvider, "name" | "model">,
  visionSetHash?: string,
  // #1704: pass only when the semantic judge graded synthesis cases on a real run.
  judge?: Pick<AIProvider, "name" | "model">,
): Promise<EvaluationIdentity> {
  return {
    provider: provider.name,
    model: provider.model,
    promptHash: evaluationPromptHash(),
    sourceHash: await currentEvaluationSourceHash(),
    corpusHash,
    ...(vision
      ? {
          vision: {
            provider: vision.name,
            model: vision.model,
            ...(visionSetHash ? { setHash: visionSetHash } : {}),
          },
        }
      : {}),
    ...(judge
      ? { judge: { provider: judge.name, model: judge.model, contractHash: judgeContractHash() } }
      : {}),
  };
}
