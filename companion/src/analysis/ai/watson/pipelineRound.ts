import type { AIProvider } from "../../../providers/provider.js";
import type { CaseStore } from "../../../storage/caseStore.js";
import type { AiCallContext } from "../aiContext.js";
import type { PipelineOptions } from "../pipelineOptions.js";
import type { WatsonChatStore } from "./chatStore.js";
import { runWatsonRound, type WatsonRoundInput } from "./round.js";
import type { WatsonChat } from "./types.js";

export type { WatsonRoundInput } from "./round.js";

/** What the route knows that the pipeline does not: the shared chat store, the model and the limits. */
export interface WatsonRoundDeps {
  chatStore: WatsonChatStore;
  cases: CaseStore;
  provider: AIProvider;
  isAiEnabled(caseId: string): Promise<boolean>;
  costLimitUSD?: number;
  tokenLimit?: number;
  onStateChanged?(caseId: string): void;
}

/** The arguments of AnalysisPipeline.watsonRound. */
export type WatsonRoundArgs = [caseId: string, input: WatsonRoundInput, deps: WatsonRoundDeps];

/**
 * Run one Watson round on the pipeline's own seams: its AI-call context (anonymizer, Presidio,
 * retry, cost), its state store, and — so the standard-question seed serializes with synthesis — its
 * own state lock instance.
 */
export function runPipelineWatsonRound(
  aiCtx: AiCallContext,
  opts: PipelineOptions,
  caseId: string,
  input: WatsonRoundInput,
  deps: WatsonRoundDeps,
): Promise<WatsonChat> {
  if (!opts.stateLock || !opts.aiCostStore) {
    return Promise.reject(new Error("Watson needs the pipeline's state lock and AI cost store"));
  }
  return runWatsonRound(
    {
      ...aiCtx,
      ...deps,
      stateStore: opts.stateStore,
      stateLock: opts.stateLock,
      costStore: opts.aiCostStore,
      mainSourceStore: opts.mainSourceStore,
      assetOverridesStore: opts.assetOverridesStore,
      velociraptorClientStore: opts.velociraptorClientStore,
    },
    caseId,
    input,
  );
}
