import type { AIProvider } from "../../../providers/provider.js";
import type { CaseStore } from "../../../storage/caseStore.js";
import type { AiCallContext } from "../aiContext.js";
import type { PipelineOptions } from "../pipelineOptions.js";
import type { WatsonChatStore } from "./chatStore.js";
import { previewWatsonRound } from "./preview.js";
import type { WatsonReply } from "./replySchema.js";
import type { WatsonReportText } from "./writers/writerTypes.js";
import { runWatsonRound, type WatsonRoundContext, type WatsonRoundInput } from "./round.js";
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
  /** The report details (ReportMetaStore), for report-text proposals. */
  reportText?: WatsonReportText;
  /** Report text made safe for report.md (the route injects reports' blockMd). Absent: none proposed. */
  reportBlockText?(text: string): string;
  onStateChanged?(caseId: string): void;
}

/** The arguments of AnalysisPipeline.watsonRound. */
export type WatsonRoundArgs = [caseId: string, input: WatsonRoundInput, deps: WatsonRoundDeps];

/** The arguments of AnalysisPipeline.watsonPreview. */
export type WatsonPreviewArgs = [caseId: string, draft: string, deps: WatsonRoundDeps];

/**
 * A Watson round's context on the pipeline's own seams: its AI-call context (anonymizer, Presidio,
 * retry, cost), its state store, and — so the standard-question seed serializes with synthesis — its
 * own state lock instance.
 */
function pipelineWatsonContext(aiCtx: AiCallContext, opts: PipelineOptions, deps: WatsonRoundDeps) {
  if (!opts.stateLock || !opts.aiCostStore) {
    throw new Error("Watson needs the pipeline's state lock and AI cost store");
  }
  const ctx: WatsonRoundContext = {
    ...aiCtx,
    ...deps,
    stateStore: opts.stateStore,
    stateLock: opts.stateLock,
    costStore: opts.aiCostStore,
    mainSourceStore: opts.mainSourceStore,
    assetOverridesStore: opts.assetOverridesStore,
    velociraptorClientStore: opts.velociraptorClientStore,
  };
  return ctx;
}

/** Run one Watson round on the pipeline's seams. */
export async function runPipelineWatsonRound(
  aiCtx: AiCallContext,
  opts: PipelineOptions,
  caseId: string,
  input: WatsonRoundInput,
  deps: WatsonRoundDeps,
): Promise<WatsonChat> {
  return runWatsonRound(pipelineWatsonContext(aiCtx, opts, deps), caseId, input);
}

/** The first request a round would send for `draft`, for the AI preview (preview.ts); saves nothing. */
export async function previewPipelineWatsonRound(
  aiCtx: AiCallContext,
  opts: PipelineOptions,
  caseId: string,
  draft: string,
  deps: WatsonRoundDeps,
): Promise<WatsonReply> {
  return previewWatsonRound(pipelineWatsonContext(aiCtx, opts, deps), caseId, draft);
}
