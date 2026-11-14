import type { WatsonRoundDeps } from "../analysis/ai/watson/pipelineRound.js";
import { matchClient } from "../integrations/velociraptor/clientInventory.js";
import { blockMd } from "../reports/mdText.js";
import type { WatsonAutoDeps } from "../analysis/ai/watson/autoApply.js";
import type { WriterDeps } from "../analysis/ai/watson/proposals.js";
import type { RouteContext } from "./context.js";
import { caseVeloConnected, watsonVeloLaunchDeps } from "./watsonVeloLaunch.js";
import { isFrozenCase } from "./importCaseGuard.js";

/** A positive finite number from a setting, else undefined: blank, junk, zero and negatives mean "no limit". */
export function positiveLimit(raw: string | undefined): number | undefined {
  const text = raw?.trim();
  const n = Number(text);
  return text && Number.isFinite(n) && n > 0 ? n : undefined;
}

export { caseVeloConnected };

type Pipeline = NonNullable<RouteContext["options"]["pipeline"]>;
const promoteVia =
  (pipeline: Pipeline): NonNullable<WriterDeps["promoteEvents"]> =>
  (caseId, events, opts) =>
    pipeline.promoteSuperTimelineWithOutcome(caseId, events, opts);

/**
 * What applying a Watson proposal needs — an analyst's click and Auto mode alike, so both launch
 * through the same Velociraptor seam. Undefined when not wired.
 */
export function watsonProposalDeps(ctx: RouteContext): WriterDeps | undefined {
  const { options, store } = ctx;
  if (!options.watsonChatStore || !options.stateStore || !options.stateLock || !options.activityLogStore) {
    return undefined;
  }
  return {
    stateStore: options.stateStore,
    stateLock: options.stateLock,
    chatStore: options.watsonChatStore,
    activity: options.activityLogStore,
    cases: store,
    markConclusionsOutOfDate: ctx.markConclusionsOutOfDate,
    reportText: options.reportMetaStore,
    ...(options.pipeline ? { promoteEvents: promoteVia(options.pipeline) } : {}),
    veloLaunch: watsonVeloLaunchDeps(ctx),
  };
}

/** Auto mode's seams for a round; undefined when proposals cannot be applied on this server. */
function watsonAutoDeps(ctx: RouteContext): WatsonAutoDeps | undefined {
  const writer = watsonProposalDeps(ctx);
  if (!writer) return undefined;
  return {
    // A case closed or archived mid-round stops Auto like a switch to Approve (final review G4).
    control: async (id) => ({ ...(await ctx.getControl(id)), frozen: await isFrozenCase(ctx.store, id) }),
    writer,
    onStateChanged: (id) => ctx.options.onStateChanged?.(id),
  };
}

/**
 * What a Watson round needs from the server: the shared chat store, the model and the limits. Read per
 * call so a Settings change applies at once. One builder for every caller — the Watson routes, the
 * `/dfir ask` slash command and the AI preview — so each runs the round on the same terms.
 * Undefined when Watson has no chat store or no model.
 */
export function watsonRoundDeps(ctx: RouteContext): WatsonRoundDeps | undefined {
  const { options, store } = ctx;
  const provider = options.watsonProvider?.();
  if (!options.watsonChatStore || !provider) return undefined;
  const auto = watsonAutoDeps(ctx);
  return {
    chatStore: options.watsonChatStore,
    cases: store,
    provider,
    isAiEnabled: async (id) => (await ctx.getControl(id)).enabled,
    costLimitUSD: positiveLimit(process.env.DFIR_AI_WATSON_COST_LIMIT_USD),
    tokenLimit: positiveLimit(process.env.DFIR_AI_WATSON_TOKEN_LIMIT),
    reportText: options.reportMetaStore,
    reportBlockText: blockMd,
    onStateChanged: options.onStateChanged,
    veloConnected: (id) => caseVeloConnected(ctx, id),
    matchClient,
    ...(auto ? { auto } : {}),
  };
}
