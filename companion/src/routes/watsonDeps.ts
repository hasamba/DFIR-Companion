import type { WatsonRoundDeps } from "../analysis/ai/watson/pipelineRound.js";
import type { RouteContext } from "./context.js";

/** A positive finite number from a setting, else undefined: blank, junk, zero and negatives mean "no limit". */
export function positiveLimit(raw: string | undefined): number | undefined {
  const text = raw?.trim();
  const n = Number(text);
  return text && Number.isFinite(n) && n > 0 ? n : undefined;
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
  return {
    chatStore: options.watsonChatStore,
    cases: store,
    provider,
    isAiEnabled: async (id) => (await ctx.getControl(id)).enabled,
    costLimitUSD: positiveLimit(process.env.DFIR_AI_WATSON_COST_LIMIT_USD),
    tokenLimit: positiveLimit(process.env.DFIR_AI_WATSON_TOKEN_LIMIT),
    onStateChanged: options.onStateChanged,
  };
}
