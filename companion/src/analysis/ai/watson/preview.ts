import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import type { WatsonReply } from "./replySchema.js";
import {
  callWatson,
  choosePaste,
  headExcerpt,
  watsonBaseInput,
  withStandardQuestions,
} from "./requestBuild.js";
import {
  limitReached,
  WatsonAiOff,
  WatsonCostLimitReached,
  type WatsonRoundContext,
} from "./roundContext.js";

/**
 * "Preview what the AI will see" for a Watson message (#2491): the first request a round would send
 * for `draft`, built by the round's own request code (requestBuild.ts) and sent to the same
 * callAiJson call, which the AI preview stops at its gate — so masking, Presidio and the prompt
 * entities are exactly the real call's.
 *
 * Unlike a round it saves nothing: no analyst turn, no reply, no paste marked read, and the standard
 * questions a first round seeds are added to the prompt's state in memory only. The checks a round
 * makes before its first call (the case's AI switch, the cost and token limits) still apply, so the
 * preview stops where the real press would.
 */
export async function previewWatsonRound(
  ctx: WatsonRoundContext,
  caseId: string,
  draft: string,
): Promise<WatsonReply> {
  if (!(await ctx.isAiEnabled(caseId))) throw new WatsonAiOff();
  const chat = await ctx.chatStore.load(caseId);
  const reached = limitReached(ctx, { usd: chat.costUSD, tokens: chat.tokens });
  if (reached) throw new WatsonCostLimitReached(reached);
  const { newPaste } = choosePaste(chat, undefined);
  const state = withStandardQuestions(await ctx.stateStore.load(caseId));
  const { base } = await watsonBaseInput(ctx, caseId, state, chat, draft.slice(0, WATSON_TURN_TEXT_MAX));
  // A paste whose stored file cannot be read is left out, as the round leaves it out.
  const excerpt = newPaste ? await headExcerpt(ctx, caseId, newPaste).catch(() => undefined) : undefined;
  const one: WatsonRoundContext = { ...ctx, opts: { ...ctx.opts, retries: 0 } };
  return callWatson(one, caseId, state, ctx.provider, excerpt ? { ...base, pasteExcerpt: excerpt } : base);
}
