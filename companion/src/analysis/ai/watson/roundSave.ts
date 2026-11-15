import { revalidatePromotion } from "./roundPromote.js";
import { commitCheck } from "./roundCancel.js";
import {
  NO_SPEND,
  spendDelta,
  WatsonCancelled,
  watsonSpend,
  type WatsonRoundContext,
  type WatsonSpend,
} from "./roundContext.js";
import { mergeOutcome, type Outcome } from "./roundOutcome.js";
import { reactionFailed, withReactionResult } from "./reactionState.js";
import type { WatsonChat } from "./types.js";

// The final save of a Watson round (moved out of round.ts): every exit charges the round and leaves
// a turn, a reply or an error.
//
// The commit point. The last stop check runs inside the chat update, right before the merge, so the
// window between the check and the save is one synchronous step. A stop that lands after the check
// is too late: the round is saved as answered. `stoppedAfterCommit` marks both late cases (after the
// promotion started, and after this check), so the route (Task 6) does not infer it.

export interface RoundSaveInput {
  turnId: string;
  reaction: boolean;
  before: WatsonSpend | null;
  calls: number;
}

/** The saved chat and the outcome as saved (a stop before the commit point cancels it). */
export interface RoundSaved {
  saved: WatsonChat;
  outcome: Outcome;
}

export async function saveRound(
  ctx: WatsonRoundContext,
  caseId: string,
  outcome: Outcome,
  i: RoundSaveInput,
): Promise<RoundSaved> {
  const after = await watsonSpend(ctx, caseId).catch(() => null);
  const spent = i.before && after ? spendDelta(i.before, after) : NO_SPEND;
  let final = outcome;
  const saved = await ctx.chatStore.update(caseId, (fresh) => {
    final = commitCheck(ctx, outcome);
    // D9b: an undo of the promotion while the round ran drops what rested on it before it is added.
    const checked = revalidatePromotion(fresh, final);
    const merged = mergeOutcome(fresh, { ...checked, turnId: i.turnId }, spent, i.calls);
    // A stopped reaction neither counts as a failure nor resets the count.
    if (!i.reaction || final.error instanceof WatsonCancelled) return merged;
    return withReactionResult(merged, reactionFailed(final.reply, final.error));
  });
  const late = ctx.signal?.aborted === true && !(final.error instanceof WatsonCancelled);
  return { saved, outcome: late ? { ...final, stoppedAfterCommit: true } : final };
}

/** Logs how a round ended badly: an analyst's stop at info, any other failure at warn. */
export function logRoundEnd(ctx: WatsonRoundContext, caseId: string, failure: unknown): void {
  if (!failure) return;
  if (failure instanceof WatsonCancelled) {
    ctx.log?.info("Watson round stopped by an analyst", { caseId });
    return;
  }
  const msg = failure instanceof Error ? failure.message : String(failure);
  ctx.log?.warn(`Watson round failed: ${msg}`, { caseId });
}
