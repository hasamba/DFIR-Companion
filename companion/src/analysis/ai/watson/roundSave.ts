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
import { newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonTurn } from "./types.js";

// The final save of a Watson round (moved out of round.ts): every exit charges the round and leaves
// a turn, a reply or an error.
//
// The commit point. The last stop check runs inside the chat update, right before the merge, so the
// window between the check and the save is one synchronous step. A stop that lands after the check
// is too late: the round is saved as answered. `stoppedAfterCommit` marks both late cases (after the
// promotion started, and after this check), so the route (Task 6) does not infer it.

/** The note a round gets when an analyst's stop came after its commit point (final review F7). */
export const WATSON_STOPPED_LATE_TEXT = "Watson finished this answer before the stop.";

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
  if (!late) return { saved, outcome: final };
  return {
    saved: await withLateStopNote(ctx, caseId, saved),
    outcome: { ...final, stoppedAfterCommit: true },
  };
}

/** Adds the late-stop note to the chat. The answer is already saved, so a failed note is only logged. */
async function withLateStopNote(
  ctx: WatsonRoundContext,
  caseId: string,
  saved: WatsonChat,
): Promise<WatsonChat> {
  const note: WatsonTurn = {
    id: newWatsonId("wt"),
    at: new Date().toISOString(),
    role: "system",
    text: WATSON_STOPPED_LATE_TEXT,
  };
  try {
    return await ctx.chatStore.update(caseId, (c) => ({ ...c, turns: [...c.turns, note] }));
  } catch (err) {
    ctx.log?.warn(
      `Watson could not save the late-stop note: ${err instanceof Error ? err.message : String(err)}`,
      { caseId },
    );
    return saved;
  }
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
