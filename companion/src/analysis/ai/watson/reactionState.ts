import { PresidioApprovalRequired } from "../../presidio.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { WATSON_CASE_EVENTS_MAX } from "./promptBuilder.js";
import { WatsonCancelled, WatsonCostLimitReached, WatsonRoundTimedOut } from "./roundContext.js";
import { newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonReactionsPaused, WatsonTurn } from "./types.js";

// The chat state automatic reactions keep (spec §4.6): the turn a reaction records, whether the
// analyst ever used Watson on the case, and when reactions pause.

/** Consecutive failed reaction rounds (not a Presidio hold or a limit) that pause reactions. */
export const WATSON_REACTION_FAILURES_MAX = 2;

/** The ANALYST block of a reaction round: the events themselves are in CASE CHANGES. */
export const WATSON_REACTION_PROMPT =
  "(No analyst message. The case changed: see CASE CHANGES SINCE LAST ROUND. Say briefly what the change means for the investigation.)";

const ERRORS_PAUSE_TEXT =
  "Watson stopped its automatic reactions because of many errors. Send a message to start them again.";

/** The turn that stands in for the analyst's message on a reaction round. */
export function reactionTurn(chat: WatsonChat): WatsonTurn {
  const texts = [...new Set(chat.pendingCaseEvents.slice(0, WATSON_CASE_EVENTS_MAX).map((e) => e.text))];
  return {
    id: newWatsonId("wt"),
    at: new Date().toISOString(),
    role: "system",
    text: `Watson reacted to: ${texts.join("; ")}`.slice(0, WATSON_TURN_TEXT_MAX),
  };
}

/**
 * The chat after an analyst message: Watson is in use here, any reactions pause is lifted, and the
 * Auto chain count and any Stop chain clear (autoChain.ts). The chain limit stays.
 */
export function engaged(chat: WatsonChat): WatsonChat {
  const {
    reactionsPaused: _paused,
    reactionFailures: _failures,
    autoChainLaunches: _chain,
    autoChainStopped: _stopped,
    autoIdleRounds: _idle,
    autoSearchesRun: _searches,
    autoSetAside: _aside,
    autoIdleFocus: _idleFocus,
    ...rest
  } = chat;
  return { ...rest, analystEngaged: true };
}

/** The chat with reactions paused and one system turn saying so. */
export function pausedReactions(chat: WatsonChat, why: WatsonReactionsPaused, text: string): WatsonChat {
  const turn: WatsonTurn = { id: newWatsonId("wt"), at: new Date().toISOString(), role: "system", text };
  return { ...chat, reactionsPaused: why, turns: [...chat.turns, turn] };
}

/**
 * A reaction that failed for a reason other than a Presidio hold or a limit (both pause at once). An
 * analyst's stop is no failure either.
 */
export function reactionFailed(reply: unknown, error: unknown): boolean {
  if (reply) return false;
  // A round that ran out of time is a failure (#2639): repeated hangs pause the reactions.
  if (error instanceof WatsonRoundTimedOut) return true;
  return !(
    error instanceof PresidioApprovalRequired ||
    error instanceof WatsonCostLimitReached ||
    error instanceof WatsonCancelled
  );
}

/** Count a reaction's result: a success resets the count, the Nth failure in a row pauses reactions. */
export function withReactionResult(chat: WatsonChat, failed: boolean): WatsonChat {
  if (!failed) {
    const { reactionFailures: _failures, ...rest } = chat;
    return rest;
  }
  const failures = (chat.reactionFailures ?? 0) + 1;
  const counted = { ...chat, reactionFailures: failures };
  if (failures < WATSON_REACTION_FAILURES_MAX || chat.reactionsPaused) return counted;
  return pausedReactions(counted, "errors", ERRORS_PAUSE_TEXT);
}
