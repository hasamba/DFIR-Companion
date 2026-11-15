import { WatsonCancelled } from "./roundContext.js";
import type { Outcome } from "./roundOutcome.js";

// How a Watson round ended, as routes/watsonMessage.ts replays it for a repeated Idempotency-Key
// (Codex #7). "answered": Watson's turn was saved, so its cost and its promotion are committed. A
// replay must not run them again. "cancelled": an analyst's stop. "failed": nothing was answered,
// so a resend runs a new round.

export type WatsonDisposition = "answered" | "cancelled" | "failed";

/**
 * What the save kept. A saved reply is answered, also when a later hop was held by Presidio (the
 * round then throws the hold after the save) and when a stop landed after the commit point.
 */
export function dispositionOf(outcome: Outcome): WatsonDisposition {
  if (outcome.reply) return "answered";
  return outcome.error instanceof WatsonCancelled ? "cancelled" : "failed";
}

/**
 * Runs a round body and reports its disposition once on every exit. The body reports what its save
 * kept; a throw before that is failed, or cancelled for a stop.
 */
export async function reportedRound<T>(
  onDisposition: ((d: WatsonDisposition) => void) | undefined,
  body: (report: (d: WatsonDisposition) => void) => Promise<T>,
): Promise<T> {
  let disposition: WatsonDisposition | undefined;
  try {
    return await body((d) => (disposition = d));
  } catch (err) {
    disposition ??= err instanceof WatsonCancelled ? "cancelled" : "failed";
    throw err;
  } finally {
    onDisposition?.(disposition ?? "failed");
  }
}
