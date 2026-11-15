import { WatsonCancelled } from "./roundContext.js";
import type { Outcome } from "./roundOutcome.js";

// An analyst's Stop on a running round (runRegistry.ts). The irreversible point of a round is its
// first promotion write: before it, a stop drops the reply and every proposal input; after it, the
// settled reply is saved as is (its proposals stay pending) and nothing more is launched or applied.

/** The stop that applies now: the signal's WatsonCancelled reason, a new one when aborted, else null. */
export function cancelReason(signal: AbortSignal | undefined): WatsonCancelled | null {
  if (!signal?.aborted) return null;
  return signal.reason instanceof WatsonCancelled ? signal.reason : new WatsonCancelled();
}

/** The outcome of a stopped round: no reply and no proposal input; cost, roster and lookups stay. */
export function cancelledOutcome(o: Outcome, err: WatsonCancelled): Outcome {
  const {
    rawEvidence: _raw,
    writeInputs: _writes,
    veloProposal: _velo,
    veloNote: _veloNote,
    note: _note,
    ...rest
  } = o;
  return { ...rest, reply: null, error: err, superShown: [] };
}

/** The commit-phase check: a stop before promotion started cancels the outcome; after, it stays. */
export function commitCheck(ctx: { signal?: AbortSignal }, outcome: Outcome): Outcome {
  const stop = cancelReason(ctx.signal);
  return stop && !outcome.promotion ? cancelledOutcome(outcome, stop) : outcome;
}
