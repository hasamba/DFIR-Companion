// What a synthesis says about a safety-filter stop (#1734/#1740), in the three places it is said:
// the Investigation-Log line, the synth-meta record the Findings card and report footnote read, and
// the analysis-run record (#2603). Kept out of synthesis.ts, which sits at its 800-line cap.
import type { SynthFallback } from "../synthMeta.js";
import type { SynthesisCall } from "./synthesisCall.js";

// #1734/#1740: the Investigation-Log note for a synthesis the safety filter stopped at least once.
function safetyLogNote(call: SynthesisCall): string {
  const times = `${call.safetyStops} ${call.safetyStops === 1 ? "time" : "times"}`;
  if (call.fallbackFrom)
    return `written by the fallback model ${call.answeredByLabel} after ${call.fallbackFrom}'s safety filter stopped the answer ${times}`;
  return `${call.primaryLabel}'s safety filter stopped the answer ${times}; it passed on retry`;
}

// #2006: the log-line note — the safety-filter note and/or how many unshown findings were carried.
export function logNoteFor(call: SynthesisCall, carried: number): { logNote?: string } {
  const notes = [
    ...(call.safetyStops > 0 ? [safetyLogNote(call)] : []),
    ...(carried > 0
      ? [`carried ${carried} prior finding${carried === 1 ? "" : "s"} the model was not shown`]
      : []),
  ];
  return notes.length ? { logNote: notes.join(" · ") } : {};
}

/**
 * #2603: the fallback facts for synth-meta and the run record, spread into both. Empty when the
 * synthesis model answered — a retry that passed is not a fallback, and shows no notice.
 */
export function synthFallbackFacts(call: SynthesisCall): { synthFallback?: SynthFallback } {
  if (!call.fallbackFrom) return {};
  return {
    synthFallback: { from: call.fallbackFrom, to: call.answeredByLabel, safetyStops: call.safetyStops },
  };
}
