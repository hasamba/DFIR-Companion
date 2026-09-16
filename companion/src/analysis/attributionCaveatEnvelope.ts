import { ADVERSARY_HINTS_CAVEAT } from "./adversaryHints.js";
import type { AdversaryHint } from "./adversaryTechniques.js";

// The ONLY way adversaryHints.ts's own technique-overlap hints may travel alongside an
// AttributionAssertion on any read surface (#933 item 20) — a typed envelope that structurally
// bundles the "not attribution" caveat with the hints, so "does the caveat travel with the hint"
// is a type-level property to test, not a prose instruction a future UI author has to remember.
// There is no other code path that emits an AdversaryHint[] for this feature.
export interface AdversaryHintsEnvelope {
  hints: AdversaryHint[];
  caveat: typeof ADVERSARY_HINTS_CAVEAT;
}

export function withAdversaryHintsCaveat(hints: AdversaryHint[]): AdversaryHintsEnvelope {
  return { hints, caveat: ADVERSARY_HINTS_CAVEAT };
}
