// Self-disclaimed subject (#1944). A finding whose own text says its subject is not in the evidence,
// and that guesses at it ("probably", "likely", "may have"), is an open question, not a finding. A
// lab run produced a High "card skimmer probably planted in the payment pages" whose description
// said "the modified pages are not in the evidence"; the drop had failed and nothing changed.
// findingGrounding.ts floors such a finding to Medium. This module only reads the text.
//
// Both conditions are required. A disclaimer alone is often honest scoping on a real finding:
// "Security log cleared (EID 1102); the cleared records are not in the evidence" — the clear is
// present, only the lost records are not. The guessing word is what marks the subject as inferred.

import type { Severity } from "./stateTypes.js";

export const SELF_DISCLAIMED_SEVERITY_FLOOR: Severity = "Medium";

const DISCLAIMER_RES: readonly RegExp[] = [
  /\bnot\s+(?:present\s+|included\s+|captured\s+|visible\s+|available\s+)?in\s+the\s+(?:provided\s+|available\s+|collected\s+)?(?:evidence|collection|data)\b/i,
  /\babsent\s+from\s+the\s+(?:evidence|collection)\b/i,
  /\bnot\s+(?:been\s+)?(?:collected|captured|acquired)\b/i,
];

// `\b` keeps "unlikely" from reading as "likely".
const GUESS_RE =
  /\b(?:probably|likely|possibly|may\s+have|might\s+have|could\s+have|suspected|presumably)\b/i;

/** The disclaimer phrase when the text both disclaims its subject and guesses at it, else null. */
export function selfDisclaimedPhrase(text: string): string | null {
  if (!GUESS_RE.test(text)) return null;
  for (const re of DISCLAIMER_RES) {
    const m = re.exec(text);
    if (m) return m[0];
  }
  return null;
}
