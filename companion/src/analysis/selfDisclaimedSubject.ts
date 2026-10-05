// Self-disclaimed subject (#1944). A finding whose own text says its subject is not in the evidence,
// and that guesses at it ("probably", "likely", "may have"), is an open question, not a finding. A
// lab run produced a High "card skimmer probably planted in the payment pages" whose description
// said "the modified pages are not in the evidence"; the drop had failed and nothing changed.
// findingGrounding.ts floors such a finding to Medium. This module only reads the text.
//
// Both conditions are required. A disclaimer alone is often honest scoping on a real finding:
// "Security log cleared (EID 1102); the cleared records are not in the evidence" — the clear is
// present, only the lost records are not. The guessing word is what marks the subject as inferred.
//
// Two exclusions keep an evidenced action at its severity (Codex review of #1944): a disclaimer whose
// sentence is about deleted/cleared/overwritten material is collateral to that action, not the
// subject; and a guess about motive ("likely to conceal activity") does not make the action itself
// inferred. Either exclusion alone keeps the severity, so the gate errs toward not capping.

import type { Severity } from "./stateTypes.js";

export const SELF_DISCLAIMED_SEVERITY_FLOOR: Severity = "Medium";

const DISCLAIMER_RES: readonly RegExp[] = [
  /\bnot\s+(?:present\s+|included\s+|captured\s+|visible\s+|available\s+)?in\s+the\s+(?:provided\s+|available\s+|collected\s+)?(?:evidence|collection|data)\b/i,
  /\babsent\s+from\s+the\s+(?:evidence|collection)\b/i,
  /\bnot\s+(?:been\s+)?(?:collected|captured|acquired)\b/i,
];

// `\b` keeps "unlikely" from reading as "likely".
const GUESS_RE =
  /\b(?:probably|likely|possibly|may\s+have|might\s+have|could\s+have|suspected|presumably)\b/gi;

// A guess followed by a purpose clause speculates about motive, not about whether the act happened.
const MOTIVE_AFTER_GUESS_RE =
  /^\s*(?:done\s+|an?\s+attempt\s+|in\s+an\s+attempt\s+)?(?:to|for|in\s+order\s+to|so\s+as\s+to|because)\b/i;

// Material an evidenced action destroyed. Its absence is the expected result of that action.
const COLLATERAL_RE = /\b(?:deleted|cleared|overwritten|removed|wiped|purged|erased|shredded|truncated)\b/i;

const SENTENCE_SPLIT_RE = /(?<=[.!?])\s+|\n+/;

function hasSubjectGuess(text: string): boolean {
  for (const m of text.matchAll(GUESS_RE)) {
    const after = text.slice((m.index ?? 0) + m[0].length);
    if (!MOTIVE_AFTER_GUESS_RE.test(after)) return true;
  }
  return false;
}

function subjectDisclaimer(sentence: string): string | null {
  if (COLLATERAL_RE.test(sentence)) return null;
  for (const re of DISCLAIMER_RES) {
    const m = re.exec(sentence);
    if (m) return m[0];
  }
  return null;
}

/** The disclaimer phrase when the text both disclaims its subject and guesses at it, else null. */
export function selfDisclaimedPhrase(text: string): string | null {
  if (!hasSubjectGuess(text)) return null;
  for (const sentence of text.split(SENTENCE_SPLIT_RE)) {
    const phrase = subjectDisclaimer(sentence);
    if (phrase) return phrase;
  }
  return null;
}
