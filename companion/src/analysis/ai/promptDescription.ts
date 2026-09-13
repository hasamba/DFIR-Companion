// The one description renderer every model-facing event row goes through (#959).
//
// Importers put their discriminators at the END of a long description, because the front is the
// text an adversary chose: the bounded-key digest tail (#955, `…#f0054aafb2f79f6e`), the derived
// note a correlation pass appends after up to 700 base characters (#939). Storage reads the whole
// description — aggregation, correlation's exact-duplicate pass, the import diff and the
// super-timeline content key all see the tail — so two rows that differ only past character 240
// are two rows on disk. A head-only `slice(0, 240)` made them one row to the model, and a raised
// event whose reason sat past the cut reached the model with the severity bump and no reason.
//
// So: a description that fits comes back untouched. One that does not keeps its head AND its tail,
// joined by " … ", inside the same budget as before — and a registered derived note is kept whole,
// never sliced through its middle. Not a prompt constant: the eval change gate hashes only
// prompts/*.ts, so a change here does not require a fresh attestation.

import { splitDerivedNotes } from "../derivedNote.js";

/** The row budget most renderers used before #959 — the synthesis timeline row and its siblings. */
export const PROMPT_DESCRIPTION_MAX = 240;
/** The wider budget explainEvent's focal row and the memory next-steps row used. */
export const PROMPT_DESCRIPTION_WIDE_MAX = 300;
/** Long enough for a 17-char digest tail (`#` + 16 hex) plus the ~20 characters before it. */
export const PROMPT_DESCRIPTION_TAIL = 40;
const ELLIPSIS = " … ";
// The head never shrinks below this, even when long notes squeeze the base budget.
const HEAD_MIN = 40;

/** `head … tail` inside `max` characters; the text itself when it already fits. */
function headAndTail(text: string, max: number): string {
  if (text.length <= max) return text;
  const tail = Math.min(PROMPT_DESCRIPTION_TAIL, Math.max(0, max - HEAD_MIN - ELLIPSIS.length));
  const head = Math.max(HEAD_MIN, max - tail - ELLIPSIS.length);
  return `${text.slice(0, head).trimEnd()}${ELLIPSIS}${text.slice(text.length - tail).trimStart()}`;
}

/**
 * The description as the model reads it: untouched when it fits, otherwise head + " … " + tail in
 * `max` characters, with every registered derived note kept whole after the shortened base.
 */
export function promptDescription(
  description: string | undefined,
  max: number = PROMPT_DESCRIPTION_MAX,
): string {
  const text = description ?? "";
  if (text.length <= max) return text;
  const { base, notes } = splitDerivedNotes(text);
  if (!notes) return headAndTail(text, max);
  // The notes are the reason the event was raised; they get the budget first and the base takes
  // what is left. A run of notes longer than the whole budget is itself head-and-tailed.
  const shownNotes = headAndTail(notes, max);
  const baseBudget = Math.max(
    HEAD_MIN + ELLIPSIS.length + PROMPT_DESCRIPTION_TAIL,
    max - shownNotes.length - 1,
  );
  return `${headAndTail(base.trimEnd(), baseBudget)} ${shownNotes}`;
}
