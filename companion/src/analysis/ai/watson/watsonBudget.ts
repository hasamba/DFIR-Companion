import { inputTokenBudget } from "../../promptBudget.js";

// #2658: how many characters Watson's FORENSIC TIMELINE block may take. It is sized from the model's
// window like synthesis (DFIR_AI_CONTEXT_TOKENS − answer room − margin), after the system prompt and
// the REST of the user prompt — measured, not guessed, so 60 open questions or a long chat take their
// real room. What is reserved is only what a LATER send of the same round adds on top of the base
// prompt: the tool-mode transcript (≤ 80k characters of results, plus the calls and the tools
// addendum) or the hop's second-call excerpt (a paste ≤ 24k plus a lookup or super-timeline excerpt).

/** ~4 characters per token, the estimate promptBudget.ts uses everywhere. */
const CHARS_PER_TOKEN = 4;
/** What a later send of the round adds to the base prompt. */
export const WATSON_SECOND_CALL_RESERVE = 120_000;
/** The timeline never gets less than this, even on a small window (the rows still disclose the cut). */
export const WATSON_TIMELINE_MIN = 4000;

export function watsonTimelineBudget(systemPromptChars: number, restOfPromptChars: number): number {
  const window = inputTokenBudget() * CHARS_PER_TOKEN;
  const left = window - systemPromptChars - restOfPromptChars - WATSON_SECOND_CALL_RESERVE;
  return Math.max(WATSON_TIMELINE_MIN, Math.floor(left));
}
