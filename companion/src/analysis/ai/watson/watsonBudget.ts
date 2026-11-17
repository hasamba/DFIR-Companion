import { inputTokenBudget } from "../../promptBudget.js";
import { WATSON_PASTE_PROMPT_MAX } from "./promptBuilder.js";
import { WATSON_SUPER_MAX_CHARS } from "./superTimelineSearch.js";
import { WATSON_LOOKUP_MAX_CHARS } from "./timelineLookup.js";
import { WATSON_TRANSCRIPT_BUDGET_CHARS } from "./toolMode.js";

// #2658: how many characters Watson's FORENSIC TIMELINE block may take. It is sized from the model's
// window like synthesis (DFIR_AI_CONTEXT_TOKENS − answer room − margin), after the system prompt and
// the REST of the user prompt — measured, not guessed, so 60 open questions or a long chat take their
// real room. What is reserved is only what a LATER send of the same round adds on top of that base
// prompt, and it depends on how the round runs (watsonLaterSendReserve).

/** ~4 characters per token, the estimate promptBudget.ts uses everywhere. */
const CHARS_PER_TOKEN = 4;
/** The tools addendum, tool schemas, the model's calls and its text between them. */
const TOOL_TURN_OVERHEAD = 20_000;
/** One tool result at most: a paste search (the largest), plus its block header. */
const MAX_TOOL_RESULT = WATSON_PASTE_PROMPT_MAX + 1_000;
/** The one-step hop's second call: the larger excerpt it can add, plus its block header. */
const MAX_HOP_EXCERPT =
  Math.max(WATSON_PASTE_PROMPT_MAX, WATSON_LOOKUP_MAX_CHARS, WATSON_SUPER_MAX_CHARS) + 2_000;

/**
 * What a later send of the round can add to the base prompt. Every round may attach a paste head.
 * The hop adds one excerpt. Tool mode keeps older results within WATSON_TRANSCRIPT_BUDGET_CHARS but
 * always keeps the NEWEST batch whole (transcriptBudget.ts), and a batch holds up to `toolCap` results;
 * a failed tool loop falls back to the hop, which adds less.
 */
export function watsonLaterSendReserve(toolCap: number): number {
  const hop = MAX_HOP_EXCERPT;
  const tools =
    toolCap > 0 ? WATSON_TRANSCRIPT_BUDGET_CHARS + toolCap * MAX_TOOL_RESULT + TOOL_TURN_OVERHEAD : 0;
  return WATSON_PASTE_PROMPT_MAX + Math.max(hop, tools);
}
/** The timeline never gets less than this, even on a small window (the rows still disclose the cut). */
export const WATSON_TIMELINE_MIN = 4000;

export function watsonTimelineBudget(
  systemPromptChars: number,
  restOfPromptChars: number,
  toolCap = 0,
): number {
  const window = inputTokenBudget() * CHARS_PER_TOKEN;
  const left = window - systemPromptChars - restOfPromptChars - watsonLaterSendReserve(toolCap);
  return Math.max(WATSON_TIMELINE_MIN, Math.floor(left));
}
