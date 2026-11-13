import type { InvestigationState } from "../../stateTypes.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import type { WatsonChat } from "./types.js";

// Pure builder for Watson's per-round user prompt. Every block is bounded, and every untrusted
// body (chat, paste, analyst text) sits inside a BEGIN/END fence the text cannot forge.
export const WATSON_RECENT_TURNS = 12;
export const WATSON_TURN_PROMPT_MAX = 1200;
export const WATSON_PASTE_PROMPT_MAX = 24000;
export const WATSON_MEMORY_PROMPT_MAX = 4000;
export const WATSON_CASE_CONTEXT_PROMPT_MAX = 30000;
export const WATSON_CASE_EVENTS_MAX = 50;
export const WATSON_CASE_EVENT_CHARS = 300;
export const WATSON_ANALYST_PROMPT_MAX = WATSON_TURN_TEXT_MAX;
export const WATSON_QUESTIONS_MAX = 60;
export const WATSON_QUESTION_CHARS = 500;
export const WATSON_ANSWER_CHARS = 1500;

export interface WatsonPromptInput {
  state: InvestigationState;
  chat: WatsonChat;
  analystText: string;
  caseContext: string;
  mainLanguages: string[];
  pasteExcerpt?: { pasteId: string; filename: string; text: string; truncated: boolean };
}

const clip = (s: string, max: number): string => (s.length > max ? `${s.slice(0, max)}…` : s);

// Any fence marker inside untrusted text is defanged so it cannot close or open a fence.
function defang(s: string): string {
  return s.replace(/<<<\s*(END\s+)?(PASTE|CHAT|ANALYST)/gi, "<<‹$1$2").replace(/>>>/g, "›››");
}

function fence(label: string, body: string): string {
  return `<<<${label}>>>\n${defang(body)}\n<<<END ${label.split(" ")[0]}>>>`;
}

export function buildWatsonUserPrompt(input: WatsonPromptInput): string {
  const { state, chat, analystText, caseContext, mainLanguages, pasteExcerpt } = input;
  const questions = (state.keyQuestions ?? [])
    .slice(0, WATSON_QUESTIONS_MAX)
    .map(
      (q) =>
        `- [${q.id}] (${q.status}) ${clip(q.question, WATSON_QUESTION_CHARS)}${q.answer ? ` — answer: ${clip(q.answer, WATSON_ANSWER_CHARS)}` : ""}`,
    );
  const recent = chat.turns
    .slice(-WATSON_RECENT_TURNS)
    .map((t) => `${t.role}: ${clip(t.text, WATSON_TURN_PROMPT_MAX)}`);
  const changes = chat.pendingCaseEvents
    .slice(0, WATSON_CASE_EVENTS_MAX)
    .map((e) => `- ${clip(e, WATSON_CASE_EVENT_CHARS)}`);

  const blocks = [
    `CASE CONTEXT\nLanguages the case can query: ${mainLanguages.join(", ") || "none known"}\n${clip(caseContext, WATSON_CASE_CONTEXT_PROMPT_MAX)}`,
    `KEY QUESTIONS\n${questions.join("\n") || "(none)"}`,
    `WATSON MEMORY\n${clip(chat.memory, WATSON_MEMORY_PROMPT_MAX) || "(empty)"}`,
    `CASE CHANGES SINCE LAST ROUND\n${changes.join("\n") || "(none)"}`,
    `RECENT CHAT\n${fence("CHAT", recent.join("\n") || "(none)")}`,
  ];
  if (pasteExcerpt) {
    const text = clip(pasteExcerpt.text, WATSON_PASTE_PROMPT_MAX);
    const note =
      pasteExcerpt.truncated || text.length < pasteExcerpt.text.length
        ? " (truncated: ask for a search)"
        : "";
    const label = `PASTE id=${pasteExcerpt.pasteId.replace(/[^\w-]/g, "")}`;
    blocks.push(`PASTE (${defang(pasteExcerpt.filename).slice(0, 200)})${note}\n${fence(label, text)}`);
  }
  blocks.push(`ANALYST\n${fence("ANALYST", clip(analystText, WATSON_ANALYST_PROMPT_MAX))}`);
  return blocks.join("\n\n");
}
