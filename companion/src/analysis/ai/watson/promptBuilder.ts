import type { InvestigationState } from "../../stateTypes.js";
import type { WatsonChat } from "./types.js";

// Pure builder for Watson's per-round user prompt. Every block is bounded.
const RECENT_TURNS = 12;
const TURN_MAX_CHARS = 1200;
const PASTE_MAX_CHARS = 24000;

export interface WatsonPromptInput {
  state: InvestigationState;
  chat: WatsonChat;
  analystText: string;
  caseContext: string;
  mainLanguages: string[];
  pasteExcerpt?: { pasteId: string; filename: string; text: string; truncated: boolean };
}

const clip = (s: string, max: number): string => (s.length > max ? `${s.slice(0, max)}…` : s);

export function buildWatsonUserPrompt(input: WatsonPromptInput): string {
  const { state, chat, analystText, caseContext, mainLanguages, pasteExcerpt } = input;
  const questions = (state.keyQuestions ?? []).map(
    (q) => `- [${q.id}] (${q.status}) ${q.question}${q.answer ? ` — answer: ${q.answer}` : ""}`,
  );
  const recent = chat.turns.slice(-RECENT_TURNS).map((t) => `${t.role}: ${clip(t.text, TURN_MAX_CHARS)}`);
  const changes = chat.pendingCaseEvents.map((e) => `- ${e}`);

  const blocks = [
    `CASE CONTEXT\nLanguages the case can query: ${mainLanguages.join(", ") || "none known"}\n${caseContext}`,
    `KEY QUESTIONS\n${questions.join("\n") || "(none)"}`,
    `WATSON MEMORY\n${chat.memory || "(empty)"}`,
    `CASE CHANGES SINCE LAST ROUND\n${changes.join("\n") || "(none)"}`,
    `RECENT CHAT\n${recent.join("\n") || "(none)"}`,
  ];
  if (pasteExcerpt) {
    const text = clip(pasteExcerpt.text, PASTE_MAX_CHARS);
    const note =
      pasteExcerpt.truncated || text.length < pasteExcerpt.text.length
        ? " (truncated: ask for a search)"
        : "";
    blocks.push(`PASTE ${pasteExcerpt.pasteId} (${pasteExcerpt.filename})${note}\n${text}`);
  }
  blocks.push(`ANALYST\n${analystText}`);
  return blocks.join("\n\n");
}
