// The Ask panel's short conversation memory (#1411). Each ask is a single-shot call, so a follow-up
// ("and on which host?") loses the thread unless the panel sends its last few Q&A pairs back with
// the new question. That history is REQUEST INPUT — untrusted, bounded here, never persisted.
//
// PURE — no I/O. Never throws: a malformed entry is dropped, not rejected, so a stale or
// hand-edited panel state can never block a question.

export interface AskTurn {
  question: string;
  answer: string;
}

export const ASK_HISTORY_MAX = 3; // the last N pairs — enough for a follow-up, cheap in tokens
export const ASK_HISTORY_FIELD_MAX = 1200; // chars per question/answer; an answer is "a few sentences"

function field(v: unknown): string {
  return typeof v === "string" ? v.trim().slice(0, ASK_HISTORY_FIELD_MAX) : "";
}

export function parseAskHistory(raw: unknown): AskTurn[] {
  if (!Array.isArray(raw)) return [];
  const turns: AskTurn[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const { question, answer } = item as Record<string, unknown>;
    if (typeof question !== "string" || typeof answer !== "string") continue;
    const q = field(question);
    if (!q) continue;
    turns.push({ question: q, answer: field(answer) });
  }
  return turns.slice(-ASK_HISTORY_MAX);
}

/** The whole POST /cases/:id/ask body: the trimmed question plus the bounded history. */
export function parseAskRequest(body: unknown): { question: string; history: AskTurn[] } {
  const b = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  return {
    question: typeof b.question === "string" ? b.question.trim() : "",
    history: parseAskHistory(b.history),
  };
}
