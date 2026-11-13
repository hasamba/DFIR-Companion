import type { InvestigationQuestion, InvestigationState } from "../stateTypes.js";
import { isProtectedWatson } from "../timeline/watsonQuestions.js";

/**
 * The key questions the case holds NOW, with their answers, for the synthesis prompt. The pinned
 * block lists only question text, so without this the model rewrote answers it had never read —
 * including answers the analyst applied from Watson. Synthesis reads the current answer before it
 * changes it. Bounded: a capped count, one clipped line per question, and the cut is disclosed.
 */

export const CURRENT_KEY_QUESTIONS_MAX = 40;
const QUESTION_CHARS = 200;
const ANSWER_CHARS = 300;

// One line: adversary-influenced text (an answer can quote an event) cannot add prompt lines.
const oneLine = (s: string, max: number): string => {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
};

function line(q: InvestigationQuestion): string {
  // Only an answer the analyst applied is labelled; a question Watson asked but nobody answered is not.
  const who = isProtectedWatson(q) ? " [Watson answer, applied by the analyst]" : "";
  const answer = q.answer ? ` → ${oneLine(q.answer, ANSWER_CHARS)}` : " (no answer yet)";
  return `[${q.id}] (${q.status})${who} ${oneLine(q.question, QUESTION_CHARS)}${answer}`;
}

export function buildCurrentKeyQuestionsBlock(state: Pick<InvestigationState, "keyQuestions">): string {
  const all = state.keyQuestions;
  if (!all.length) return "";
  const shown = all.slice(0, CURRENT_KEY_QUESTIONS_MAX);
  const cut = all.length - shown.length;
  return (
    `CURRENT KEY QUESTIONS (what the case answers now — read each answer before you change it; ` +
    `return a question with the SAME id; change its status or answer only when the evidence supports ` +
    `the change):\n` +
    shown.map(line).join("\n") +
    (cut > 0 ? `\n(${cut} more key questions not shown)` : "") +
    "\n\n"
  );
}
