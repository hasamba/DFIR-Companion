import type { InvestigationQuestion } from "../../stateTypes.js";

// The six starting questions Watson opens every case with (spec 4.1). Ids are stable so the
// helper can run on every round without duplicating or overwriting anything.
const STANDARD: ReadonlyArray<{ id: string; question: string }> = [
  { id: "wq-std-what", question: "What happened?" },
  { id: "wq-std-who", question: "Who did it, and which accounts were used?" },
  { id: "wq-std-when", question: "When did it start and end?" },
  { id: "wq-std-how", question: "How did the attacker get in, move, and persist?" },
  { id: "wq-std-scope", question: "Which hosts and data were affected?" },
  { id: "wq-std-active", question: "Is the attacker still active?" },
];

export function ensureStandardQuestions(
  questions: readonly InvestigationQuestion[],
): InvestigationQuestion[] {
  const present = new Set(questions.map((q) => q.id));
  const added = STANDARD.filter((s) => !present.has(s.id)).map((s): InvestigationQuestion => ({
    id: s.id,
    question: s.question,
    status: "unknown",
    answer: "",
    pointer: "",
    pinned: true,
    author: "watson",
  }));
  return [...questions, ...added];
}
