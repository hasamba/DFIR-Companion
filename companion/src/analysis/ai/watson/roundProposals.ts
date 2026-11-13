import { randomBytes } from "node:crypto";
import type { InvestigationQuestion } from "../../stateTypes.js";
import type { WatsonReply } from "./replySchema.js";
import type { WatsonProposal } from "./types.js";

// Turn a sanitized Watson reply into PENDING proposals. Nothing here touches case state: the analyst
// applies or rejects each proposal later. Every question Watson writes is pinned and authored
// "watson", and its id is fixed now so applying the proposal later keeps it stable.

const QUESTION_MAX = 500;
const ANSWER_MAX = 1500;
const POINTER_MAX = 500;

export const newWatsonId = (prefix: string): string => `${prefix}-${randomBytes(4).toString("hex")}`;

export function buildProposals(
  reply: WatsonReply,
  questions: readonly InvestigationQuestion[],
  turnId: string,
): WatsonProposal[] {
  const byId = new Map(questions.map((q) => [q.id, q] as const));
  const updates = reply.questionUpdates.flatMap((u): WatsonProposal[] => {
    const before = byId.get(u.questionId);
    if (!before) return [];
    const after: InvestigationQuestion = {
      ...before,
      status: u.status,
      answer: u.answer.slice(0, ANSWER_MAX),
      pointer: u.pointer.slice(0, POINTER_MAX),
      pinned: true,
      author: "watson",
    };
    return [
      {
        id: newWatsonId("wp"),
        turnId,
        kind: "question_update",
        questionId: before.id,
        before,
        after,
        status: "pending",
      },
    ];
  });
  const created = reply.newQuestions.map((q): WatsonProposal => {
    const id = newWatsonId("wq");
    return {
      id: newWatsonId("wp"),
      turnId,
      kind: "question_new",
      questionId: id,
      after: {
        id,
        question: q.question.slice(0, QUESTION_MAX),
        status: "unknown",
        answer: "",
        // Why Watson asks: kept as the pointer, the field that says where to look next.
        pointer: q.why.slice(0, POINTER_MAX),
        pinned: true,
        author: "watson",
      },
      status: "pending",
    };
  });
  return [...updates, ...created];
}
