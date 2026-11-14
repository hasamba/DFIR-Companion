import type { InvestigationQuestion, InvestigationState } from "../../stateTypes.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
  type WriterDeps,
} from "./proposals.js";
import { ANSWER_MAX, newWatsonId, POINTER_MAX, QUESTION_MAX } from "./roundProposals.js";
import type { WatsonAnswer, WatsonChat, WatsonQuestionProposal } from "./types.js";

// "Add to open questions" on a Watson answer: the analyst's click is the approval, so the question
// is proposed and applied in one call. The proposal stays on the chat, so Undo works as for any other.
// A question already on the board is refused (Task 10): Watson linked the answer to it, or its text
// normalizes to the same words. The normalization is deliberately simple and deterministic.

/** The question is already a key question on the board; nothing was written (route → 409). */
export class WatsonQuestionOnBoard extends WatsonProposalConflict {
  constructor(question: string) {
    super(`This question is already on the board: ${question}`);
    this.name = "WatsonQuestionOnBoard";
  }
}

const LEADING_FILLER = ["do we know", "what was", "what were", "what is", "what are", "the"];

/** Lowercase, punctuation stripped, spaces collapsed, leading filler ("do we know", "what was", "the") dropped. */
export function normalizeQuestionText(text: string): string {
  let out = text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]+/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  for (let cut = true; cut;) {
    cut = false;
    for (const filler of LEADING_FILLER) {
      if (out === filler || out.startsWith(filler + " ")) {
        out = out.slice(filler.length).trim();
        cut = true;
      }
    }
  }
  return out;
}

function onBoard(
  answer: WatsonAnswer,
  board: readonly InvestigationQuestion[],
): InvestigationQuestion | undefined {
  const linked = answer.matchesQuestionId && board.find((q) => q.id === answer.matchesQuestionId);
  if (linked) return linked;
  const want = normalizeQuestionText(answer.question);
  return want ? board.find((q) => normalizeQuestionText(q.question) === want) : undefined;
}

function proposalFor(answer: WatsonAnswer, turnId: string): WatsonQuestionProposal {
  const id = newWatsonId("wq");
  return {
    id: newWatsonId("wp"),
    turnId,
    kind: "question_new",
    questionId: id,
    after: {
      id,
      question: answer.question.slice(0, QUESTION_MAX),
      // Only an approved Watson proposal may set `unanswerable`, and a click on an answer is not one.
      status: answer.status === "unanswerable" ? "unknown" : answer.status,
      answer: answer.answer.slice(0, ANSWER_MAX),
      pointer: answer.pointer.slice(0, POINTER_MAX),
      pinned: true,
      author: "watson",
    },
    status: "pending",
  };
}

export async function addAnswerAsQuestion(
  deps: WriterDeps,
  caseId: string,
  turnId: string,
  actor?: string,
): Promise<{ chat: WatsonChat; state: InvestigationState }> {
  let proposal: WatsonQuestionProposal | undefined;
  const board = (await deps.stateStore.loadOverview(caseId)).keyQuestions ?? [];
  // The status check and the append are one chat update, so two clicks cannot both add.
  await deps.chatStore.update(caseId, (c) => {
    const turn = c.turns.find((t) => t.id === turnId);
    if (!turn?.answer) throw new WatsonProposalNotFoundError(turnId);
    if (turn.answerProposalId) {
      const prior = c.proposals.find((p) => p.id === turn.answerProposalId);
      throw new WatsonProposalStateError("add", prior?.status ?? "applied");
    }
    const existing = onBoard(turn.answer, board);
    if (existing) throw new WatsonQuestionOnBoard(existing.question);
    proposal = proposalFor(turn.answer, turnId);
    const made = proposal;
    return {
      ...c,
      proposals: [...c.proposals, made],
      turns: c.turns.map((t) =>
        t.id === turnId
          ? { ...t, answerProposalId: made.id, proposalIds: [...(t.proposalIds ?? []), made.id] }
          : t,
      ),
    };
  });
  const out = await applyWatsonProposal(
    deps,
    caseId,
    (proposal as WatsonQuestionProposal).id,
    "apply",
    actor,
  );
  return { chat: out.chat, state: out.state as InvestigationState };
}
