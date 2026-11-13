import type { InvestigationState } from "../../stateTypes.js";
import {
  applyWatsonProposal,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
  type WatsonProposalDeps,
} from "./proposals.js";
import { ANSWER_MAX, newWatsonId, POINTER_MAX, QUESTION_MAX } from "./roundProposals.js";
import type { WatsonAnswer, WatsonChat, WatsonProposal } from "./types.js";

// "Add to open questions" on a Watson answer: the analyst's click is the approval, so the question
// is proposed and applied in one call. The proposal stays on the chat, so Undo works as for any other.

function proposalFor(answer: WatsonAnswer, turnId: string): WatsonProposal {
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
  deps: WatsonProposalDeps,
  caseId: string,
  turnId: string,
  actor?: string,
): Promise<{ chat: WatsonChat; state: InvestigationState }> {
  let proposal: WatsonProposal | undefined;
  // The status check and the append are one chat update, so two clicks cannot both add.
  await deps.chatStore.update(caseId, (c) => {
    const turn = c.turns.find((t) => t.id === turnId);
    if (!turn?.answer) throw new WatsonProposalNotFoundError(turnId);
    if (turn.answerProposalId) {
      const prior = c.proposals.find((p) => p.id === turn.answerProposalId);
      throw new WatsonProposalStateError("add", prior?.status ?? "applied");
    }
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
  const out = await applyWatsonProposal(deps, caseId, (proposal as WatsonProposal).id, "apply", actor);
  return { chat: out.chat, state: out.state as InvestigationState };
}
