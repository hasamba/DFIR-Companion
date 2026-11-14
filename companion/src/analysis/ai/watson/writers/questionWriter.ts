import type { InvestigationQuestion } from "../../../stateTypes.js";
import { sameAnswer } from "../../../timeline/watsonQuestions.js";
import { WatsonProposalConflict } from "../proposalErrors.js";
import type { WatsonQuestionProposal } from "../types.js";
import type { WatsonWriter } from "./writerTypes.js";

// Phase 1's only write: a key question Watson answered or added. Overview only — a key-question
// edit never rewrites the forensic timeline.

const conflict = (questionId: string): WatsonProposalConflict =>
  new WatsonProposalConflict(`Key question ${questionId} changed since this proposal; nothing was written`);

/**
 * The question Watson writes: its answer, pinned, authored. Every annotation that belonged to the
 * OLD answer goes (disagreement, contradiction, stale flag, the findings it relied on, its collect
 * directive), also from a proposal saved before this rule, so none is shown against Watson's answer.
 */
function applied(after: InvestigationQuestion): InvestigationQuestion {
  const {
    synthesisDisagrees: _d,
    answeredBy: _a,
    contradicted: _c,
    staleReSynth: _s,
    relatedFindingIds: _r,
    collect: _k,
    ...rest
  } = after;
  return { ...rest, pinned: true, author: "watson" };
}

/** Pure: the new key-question list, or a conflict when the stored question moved on. */
export function nextQuestions(
  questions: readonly InvestigationQuestion[],
  p: WatsonQuestionProposal,
  action: "apply" | "undo",
): InvestigationQuestion[] {
  const current = questions.find((q) => q.id === p.questionId);
  const expected = action === "apply" ? p.before : applied(p.after);
  const matches = expected ? !!current && sameAnswer(current, expected) : !current;
  if (!matches) throw conflict(p.questionId);
  if (action === "apply") {
    const q = applied(p.after);
    return current ? questions.map((x) => (x.id === q.id ? q : x)) : [...questions, q];
  }
  // Undo: restore the question as it was when Watson proposed, or remove a question Watson added.
  return p.before
    ? questions.map((x) => (x.id === p.questionId ? (p.before as InvestigationQuestion) : x))
    : questions.filter((x) => x.id !== p.questionId);
}

function write(action: "apply" | "undo"): WatsonWriter<WatsonQuestionProposal>["apply"] {
  return async (deps, caseId, p) => {
    const loaded = await deps.stateStore.loadOverview(caseId);
    const saved = { ...loaded, keyQuestions: nextQuestions(loaded.keyQuestions, p, action) };
    await deps.stateStore.saveOverview(saved);
    return { state: saved };
  };
}

export const questionWriter: WatsonWriter<WatsonQuestionProposal> = {
  apply: write("apply"),
  undo: write("undo"),
};
