import type { ActivityLogStore } from "../../activityLog.js";
import type { StateLock } from "../../stateLock.js";
import type { StateStore } from "../../stateStore.js";
import type { InvestigationQuestion, InvestigationState } from "../../stateTypes.js";
import type { WatsonChatStore } from "./chatStore.js";
import { sameAnswer } from "./keepWatsonAnswers.js";
import type { WatsonChat, WatsonProposal } from "./types.js";

// The analyst's decision on one Watson proposal: apply it to the case's key questions, reject it,
// or undo an applied one. The proposal status and the case write change together: the status check
// runs inside chatStore.update() (so two clicks cannot both apply), the case write under the state
// lock (so it cannot race a synthesis save). Nesting order is always chat first, then state lock.

export type WatsonProposalAction = "apply" | "reject" | "undo";

export interface WatsonProposalDeps {
  stateStore: StateStore;
  stateLock: StateLock;
  chatStore: WatsonChatStore;
  activity: ActivityLogStore;
}

/** No proposal with that id on this case (route → 404). */
export class WatsonProposalNotFoundError extends Error {
  constructor(proposalId: string) {
    super(`No Watson proposal ${proposalId}`);
    this.name = "WatsonProposalNotFoundError";
  }
}

/** The action is not allowed from the proposal's status (route → 409). */
export class WatsonProposalStateError extends Error {
  constructor(action: WatsonProposalAction, status: WatsonProposal["status"]) {
    super(`Cannot ${action} a proposal that is ${status}`);
    this.name = "WatsonProposalStateError";
  }
}

/** The question changed since the proposal was made or applied (route → 409). */
export class WatsonProposalConflict extends Error {
  constructor(questionId: string) {
    super(`Key question ${questionId} changed since this proposal; nothing was written`);
    this.name = "WatsonProposalConflict";
  }
}

const FROM: Record<WatsonProposalAction, WatsonProposal["status"]> = {
  apply: "pending",
  reject: "pending",
  undo: "applied",
};
const TO: Record<WatsonProposalAction, WatsonProposal["status"]> = {
  apply: "applied",
  reject: "rejected",
  undo: "undone",
};

/** The question Watson writes: its answer, pinned, authored, with no stale disagreement. */
function applied(after: InvestigationQuestion): InvestigationQuestion {
  const { synthesisDisagrees: _d, ...rest } = after;
  return { ...rest, pinned: true, author: "watson" };
}

/** Pure: the new key-question list, or a conflict when the stored question moved on. */
export function nextQuestions(
  questions: readonly InvestigationQuestion[],
  p: WatsonProposal,
  action: "apply" | "undo",
): InvestigationQuestion[] {
  const current = questions.find((q) => q.id === p.questionId);
  const expected = action === "apply" ? p.before : applied(p.after);
  const matches = expected ? !!current && sameAnswer(current, expected) : !current;
  if (!matches) throw new WatsonProposalConflict(p.questionId);
  if (action === "apply") {
    const q = applied(p.after);
    return current ? questions.map((x) => (x.id === q.id ? q : x)) : [...questions, q];
  }
  // Undo: restore the question as it was when Watson proposed, or remove a question Watson added.
  return p.before
    ? questions.map((x) => (x.id === p.questionId ? (p.before as InvestigationQuestion) : x))
    : questions.filter((x) => x.id !== p.questionId);
}

function detailFor(action: WatsonProposalAction, p: WatsonProposal): string {
  const what = p.kind === "question_new" ? "new key question" : "key question answer";
  const verb = { apply: "Applied", reject: "Rejected", undo: "Undid" }[action];
  return `${verb} Watson's ${what}: ${p.after.question.slice(0, 200)}`;
}

export async function applyWatsonProposal(
  deps: WatsonProposalDeps,
  caseId: string,
  proposalId: string,
  action: WatsonProposalAction,
  actor?: string,
): Promise<{ chat: WatsonChat; state?: InvestigationState }> {
  let state: InvestigationState | undefined;
  let decided: WatsonProposal | undefined;
  const chat = await deps.chatStore.update(caseId, async (c) => {
    const p = c.proposals.find((x) => x.id === proposalId);
    if (!p) throw new WatsonProposalNotFoundError(proposalId);
    if (p.status !== FROM[action]) throw new WatsonProposalStateError(action, p.status);
    if (action !== "reject") {
      await deps.stateLock.runExclusive(caseId, async () => {
        const loaded = await deps.stateStore.loadOverview(caseId);
        const saved = { ...loaded, keyQuestions: nextQuestions(loaded.keyQuestions, p, action) };
        // Overview only: a key-question edit never rewrites the forensic timeline.
        await deps.stateStore.saveOverview(saved);
        state = saved;
      });
    }
    decided = p;
    return {
      ...c,
      proposals: c.proposals.map((x) => (x.id === proposalId ? { ...x, status: TO[action] } : x)),
    };
  });
  if (decided) {
    await deps.activity.add(caseId, {
      ...(actor ? { actor } : {}),
      category: "ai",
      action: `watson.${action}`,
      detail: detailFor(action, decided),
      targetType: "question",
      targetId: decided.questionId,
    });
  }
  return state ? { chat, state } : { chat };
}
