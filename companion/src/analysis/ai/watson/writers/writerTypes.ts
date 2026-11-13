import type { InvestigationState } from "../../../stateTypes.js";
import type { CaseStore } from "../../../../storage/caseStore.js";
import type { WatsonProposalDeps } from "../proposalErrors.js";
import type { WatsonProposal } from "../types.js";

// One writer per proposal kind. The dispatcher (proposals.ts) runs the status check inside
// chatStore.update() and then calls the writer: under the state lock it holds itself, or, for a
// self-locking writer, with no lock held so the writer can call code that takes the lock on its own
// (StateLock is not re-entrant). A writer re-reads the stored item, throws WatsonProposalConflict
// when it no longer matches, and checks everything before its first write.

export interface WriterDeps extends WatsonProposalDeps {
  /** Reads stored pastes. Without it, a cited paste line counts as unreadable. */
  cases?: CaseStore;
  /** #1599: a Watson write marks the conclusions out of date and never starts a synthesis. */
  markConclusionsOutOfDate(caseId: string, why: string): Promise<void>;
}

/**
 * What a writer did. `state` is the overview it saved (absent when it saved none); `proposal` is the
 * proposal with what the apply recorded (the item as written, the rows it created) so undo can
 * check exactly that. The dispatcher stores it in the chat.
 */
export interface WriterResult<P extends WatsonProposal> {
  state?: InvestigationState;
  proposal?: P;
}

export interface WatsonWriter<P extends WatsonProposal> {
  /** True: apply/undo are called without the state lock held and take it themselves. */
  selfLocking?: boolean;
  apply(deps: WriterDeps, caseId: string, p: P): Promise<WriterResult<P>>;
  undo(deps: WriterDeps, caseId: string, p: P): Promise<WriterResult<P>>;
}

/** The activity entry's target, per kind. */
export type WatsonTargetType = "question" | "finding" | "next_step" | "report" | "event";
