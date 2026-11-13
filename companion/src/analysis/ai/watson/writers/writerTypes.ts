import type { ForensicEvent, InvestigationState } from "../../../stateTypes.js";
import type { PromotionOptions } from "../../../ingest/timelineImports.js";
import type { PromotionOutcome } from "../../../ingest/promotionOutcome.js";
import type { CaseStore } from "../../../../storage/caseStore.js";
import type { WatsonProposalDeps } from "../proposalErrors.js";
import type { WatsonProposal } from "../types.js";

// One writer per proposal kind. The dispatcher (proposals.ts) runs the status check inside
// chatStore.update() and then calls the writer: under the state lock it holds itself, or, for a
// self-locking writer, with no lock held so the writer can call code that takes the lock on its own
// (StateLock is not re-entrant). A writer re-reads the stored item, throws WatsonProposalConflict
// when it no longer matches, and checks everything before its first write.

export type WatsonReportField = "conclusions" | "investigationLimitations";

/** The report details as Watson sees them: the two fields it may write and its marks. */
export interface WatsonReportFields {
  conclusions: string;
  investigationLimitations: string;
  updatedAt?: string;
  watsonFields?: Partial<Record<WatsonReportField, { proposalId: string; at: string }>>;
}

/**
 * The report-details store, structurally (analysis/ai may not import reports/): the route injects
 * ReportMetaStore. `update` is its one serialized write path; `fn` must spread its argument so the
 * fields Watson does not know are kept.
 */
export interface WatsonReportText {
  load(caseId: string): Promise<WatsonReportFields>;
  update(
    caseId: string,
    fn: (current: WatsonReportFields) => WatsonReportFields | Promise<WatsonReportFields>,
  ): Promise<WatsonReportFields>;
}

export interface WriterDeps extends WatsonProposalDeps {
  /** The report details. Without it, a report-text proposal cannot be applied. */
  reportText?: WatsonReportText;
  /** Reads stored pastes. Without it, a cited paste line counts as unreadable. */
  cases?: CaseStore;
  /** #1599: a Watson write marks the conclusions out of date and never starts a synthesis. */
  markConclusionsOutOfDate(caseId: string, why: string): Promise<void>;
  /** The pipeline's promotion seam (it takes the state lock). Without it, rows cannot be promoted. */
  promoteEvents?(
    caseId: string,
    events: ForensicEvent[],
    opts: PromotionOptions,
  ): Promise<{ state: InvestigationState; outcome: PromotionOutcome }>;
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
  apply(deps: WriterDeps, caseId: string, p: P, actor?: string): Promise<WriterResult<P>>;
  undo(deps: WriterDeps, caseId: string, p: P): Promise<WriterResult<P>>;
}

/** The activity entry's target, per kind. */
export type WatsonTargetType = "question" | "finding" | "next_step" | "report" | "event";
