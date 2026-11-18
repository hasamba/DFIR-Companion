// The marks a finding or next step carries when the analyst applied it from Watson (phase 2). Types
// only, so stateTypes.ts (the shared layer) can carry the fields; the logic that keeps Watson items
// across every merge is timeline/watsonItems.ts.

import type { FindingStatus, Severity } from "./stateTypes.js";

/** A next step (and the base of a finding's marks): Watson wrote it and the analyst approved it. */
export interface WatsonItemMark {
  author?: "watson";
}

/** What synthesis said when it re-issued a Watson finding's id with other content. */
export interface WatsonFindingDisagreement {
  severity: Severity;
  title: string;
  description: string;
}

/** The optional fields a Finding carries for Watson. */
export interface WatsonFindingMarks extends WatsonItemMark {
  // The analyst who applied it from Watson (the Markdown report says "approved by <name>").
  approvedBy?: string;
  // Lines of a stored paste the finding cites, beside (or instead of) forensic-event citations.
  citedPasteLines?: { pasteId: string; line: number }[];
  // Synthesis re-issued this Watson finding's id with a different severity, title or description.
  // Shown beside the finding; never applied (the analyst approved Watson's version).
  synthesisDisagrees?: WatsonFindingDisagreement;
  // A synthesis finding with the same semantic key: both are kept, and the dashboard links them.
  similarSynthesisId?: string;
  // Every forensic event the finding cites is now a false positive or gone ("cited evidence changed").
  citationsChanged?: boolean;
  // Watson demoted or dismissed this synthesis finding (#2682); never set on a Watson finding.
  watsonReview?: WatsonFindingReview;
}

/** What Watson's verdict does to a synthesis finding (#2682): a lower severity, or dismissed. */
export type WatsonReviewAction = "demote" | "dismiss";

/**
 * Watson's verdict on a finding synthesis wrote (#2682), as the case keeps it. Synthesis mints new
 * ids each run, so the verdict is matched by `key` (timeline/watsonVerdicts.ts) and each later run
 * applies it again, until a run cites evidence the verdict did not consider. Never an analyst marker.
 */
export interface WatsonFindingVerdict {
  key: string;
  action: WatsonReviewAction;
  /** demote only: the severity Watson set. A verdict never raises a finding. */
  severity?: Severity;
  reason: string;
  /** The forensic events Watson cited. */
  eventIds: string[];
  /** Every event the verdict considered: the finding's citations when applied, and Watson's. */
  consideredEventIds: string[];
  proposalId: string;
  approvedBy: string;
  at: string;
  title: string;
  /** Auto applied it (no analyst): it never applies to a High or Critical finding. */
  auto?: true;
}

/** The mark on a finding a Watson verdict changed, or would have changed (`newEventIds`). */
export interface WatsonFindingReview {
  action: WatsonReviewAction;
  severity?: Severity;
  reason: string;
  eventIds: string[];
  proposalId: string;
  approvedBy: string;
  at: string;
  /** The finding's severity and status before the verdict: what removing the mark puts back. */
  fromSeverity: Severity;
  fromStatus: FindingStatus;
  /** This run cites events the verdict did not consider: the finding is open again, unchanged. */
  newEventIds?: string[];
  /** An Auto verdict met a High or Critical finding: not applied, it waits for an analyst. */
  autoHeld?: true;
}

/** The case-level record of Watson's verdicts (#2682): kept across every merge. */
export interface WatsonStateMarks {
  watsonFindingVerdicts?: WatsonFindingVerdict[];
}
