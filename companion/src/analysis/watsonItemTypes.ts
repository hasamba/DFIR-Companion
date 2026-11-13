// The marks a finding or next step carries when the analyst applied it from Watson (phase 2). Types
// only, so stateTypes.ts (the shared layer) can carry the fields; the logic that keeps Watson items
// across every merge is timeline/watsonItems.ts.

import type { Severity } from "./stateTypes.js";

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
  // Lines of a stored paste the finding cites, beside (or instead of) forensic-event citations.
  citedPasteLines?: { pasteId: string; line: number }[];
  // Synthesis re-issued this Watson finding's id with a different severity, title or description.
  // Shown beside the finding; never applied (the analyst approved Watson's version).
  synthesisDisagrees?: WatsonFindingDisagreement;
  // A synthesis finding with the same semantic key: both are kept, and the dashboard links them.
  similarSynthesisId?: string;
  // Every forensic event the finding cites is now a false positive or gone ("cited evidence changed").
  citationsChanged?: boolean;
}
