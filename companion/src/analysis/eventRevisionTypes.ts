// The shape of a row's "changed after first recorded" record (#2141). Types only, so stateTypes.ts
// (the shared layer) can carry the fields; the logic that writes and reads them is eventRevision.ts.

import type { Severity } from "./stateTypes.js";

export interface EventRevision {
  at: string; // the merge's timestamp
  source: string; // the import label, MCP agent or source that made the change
  description?: { from: string }; // the new text is the row's current one
  severity?: { from: Severity; to: Severity };
}

/** The optional fields a ForensicEvent carries for this record. */
export interface EventRevisionFields {
  // Capped: the oldest entry pinned plus the newest four (eventRevision.ts). When correlation folds
  // one row into another, the survivor keeps only its own record.
  revisions?: EventRevision[];
  revisionsDropped?: number; // middle entries the cap dropped
  // The import grade the content tagger raised this row from (#2182). A re-import restates that raw
  // grade; the merge keeps the tagger's higher grade instead of dropping the row back to it.
  taggerRaisedFrom?: Severity;
}
