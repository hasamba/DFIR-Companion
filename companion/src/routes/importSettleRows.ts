import type { ForensicRowStore } from "../analysis/forensicRows.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { isManualId } from "../analysis/manualId.js";

/**
 * The row-level plumbing of an import's settle phase (#1874): which rows the import added, which old
 * rows were touched while it held the case, and one read-transform-write that changes only those.
 */

export type RunExclusive = <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
export const runUnlocked: RunExclusive = (_caseId, fn) => fn();

// The read-transform-write lives with the row types (analysis/forensicRowRewrite.ts) so the
// tagger shares it; re-exported for the settle steps.
export { rewriteRows } from "../analysis/forensicRowRewrite.js";

/** What the settle knows about the rows before it changes anything. */
export interface SettleScope {
  /** Ids the import added, in timeline order (not in the baseline). */
  addedIds: string[];
  /** Rows present before the import that were changed while it held the case (from the journal). */
  touchedRowIds: number[];
  /** False when the touched rows cannot be known (a legacy full-state baseline, or a lost journal). */
  touchedKnown: boolean;
  /** Forensic row count right after the importer's merge. */
  mergedCount: number;
}

export async function settleScope(
  store: ForensicRowStore,
  caseId: string,
  baseline: ImportBaseline,
): Promise<SettleScope> {
  const before = new Set(baseline.outline.ids);
  const now = await store.forensicOutline(caseId, false);
  const seen = new Set<string>();
  const addedIds: string[] = [];
  for (const id of now.ids) {
    if (typeof id !== "string" || before.has(id) || seen.has(id)) continue;
    seen.add(id);
    addedIds.push(id);
  }
  if (baseline.empty) return { addedIds, touchedRowIds: [], touchedKnown: true, mergedCount: now.ids.length };
  const journal =
    baseline.journalToken && store.readImportJournal
      ? await store.readImportJournal(caseId, baseline.journalToken, baseline.journalFence)
      : null;
  if (!journal) return { addedIds, touchedRowIds: [], touchedKnown: false, mergedCount: now.ids.length };
  // Only rows that existed at the snapshot count as touched; a row the import inserted and then
  // changed is simply one of its added rows.
  const baseRowIds = new Set(baseline.outline.rowIds);
  const present = new Set(now.rowIds);
  const touchedRowIds = journal.map((j) => j.rowId).filter((id) => baseRowIds.has(id) && present.has(id));
  return { addedIds, touchedRowIds, touchedKnown: true, mergedCount: now.ids.length };
}

/**
 * A row new since the baseline that another writer added while the import held the case (#1904).
 * The import section holds the IMPORT lock, not the state lock, so the analyst can still add a manual
 * event or promote a super-timeline row mid-import; the outline diff then lists that row as added.
 * It is not the import's: it gets no import stamp, no super-timeline copy, no tagger pass.
 *
 * Read from the row itself, by marks no import can produce:
 *  - the `manual-` id only the manual-entry builders mint (not `sources`, which an AI import may
 *    fill with any string and which correlation unions across members);
 *  - a `promotedAt` at or after the capture. Correlation carries an OLDER promotion stamp onto a
 *    new import row that folded with a row promoted earlier — that row is the import's own. A legacy
 *    baseline has no capture time, so no promotion stamp marks a row foreign there.
 */
export function isForeignToImport(e: ForensicEvent, capturedAt: string | undefined): boolean {
  if (isManualId(e.id)) return true;
  if (!capturedAt || typeof e.promotedAt !== "string") return false;
  const promoted = Date.parse(e.promotedAt);
  const captured = Date.parse(capturedAt);
  return Number.isFinite(promoted) && Number.isFinite(captured) && promoted >= captured;
}
