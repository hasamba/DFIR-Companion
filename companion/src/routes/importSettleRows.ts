import type { ForensicRowStore } from "../analysis/forensicRows.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";

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
      ? await store.readImportJournal(caseId, baseline.journalToken)
      : null;
  if (!journal) return { addedIds, touchedRowIds: [], touchedKnown: false, mergedCount: now.ids.length };
  // Only rows that existed at the snapshot count as touched; a row the import inserted and then
  // changed is simply one of its added rows.
  const baseRowIds = new Set(baseline.outline.rowIds);
  const present = new Set(now.rowIds);
  const touchedRowIds = journal.map((j) => j.rowId).filter((id) => baseRowIds.has(id) && present.has(id));
  return { addedIds, touchedRowIds, touchedKnown: true, mergedCount: now.ids.length };
}
