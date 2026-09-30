import type { ForensicEvent } from "./stateTypes.js";
import type { ForensicRow, ForensicRowStore } from "./forensicRows.js";

// A version conflict means a writer outside the state lock changed the row between read and write.
// The row is read again and the change re-applied; after this many rounds it is left as it is —
// only a writer bypassing the lock can cause that, and the row then keeps that writer's content.
const REWRITE_ROUNDS = 3;

/**
 * Apply `transform` to `rows` and write back only the rows it changed, by row id and version. A row
 * another writer changed in between is re-read and transformed again; a row deleted in between is
 * never re-inserted. Returns the rows as written. `transform` must be idempotent: a re-read row may
 * already carry part of the change.
 */
export async function rewriteRows(
  store: ForensicRowStore,
  caseId: string,
  rows: readonly ForensicRow[],
  transform: (e: ForensicEvent) => ForensicEvent,
): Promise<ForensicRow[]> {
  const written: ForensicRow[] = [];
  let pending = rows;
  for (let round = 0; round < REWRITE_ROUNDS && pending.length; round++) {
    const changes = pending.flatMap((r) => {
      const next = transform(r.event);
      return next === r.event ? [] : [{ ...r, event: next }];
    });
    if (!changes.length) break;
    const result = await store.updateForensicRows(caseId, changes);
    const conflicted = new Set(result.conflicts);
    const missing = new Set(result.missing);
    written.push(...changes.filter((c) => !conflicted.has(c.rowId) && !missing.has(c.rowId)));
    if (!conflicted.size) break;
    pending = await store.forensicRowsByRowId(caseId, [...conflicted]);
  }
  return written;
}
