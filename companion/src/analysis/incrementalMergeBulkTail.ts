import type { ForensicEvent } from "./stateTypes.js";
import type { StateStore } from "./stateStore.js";
import { isBulkPassId } from "./cloudBulkReadSummaryId.js";
import { NEW_ROW_BASE, type HeldRow } from "./incrementalMergeRows.js";

/**
 * The cloud bulk-read pass's re-emitted rows in the incremental importer merge (#2544).
 *
 * summarizeBulkReads (cloudBulkRead.ts) returns the timeline without the rows it replaces by id — its
 * group summaries, the truncation row and the object-logging coverage row — and appends what it
 * emits, in emission order. The full merge then sorts by time and first appearance, so a re-emitted
 * row sorts after every row at its time. Every later pass is per-row, gated, or a trigger, so the
 * chain's output is the held rows in order with some of the pass's ids taken out (K), then a tail of
 * the pass's ids (A). The merge holds every row the pass reads or replaces (mergeIndex.ts
 * mergeLoadAlways), so the incremental pass emits exactly what the full one does.
 *
 * Each tail row keeps the stored row it replaced (so the write updates that row in place) and takes
 * a first appearance past every other row: stored ordinals < new rows (NEW_ROW_BASE + i) < the
 * metadata coverage row (NEW_ROW_BASE + rows, placeCoverage — appended by an EARLIER pass) < the tail.
 */

/** Past every new row and the metadata coverage row: where the bulk-read pass appends. */
export const BULK_TAIL_BASE = 2 * NEW_ROW_BASE;

const REORDERED = "the chain added, removed or reordered a row";

/** The chained rows matched back to the held rows (K), then the pass's tail (A); or why not. */
export function placeBulkTail(
  working: readonly HeldRow[],
  chained: readonly ForensicEvent[],
): HeldRow[] | string {
  const kept: HeldRow[] = [];
  const keptAt: number[] = [];
  const removed = new Map<string, HeldRow>();
  let j = 0;
  let i = 0;
  for (; i < chained.length; i++) {
    const id = chained[i].id;
    let k = j;
    while (k < working.length && working[k].event.id !== id && isBulkPassId(working[k].event.id)) k++;
    if (k >= working.length || working[k].event.id !== id) break; // the tail starts here
    for (; j < k; j++) removed.set(working[j].event.id, working[j]);
    kept.push({ ...working[k], event: chained[i] });
    keptAt.push(i);
    j = k + 1;
  }
  for (; j < working.length; j++) {
    if (!isBulkPassId(working[j].event.id)) return REORDERED;
    removed.set(working[j].event.id, working[j]);
  }
  const ambiguous = ambiguousKept(chained, kept, keptAt);
  if (ambiguous) return ambiguous;
  const tail = placeTail(chained.slice(i), removed, new Set(kept.map((h) => h.event.id)));
  if (typeof tail === "string") return tail;
  for (const h of removed.values()) if (h.stored) return "the chain removed a stored row";
  return [...kept, ...tail];
}

/**
 * A kept row of the pass after the last row that is not the pass's could equally be one it removed
 * and re-emitted last — the two place differently. No new row of the delta separates them then.
 */
function ambiguousKept(
  chained: readonly ForensicEvent[],
  kept: readonly HeldRow[],
  at: number[],
): string | null {
  let lastOther = -1;
  chained.forEach((e, n) => {
    if (!isBulkPassId(e.id)) lastOther = n;
  });
  return kept.some((h, n) => at[n] > lastOther && isBulkPassId(h.event.id))
    ? "the chain's tail cannot tell a kept bulk-read row from a re-emitted one"
    : null;
}

/** The tail rows, each with the stored row it replaces (taken out of `removed`) and its place. */
function placeTail(
  tail: readonly ForensicEvent[],
  removed: Map<string, HeldRow>,
  keptIds: ReadonlySet<string>,
): HeldRow[] | string {
  const seen = new Set<string>();
  const out: HeldRow[] = [];
  for (const [n, event] of tail.entries()) {
    if (!isBulkPassId(event.id) || keptIds.has(event.id) || seen.has(event.id)) return REORDERED;
    seen.add(event.id);
    const stored = removed.get(event.id)?.stored;
    removed.delete(event.id);
    out.push({ ...(stored ? { stored } : {}), event, pre: BULK_TAIL_BASE + n });
  }
  return out;
}

/**
 * Why a tail row the merge holds no stored row for cannot be inserted: its id is stored already. The
 * merge index holds every stored row under one of the pass's ids, so this is a guard, not a path.
 */
export async function tailIdsFree(
  store: StateStore,
  caseId: string,
  rows: readonly HeldRow[],
): Promise<string | null> {
  const fresh = rows.filter((h) => !h.stored && h.pre >= BULK_TAIL_BASE).map((h) => h.event.id);
  const counts = await store.mergeIdCounts(caseId, fresh);
  return fresh.some((id) => (counts[id] ?? 0) > 0)
    ? "a re-emitted bulk-read row is stored but not held"
    : null;
}
