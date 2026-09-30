import { isDeepStrictEqual } from "node:util";
import type { ForensicEvent } from "./stateTypes.js";
import type { MergeStoredRow } from "./caseSqliteWorkerMerge.js";
import { storedForm, type StateStore } from "./stateStore.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";
import { correlateEventsTracked, correlationGroups } from "./correlate.js";
import { runTimelineChain } from "./stateMerge.js";
import { correlationKeys } from "./mergeIndex.js";

/**
 * The row-level helpers of the incremental importer merge (#1874): reading stored rows, the
 * correlation closure, the fixed-point test and the stability test. incrementalMerge.ts drives them.
 */

/** A forensic row the merge holds: the stored row (absent for a new event) and its event. */
export interface HeldRow {
  stored?: MergeStoredRow;
  event: ForensicEvent;
  /** First appearance in the pre-sort timeline: the stored ordinal, or past every ordinal. */
  pre: number;
}

/** Past every stored ordinal: where the full merge appends a new event before sorting. */
export const NEW_ROW_BASE = 2 ** 50;

/** A stored forensic row as load() would hand it to the merge. */
export function eventOf(row: MergeStoredRow): ForensicEvent {
  return upgradeForensicEvent(JSON.parse(row.payload) as ForensicEvent);
}

/** The event as the NEXT merge will read it back: its stored form, parsed and upgraded. */
export function readBack(e: ForensicEvent): ForensicEvent {
  return upgradeForensicEvent(JSON.parse(JSON.stringify(storedForm(e))) as ForensicEvent);
}

/** byEventTime's key: the parsed time, or null (sorts last). */
export function timeKey(e: ForensicEvent): number | null {
  const t = Date.parse(e.timestamp);
  return Number.isNaN(t) ? null : t;
}

/** byEventTime, then first appearance — the order a stable sort of the pre-sort timeline produces. */
export function compareFinal(
  a: { t: number | null; pre: number },
  b: { t: number | null; pre: number },
): number {
  if (a.t !== b.t) {
    if (a.t === null) return 1;
    if (b.t === null) return -1;
    return a.t - b.t;
  }
  return a.pre - b.pre;
}

/**
 * Every clean stored row that shares a correlation bucket with `seedKeys`, and every row sharing a
 * bucket with those, to a fixed point, never the rows in `held`. The set returned plus `held` holds
 * every bucket that touches it whole. Returns null when a fetched row is not clean (a write landed
 * outside the merge; the caller takes the full path) or when the closure passes `limit` rows.
 */
export async function correlationClosure(
  store: StateStore,
  caseId: string,
  seedKeys: Iterable<string>,
  held: ReadonlySet<number>,
  limit: number,
): Promise<MergeStoredRow[] | null> {
  const seen = new Set<string>(seedKeys);
  let pending = [...seen];
  const exclude = new Set(held);
  const out: MergeStoredRow[] = [];
  while (pending.length) {
    const rows = await store.mergeRows(caseId, { keys: pending, excludeRowIds: [...exclude] });
    pending = [];
    for (const row of rows) {
      if (!row.index || row.index.version !== row.version) return null;
      exclude.add(row.rowId);
      out.push(row);
      for (const key of row.index.keys) {
        if (seen.has(key)) continue;
        seen.add(key);
        pending.push(key);
      }
    }
    if (out.length > limit) return null;
  }
  return out;
}

/**
 * Which of `values` the next merge's chain and per-row correlation steps would leave exactly as they
 * are — the rows it may skip. Only meaningful when no row of the case has a trigger (mergeIndex.ts):
 * then every pass is per-row, so one chain run over the batch answers for each row. The year clamp is
 * left out: the merge reads every row it would move.
 */
export function fixedPoints(values: readonly ForensicEvent[], at: string): boolean[] {
  const chained = new Map(
    runTimelineChain(values, [], at, (events) => [...events], false).map((e) => [e.id, e]),
  );
  return values.map((v) => {
    const after = chained.get(v.id);
    if (!after) return false;
    const [again] = correlateEventsTracked([after]).events;
    return isDeepStrictEqual(again, v);
  });
}

/**
 * Whether the rows around a merge's output would fold on the NEXT merge: the output rows as they read
 * back, with every stored row sharing a bucket with them (or with a row this merge removed or rewrote)
 * — any group of two or more means today's merge would fold stored rows next time, so the next merge
 * must take the full path. Null when the closure could not be read.
 */
export async function foldsNextTime(
  store: StateStore,
  caseId: string,
  outputs: readonly ForensicEvent[],
  extraKeys: Iterable<string>,
  heldRowIds: ReadonlySet<number>,
  limit: number,
): Promise<boolean | null> {
  const keys = new Set<string>(extraKeys);
  for (const e of outputs) for (const k of correlationKeys(e)) keys.add(k);
  const around = await correlationClosure(store, caseId, keys, heldRowIds, limit);
  if (!around) return null;
  const groups = correlationGroups([...around.map(eventOf), ...outputs]);
  return groups.some((g) => g.length > 1);
}
