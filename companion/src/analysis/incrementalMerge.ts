import { isDeepStrictEqual } from "node:util";
import { citesEvents, renameForgedFindingIds, type AnalysisDelta } from "./responseSchema.js";
import type { ForensicEvent, InvestigationState, IOC } from "./stateTypes.js";
import type { MergePlacedRow, MergeSnapshot, MergeStoredRow } from "./caseSqliteWorkerMerge.js";
import { storedForm, type StateStore } from "./stateStore.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";
import { correlateEventsTracked } from "./correlate.js";
import { clampToYear, dominantYear, yearOf } from "./timeYearClamp.js";
import {
  assembleMerge,
  copyTimeline,
  iocMatchKey,
  mergeIocs,
  runTimelineChain,
  upsertForensicEvents,
  type WindowContext,
} from "./stateMerge.js";
import {
  MERGE_FLAG_CLOUD_AUDIT,
  MERGE_FLAG_LOAD,
  MERGE_FLAG_PROCESS,
  MERGE_FLAG_TRIGGER,
  correlationKeys,
  mergeIndexEntry,
  mergeTrigger,
} from "./mergeIndex.js";
import {
  NEW_ROW_BASE,
  compareFinal,
  correlationClosure,
  eventOf,
  fixedPoints,
  foldsNextTime,
  timeKey,
  type HeldRow,
} from "./incrementalMergeRows.js";

/**
 * The importer merge, reading and writing only what the incoming delta needs (#1874).
 *
 * Today's merge loads the whole case, runs mergeDelta over it and saves it all. This computes the
 * same result from the rows that can matter — the rows the delta names, the rows written outside the
 * merge since the last one, the rows the year clamp moves, the rows a subset-safe correlation pass
 * reads, and every row sharing a correlation bucket with any of them — and writes only what changed,
 * in one transaction that refuses to write if the case changed underneath it. The per-row index that
 * makes that possible is described in caseSqliteWorkerMerge.ts and mergeIndex.ts.
 *
 * Whenever it cannot show the result would be identical, it says why and the caller runs today's full
 * merge instead: a case whose index is missing or from another build, rows another writer changed in
 * bulk, a correlation pass with work to do (the triggers in mergeIndex.ts), a delta that cites events
 * or carries lab intel, duplicate event ids, a timeline not in time order, a correlation bucket
 * spanning most of the case, the cloud metadata coverage row falling due, or a write that raced it.
 */

/** Bump when the merge's semantics or the index's contents change: every case re-indexes once. */
export const MERGE_INDEX_VERSION = 1;

export type IncrementalResult =
  { ok: true; state: InvestigationState; read: number; written: number } | { ok: false; reason: string };

const fallback = (reason: string): IncrementalResult => ({ ok: false, reason });

/** More rows than this to read up front and the full merge costs no more; it re-indexes too. */
function readLimit(rowCount: number): number {
  return Math.max(2000, Math.floor(rowCount / 2));
}

/** Why the stored index cannot carry this merge, or null. */
function snapshotGate(snap: MergeSnapshot | null, stamp: string): string | null {
  if (!snap) return "the case has no stored state yet";
  if (snap.meta?.stamp !== stamp) return "the merge index is missing or from another build";
  if (snap.meta?.stable !== true) return "stored rows may correlate with each other";
  if (snap.stale.length > readLimit(snap.rowCount))
    return `${snap.stale.length} rows were written outside the merge`;
  if (snap.clean.trigger > 0) return "a correlation pass has stored rows to act on";
  return null;
}

export async function mergeIncrementally(
  store: StateStore,
  caseId: string,
  incoming: AnalysisDelta,
  ctx: WindowContext,
  stamp: string,
): Promise<IncrementalResult> {
  const snap = await store.mergeSnapshot(caseId);
  const gate = snapshotGate(snap, stamp);
  if (gate || !snap) return fallback(gate ?? "no snapshot");

  const overview = await store.loadMergeOverview(caseId);
  const delta = renameForgedFindingIds(
    incoming,
    ctx.knownFindingIds ?? new Set(overview.findings.map((f) => f.id)),
  );
  if (citesEvents(delta)) return fallback("the delta cites events");
  if (delta.labIntel?.length || overview.labIntel?.length) return fallback("the case holds lab intel");

  const held = await readHeld(store, caseId, snap, delta);
  if (typeof held === "string") return fallback(held);
  const clamped = await clampHeld(store, caseId, snap, held, delta, ctx);
  const chained = chainHeld(snap, held, clamped.working, clamped.year, ctx);
  if (typeof chained === "string") return fallback(chained);
  const limit = Math.max(5000, Math.floor(snap.rowCount / 2));
  const corr = await correlateHeld(store, caseId, snap, held, chained.rows, limit);
  if (typeof corr === "string") return fallback(corr);

  const iocPart = await mergeIocPart(store, caseId, delta, ctx, overview, [...corr.absorbedInto.keys()]);
  const merged = assembleMerge(
    { ...overview, iocs: iocPart.stored.map((r) => JSON.parse(r.payload) as IOC), forensicTimeline: [] },
    delta,
    ctx,
    {
      ...iocPart.result,
      forensicTimeline: corr.outputs.map((o) => o.event),
      absorbedInto: corr.absorbedInto,
    },
  );

  const writes = await describeWrites(store, caseId, corr, held, limit, ctx.timestamp);
  if (typeof writes === "string") return fallback(writes);
  const applied = await applyOrExplain(store, caseId, {
    generation: snap.generation,
    overview: { ...merged, forensicTimeline: [], iocs: [] },
    iocs: {
      updates: iocPart.stored.map((r, i) => ({ rowId: r.rowId, version: r.version, entity: merged.iocs[i] })),
      inserts: merged.iocs.slice(iocPart.stored.length),
    },
    forensic: {
      deletes: corr.deletes.map((r) => ({ rowId: r.rowId, version: r.version })),
      placed: writes.placed,
    },
    meta: { stamp, stable: !writes.folds },
  });
  if (applied) return fallback(applied);
  return { ok: true, state: merged, read: corr.input.length, written: writes.placed.length };
}

/** An apply that failed in a way that does not say whether it committed (analysis/caseMerge.ts). */
export class MergeCommitUnknown extends Error {
  constructor(readonly cause: unknown) {
    super("the incremental merge's write may or may not have committed");
  }
}

// The apply refuses inside its transaction — nothing written — when the case changed or its stored
// order is not the time order: the caller takes the full path. Any other failure may have come after
// the commit, so it is surfaced as MergeCommitUnknown and never retried by a second merge.
const REFUSALS = new Set(["DFIR_MERGE_CONFLICT", "DFIR_MERGE_UNSORTED"]);

async function applyOrExplain(
  store: StateStore,
  caseId: string,
  plan: Parameters<StateStore["mergeApply"]>[1],
): Promise<string | null> {
  try {
    await store.mergeApply(caseId, plan);
    return null;
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    if (typeof code === "string" && REFUSALS.has(code)) return (err as Error).message;
    throw new MergeCommitUnknown(err);
  }
}

/** The stored rows the delta names, every stale row, and every row a subset-safe pass reads. */
async function readHeld(
  store: StateStore,
  caseId: string,
  snap: MergeSnapshot,
  delta: AnalysisDelta,
): Promise<Map<number, MergeStoredRow> | string> {
  const incomingIds = [
    // Work-log rows included: the upsert skips them, and a stored row read for nothing is harmless.
    ...new Set((delta.forensicEvents ?? []).map((e) => e.id)),
  ];
  const named = incomingIds.length ? await store.mergeRows(caseId, { ids: incomingIds }) : [];
  if (new Set(named.map((r) => eventOf(r).id)).size !== named.length)
    return "an incoming event id is stored more than once";
  const stale = snap.stale.length ? await store.mergeRows(caseId, { rowIds: snap.stale }) : [];
  // Every row a subset-safe pass reads (mergeIndex.ts mergeLoadAlways), so it sees all of its input.
  const always = snap.clean.load ? await store.mergeRows(caseId, { flagMask: MERGE_FLAG_LOAD }) : [];
  if (always.length > readLimit(snap.rowCount)) return `${always.length} rows feed a correlation pass`;
  const held = new Map<number, MergeStoredRow>();
  for (const r of [...named, ...stale, ...always]) held.set(r.rowId, r);
  return held;
}

const isClean = (r: MergeStoredRow): boolean => !!r.index && r.index.version === r.version;

/**
 * Upsert the delta into the held rows, then the dominant year over the WHOLE case (the stored
 * histogram of the clean rows not held, plus the held rows as they now read), then every clean row
 * the clamp would move — held too, and the upsert run again over them.
 */
async function clampHeld(
  store: StateStore,
  caseId: string,
  snap: MergeSnapshot,
  held: Map<number, MergeStoredRow>,
  delta: AnalysisDelta,
  ctx: WindowContext,
): Promise<{ working: HeldRow[]; year: number | null }> {
  let working = upsert([...held.values()], delta, ctx);
  const years = new Map(snap.years);
  for (const r of held.values()) {
    if (isClean(r) && r.index!.year !== null) years.set(r.index!.year, (years.get(r.index!.year) ?? 0) - 1);
  }
  for (const h of working) {
    const y = yearOf(h.event.timestamp);
    if (y !== null) years.set(y, (years.get(y) ?? 0) + 1);
  }
  const year = dominantYear(new Map([...years].filter(([, n]) => n > 0)));
  if (year !== null) {
    const movers = await store.mergeRows(caseId, { clampYear: year, excludeRowIds: [...held.keys()] });
    if (movers.length) {
      for (const r of movers) held.set(r.rowId, r);
      working = upsert([...held.values()], delta, ctx);
    }
  }
  return { working, year };
}

/** copyTimeline + upsertForensicEvents over the held rows in stored order, new rows after them. */
function upsert(rows: readonly MergeStoredRow[], delta: AnalysisDelta, ctx: WindowContext): HeldRow[] {
  const ordered = [...rows].sort((a, b) => a.ordinal - b.ordinal);
  const timeline = copyTimeline(ordered.map(eventOf));
  upsertForensicEvents(timeline, delta, ctx);
  return timeline.map((event, i) =>
    i < ordered.length
      ? { stored: ordered[i], event, pre: ordered[i].ordinal }
      : { event, pre: NEW_ROW_BASE + (i - ordered.length) },
  );
}

/**
 * The chain over the held rows. With no trigger in the case (checked on every held row before and
 * after the chain; the clean rows' flags were checked by the snapshot) every pass is the identity or
 * a per-row rewrite, and the subset-safe passes see every row they read.
 */
function chainHeld(
  snap: MergeSnapshot,
  held: ReadonlyMap<number, MergeStoredRow>,
  working: readonly HeldRow[],
  year: number | null,
  ctx: WindowContext,
): { rows: HeldRow[] } | string {
  for (const h of working) {
    const why = mergeTrigger(h.event);
    if (why) return `a correlation pass has work: ${why}`;
  }
  const chained = runTimelineChain(
    working.map((h) => h.event),
    [],
    ctx.timestamp,
    (events) => clampToYear(events, year),
    false,
  );
  if (chained.length !== working.length) return "the chain added or removed a row";
  const rows = working.map((h, i) => ({ ...h, event: chained[i] }));
  // The metadata coverage row's two case-wide counts after this merge: stored counts of the clean
  // rows, less the held clean rows' stored flags, plus every held row as it now reads.
  let { process, cloud } = snap.clean;
  for (const r of held.values()) {
    if (!isClean(r)) continue;
    if (r.index!.flags & MERGE_FLAG_PROCESS) process--;
    if (r.index!.flags & MERGE_FLAG_CLOUD_AUDIT) cloud--;
  }
  for (const h of rows) {
    const flags = mergeIndexEntry(h.event).flags;
    if (flags & MERGE_FLAG_TRIGGER) return `a correlation pass has work: ${mergeTrigger(h.event)}`;
    if (flags & MERGE_FLAG_PROCESS) process++;
    if (flags & MERGE_FLAG_CLOUD_AUDIT) cloud++;
  }
  if (cloud > 0 && process === 0) return "the cloud metadata coverage row is due";
  return { rows };
}

interface Correlated {
  input: HeldRow[];
  /** Clean rows read only for their correlation buckets. */
  around: Map<number, ForensicEvent>;
  outputs: { event: ForensicEvent; t: number | null; pre: number }[];
  absorbedInto: Map<string, string>;
  deletes: MergeStoredRow[];
  storedOf: Map<string, MergeStoredRow>;
  seed: Set<string>;
}

/**
 * Correlation over every bucket the held rows touch, whole, in the pre-sort order; then each output
 * row's first appearance, its stored row, and its place in the final order.
 */
async function correlateHeld(
  store: StateStore,
  caseId: string,
  snap: MergeSnapshot,
  held: ReadonlyMap<number, MergeStoredRow>,
  rows: readonly HeldRow[],
  limit: number,
): Promise<Correlated | string> {
  const seed = new Set<string>(snap.dirtyKeys);
  for (const h of rows) for (const k of correlationKeys(h.event)) seed.add(k);
  for (const r of held.values()) for (const k of r.index?.keys ?? []) seed.add(k);
  const aroundRows = await correlationClosure(store, caseId, seed, new Set(held.keys()), limit);
  if (!aroundRows) return "a correlation bucket spans most of the case, or a row changed";
  const around = new Map(aroundRows.map((r) => [r.rowId, eventOf(r)]));
  const input: HeldRow[] = [
    ...rows,
    ...aroundRows.map((r) => ({ stored: r, event: around.get(r.rowId)!, pre: r.ordinal })),
  ].sort((a, b) => a.pre - b.pre);
  const ids = input.map((h) => h.event.id);
  if (new Set(ids).size !== ids.length) return "duplicate event ids in a correlation bucket";
  const storedIds = input.filter((h) => h.stored).map((h) => h.event.id);
  const counts = await store.mergeIdCounts(caseId, storedIds);
  if (storedIds.some((id) => counts[id] !== 1)) return "an event id is stored more than once";

  const { events: folded, absorbedInto } = correlateEventsTracked(input.map((h) => h.event));
  const preOf = new Map(input.map((h) => [h.event.id, h.pre]));
  const firstPre = new Map<string, number>();
  for (const [from, to] of absorbedInto) {
    firstPre.set(to, Math.min(firstPre.get(to) ?? Infinity, preOf.get(from) ?? Infinity));
  }
  const outputs = folded
    .map((event) => ({
      event,
      t: timeKey(event),
      pre: Math.min(preOf.get(event.id) ?? Infinity, firstPre.get(event.id) ?? Infinity),
    }))
    .sort(compareFinal);
  const survivors = new Set(folded.map((e) => e.id));
  const deletes = input.filter((h) => h.stored && !survivors.has(h.event.id)).map((h) => h.stored!);
  const storedOf = new Map(input.filter((h) => h.stored).map((h) => [h.event.id, h.stored!]));
  return { input, around, outputs, absorbedInto, deletes, storedOf, seed };
}

/**
 * What the merge writes: every output row at its place, in its stored form, with its index — unless
 * it is a row read only for its buckets that came out exactly as it went in. Also whether the next
 * merge would fold stored rows (then it must take the full path, as today's merge folds them then).
 */
async function describeWrites(
  store: StateStore,
  caseId: string,
  corr: Correlated,
  held: ReadonlyMap<number, MergeStoredRow>,
  limit: number,
  at: string,
): Promise<{ placed: MergePlacedRow[]; folds: boolean } | string> {
  const stored = corr.outputs.map((o) => storedForm(o.event));
  // As the next merge will read each row back: its stored form, parsed and upgraded.
  const values = stored.map((s) => upgradeForensicEvent(JSON.parse(JSON.stringify(s)) as ForensicEvent));
  const clean = fixedPoints(values, at);
  const oldKeys = new Set<string>(corr.seed);
  for (const r of corr.deletes) for (const k of r.index?.keys ?? correlationKeys(eventOf(r))) oldKeys.add(k);
  const inputRowIds = new Set(corr.input.filter((h) => h.stored).map((h) => h.stored!.rowId));
  const folds = await foldsNextTime(store, caseId, values, oldKeys, inputRowIds, limit);
  if (folds === null) return "a correlation bucket spans most of the case, or a row changed";
  const placed = corr.outputs.map((o, i): MergePlacedRow => {
    const row = corr.storedOf.get(o.event.id);
    const before = row && !held.has(row.rowId) ? corr.around.get(row.rowId) : undefined;
    const unchanged = !!before && isDeepStrictEqual(before, o.event);
    return {
      ...(row ? { rowId: row.rowId, version: row.version } : {}),
      entity: stored[i],
      timeMs: o.t,
      pre: o.pre,
      ...(unchanged ? {} : { index: { ...mergeIndexEntry(values[i]), clean: clean[i] } }),
    };
  });
  return { placed, folds };
}

async function mergeIocPart(
  store: StateStore,
  caseId: string,
  delta: AnalysisDelta,
  ctx: WindowContext,
  overview: InvestigationState,
  absorbedIds: readonly string[],
): Promise<{ stored: MergeStoredRow[]; result: ReturnType<typeof mergeIocs> }> {
  const lowered = new Set<string>();
  const aliasIds = new Set<string>();
  for (const ioc of delta.iocs) {
    const lower = iocMatchKey(ioc);
    if (lower === null) continue;
    lowered.add(lower);
    const alias = ctx.iocAliases?.[lower];
    if (alias !== undefined) aliasIds.add(alias);
  }
  const candidates = lowered.size
    ? await store.mergeIocCandidates(caseId, [...lowered], [...aliasIds])
    : { rows: [], nextSeq: 1 };
  const citing = await store.mergeIocsCiting(caseId, absorbedIds);
  const byRow = new Map<number, MergeStoredRow>();
  for (const r of [...candidates.rows, ...citing]) byRow.set(r.rowId, r);
  const stored = [...byRow.values()].sort((a, b) => a.ordinal - b.ordinal);
  const result = mergeIocs(
    stored.map((r) => JSON.parse(r.payload) as IOC),
    delta,
    ctx,
    overview.iocExcludeRules,
    candidates.nextSeq,
  );
  return { stored, result };
}
