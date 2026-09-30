import { outlineEvents, type ForensicRowStore, type JournalEntry } from "../analysis/forensicRows.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import { diffTimeline, type DiffEvent, type TimelineDiff } from "../analysis/timelineDiff.js";
import {
  diffKeyDigest,
  diffKeyOfFields,
  hasRowFacts,
  rowFactsStamp,
  type FactsStore,
} from "../analysis/rowFacts.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";

/**
 * The settle's post-demote timeline diff against the import's baseline (#1874) — diffTimeline over the
 * whole timeline before and after, computed from the rows that can change it.
 *
 * diffTimeline keys every row by normalized time + description and reports the keys present on one
 * side only, each shown as its first row in timeline order. A row that nothing wrote while the import
 * held the case has the same key before and after, so a key such a row holds is on both sides and in
 * neither list. Every other row is one of: a row the import section inserted (after only), a baseline
 * row it changed or removed (its journaled image before, its current row after if still present), or
 * a baseline row whose row facts were unknown at capture (untouched, read now). Their keys are the
 * only keys that can differ; for each, the row facts' key index says whether an untouched row holds it
 * (each hit is checked against the row's real fields), and the rest is decided — presence, first row,
 * order — by those rows and their positions in the two outlines.
 *
 * A legacy full-state baseline (it carries the keyed outline) and a store without row facts keep the
 * full diff. So does a stamp that stopped matching mid-import, from the untouched rows' current keys.
 */
export async function settleTimelineDiff(
  store: ForensicRowStore,
  caseId: string,
  baseline: ImportBaseline,
): Promise<{ timelineDiff: TimelineDiff; forensicCount: number }> {
  if (baseline.unfresh === undefined || !hasRowFacts(store)) {
    const outline = await store.forensicOutline(caseId);
    const timelineDiff = diffTimeline(outlineEvents(baseline.outline), outlineEvents(outline));
    return { timelineDiff, forensicCount: outline.ids.length };
  }
  const after = await store.forensicOutline(caseId, false);
  const journal = baseline.empty
    ? []
    : baseline.journalToken && store.readImportJournal
      ? await store.readImportJournal(caseId, baseline.journalToken, baseline.journalFence)
      : null;
  // Without the journal the rows the import changed or removed have lost their old keys: no diff
  // can be shown honestly, so the settle fails rather than report a partial one.
  if (!journal) throw new ImportJournalLostError(caseId);
  const timelineDiff = await diffFromRows(store, caseId, baseline, after.rowIds, journal);
  return { timelineDiff, forensicCount: after.ids.length };
}

type Row = { timestamp: unknown; description: unknown; severity: unknown };
type Entry = { pos: number; row: Row; key: string };

// SQL NULL and a JSON null read as a missing field, as outlineEvents maps them.
const field = (v: unknown): unknown => (v === null ? undefined : v);
const rowOf = (f: readonly unknown[]): Row => ({
  timestamp: field(f[0]),
  description: field(f[1]),
  severity: field(f[2]),
});
const keyOfRow = (row: Row): string => diffKeyOfFields(row.timestamp, row.description);
const entry = (pos: number, row: Row): Entry => ({ pos, row, key: keyOfRow(row) });
const shown = (row: Row): DiffEvent => ({
  timestamp: row.timestamp as string,
  description: row.description as string,
  severity: row.severity as ForensicEvent["severity"],
});

async function diffFromRows(
  store: ForensicRowStore & FactsStore,
  caseId: string,
  baseline: ImportBaseline,
  afterRowIds: readonly number[],
  journal: readonly JournalEntry[],
): Promise<TimelineDiff> {
  const beforePos = new Map(baseline.outline.rowIds.map((rowId, i) => [rowId, i]));
  const afterPos = new Map(afterRowIds.map((rowId, i) => [rowId, i]));
  // Journaled baseline rows, whatever their row id holds now (a removed row's id can be reused).
  const images = new Map<number, ForensicEvent>();
  for (const j of journal) if (beforePos.has(j.rowId) && !images.has(j.rowId)) images.set(j.rowId, j.event);
  const unfresh = (baseline.unfresh ?? baseline.outline.rowIds).filter(
    (rowId) => beforePos.has(rowId) && !images.has(rowId) && afterPos.has(rowId),
  );
  const inserted = afterRowIds.filter((rowId) => !beforePos.has(rowId));
  const current = [...inserted, ...[...images.keys()].filter((rowId) => afterPos.has(rowId)), ...unfresh];
  const fields = new Map(
    (await store.forensicKeyFields(caseId, current)).map((r) => [r.rowId, rowOf(r.fields)]),
  );
  const before: Entry[] = [...images].map(([rowId, e]) =>
    entry(beforePos.get(rowId)!, rowOf([e.timestamp, e.description, e.severity])),
  );
  for (const rowId of unfresh) {
    const row = fields.get(rowId);
    if (row) before.push(entry(beforePos.get(rowId)!, row));
  }
  const after: Entry[] = current.flatMap((rowId) => {
    const row = fields.get(rowId);
    return row ? [entry(afterPos.get(rowId)!, row)] : [];
  });
  const explicit = [...new Set([...inserted, ...images.keys(), ...unfresh])];
  const held = await heldByOthers(store, caseId, candidateKeys(before, after), explicit);
  return diffEntries(before, after, held);
}

const candidateKeys = (before: readonly Entry[], after: readonly Entry[]): Set<string> =>
  new Set([...before, ...after].map((e) => e.key).filter((key) => key !== "|"));

// The candidate keys some row outside `explicit` holds. Those rows were not written since capture and
// their facts were known then, so the key index answers; a stamp that no longer matches reads them all.
async function heldByOthers(
  store: ForensicRowStore & FactsStore,
  caseId: string,
  candidates: Set<string>,
  explicit: readonly number[],
): Promise<Set<string>> {
  if (!candidates.size) return new Set();
  const digests = [...candidates].map(diffKeyDigest);
  const holders = await store.factsKeyHolders(caseId, rowFactsStamp(), digests, explicit);
  const held = new Set<string>();
  if (holders) {
    for (const h of holders) {
      const key = keyOfRow(rowOf(h.fields));
      if (candidates.has(key)) held.add(key);
    }
    return held;
  }
  const outline = await store.forensicOutline(caseId);
  const skip = new Set(explicit);
  outline.rowIds.forEach((rowId, i) => {
    if (skip.has(rowId)) return;
    const key = diffKeyOfFields(field(outline.timestamps[i]), field(outline.descriptions[i]));
    if (candidates.has(key)) held.add(key);
  });
  return held;
}

// diffTimeline's byKey + comparison over the rows that can differ: first row per key in timeline
// order, keys a row outside them holds dropped (they are on both sides), "|" skipped.
function diffEntries(before: readonly Entry[], after: readonly Entry[], held: Set<string>): TimelineDiff {
  const firstByKey = (entries: readonly Entry[]): Map<string, Entry> => {
    const map = new Map<string, Entry>();
    for (const e of [...entries].sort((x, y) => x.pos - y.pos)) {
      if (e.key === "|" || held.has(e.key) || map.has(e.key)) continue;
      map.set(e.key, e);
    }
    return map;
  };
  const b = firstByKey(before);
  const a = firstByKey(after);
  return {
    added: [...a].filter(([key]) => !b.has(key)).map(([, e]) => shown(e.row)),
    removed: [...b].filter(([key]) => !a.has(key)).map(([, e]) => shown(e.row)),
  };
}

/** The import journal went away before the settle read it (the case database was replaced mid-import). */
export class ImportJournalLostError extends Error {
  constructor(caseId: string) {
    super(
      `the import journal of case ${caseId} is gone (was the case database replaced during the import?): ` +
        "this import's changed and removed rows cannot be counted, and it cannot be undone",
    );
    this.name = "ImportJournalLostError";
  }
}
