import { isDeepStrictEqual } from "node:util";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import type { ImportBaseline } from "./importBaseline.js";
import type { JournalEntry } from "./forensicRows.js";
import type { StateStore } from "./stateStore.js";
import {
  computeUndoDelta,
  type KeyedArrayDelta,
  type RestoredRow,
  type StateDelta,
} from "./importUndoDelta.js";
import type { ImportCheckpoint } from "./importUndo.js";

/**
 * An import's undo checkpoint from row sets (#1874), not from a full copy of the case held since the
 * import took it. The result is the StateDelta computeUndoDelta(before, after) would build:
 *
 *  - the small fields and the IOCs come from computeUndoDelta over the two overviews (the baseline's
 *    and the current one), which are not large;
 *  - the forensic timeline's delta is built from the ids before and after, and from the import
 *    journal: the stored image of every row the import changed or removed, captured by the case
 *    database the first time the row was written while the import held the case. A journaled row
 *    whose current content equals its image counts as unchanged, as deep equality did before.
 *
 * When the ids are not unique (before or after), computeUndoDelta stores the whole timeline, so the
 * before-timeline is rebuilt from the journal plus the untouched rows and handed to it — the one
 * case that still reads the whole case. Returns null when the journal is gone (the section ended)
 * or does not account for a removed row: then no honest checkpoint can be built.
 */
export async function baselineCheckpoint(
  store: StateStore,
  baseline: ImportBaseline,
  label: string,
  at: string,
): Promise<ImportCheckpoint | null> {
  const caseId = baseline.caseId;
  const journal: JournalEntry[] | null = baseline.empty
    ? []
    : baseline.journalToken
      ? await store.readImportJournal(caseId, baseline.journalToken, baseline.journalFence)
      : null;
  if (!journal) return null;
  const before = baseline.outline;
  const after = await store.forensicOutline(caseId, false);
  const afterOverview = await store.loadOverview(caseId);
  const counts = {
    events: before.ids.length,
    iocs: baseline.overview.iocs?.length ?? 0,
    findings: baseline.overview.findings?.length ?? 0,
  };
  const baseRows = new Set(before.rowIds);
  const images = new Map(journal.filter((j) => baseRows.has(j.rowId)).map((j) => [j.rowId, j.event]));
  if (!uniqueIds(before.ids) || !uniqueIds(after.ids)) {
    const target = await rebuildBefore(store, baseline, images);
    if (!target) return null;
    const delta = computeUndoDelta(target, await store.load(caseId));
    return { label, at, delta, counts };
  }
  const keyed = await forensicDelta(
    store,
    caseId,
    before.ids as string[],
    after.ids as string[],
    before.rowIds,
    images,
  );
  if (!keyed) return null;
  const delta: StateDelta = computeUndoDelta(
    { ...baseline.overview, forensicTimeline: [] },
    { ...afterOverview, forensicTimeline: [] },
  );
  delta.keyed.forensicTimeline = keyed;
  return { label, at, delta, counts };
}

const uniqueIds = (ids: readonly (string | null)[]): boolean =>
  ids.every((id) => typeof id === "string") && new Set(ids).size === ids.length;

async function forensicDelta(
  store: StateStore,
  caseId: string,
  beforeIds: string[],
  afterIds: string[],
  beforeRowIds: number[],
  images: Map<number, ForensicEvent>,
): Promise<KeyedArrayDelta | null> {
  const afterSet = new Set(afterIds);
  const imageById = new Map<string, ForensicEvent>();
  beforeIds.forEach((id, i) => {
    const image = images.get(beforeRowIds[i]);
    if (image) imageById.set(id, image);
  });
  // A row gone without a journaled image cannot be put back: refuse rather than build a lossy undo.
  if (beforeIds.some((id) => !afterSet.has(id) && !imageById.has(id))) return null;
  const current = new Map(
    (await store.forensicRowsById(caseId, [...imageById.keys()])).map((r) => [r.event.id, r.event]),
  );
  const changed = new Set(
    [...imageById].filter(([id, image]) => !isDeepStrictEqual(current.get(id), image)).map(([id]) => id),
  );
  const beforeSet = new Set(beforeIds);
  const restore: RestoredRow[] = [];
  beforeIds.forEach((id, i) => {
    if (changed.has(id))
      restore.push({ i, after: i === 0 ? null : beforeIds[i - 1], row: imageById.get(id) });
  });
  const added = afterIds.filter((id) => !beforeSet.has(id));
  const inTarget = beforeIds.filter((id) => !changed.has(id));
  const inFrom = afterIds.filter((id) => beforeSet.has(id) && !changed.has(id));
  const sameOrder = inTarget.length === inFrom.length && inTarget.every((id, k) => id === inFrom[k]);
  return sameOrder ? { added, restore } : { added, restore, order: [...beforeIds] };
}

// The before-timeline, row by row: the journaled image where the import changed the row, the row as
// it is now where it did not (an unjournaled row was never written, so it is unchanged).
async function rebuildBefore(
  store: StateStore,
  baseline: ImportBaseline,
  images: Map<number, ForensicEvent>,
): Promise<InvestigationState | null> {
  const want = baseline.outline.rowIds.filter((id) => !images.has(id));
  const current = new Map(
    (await store.forensicRowsByRowId(baseline.caseId, want)).map((r) => [r.rowId, r.event]),
  );
  const rows: ForensicEvent[] = [];
  for (const rowId of baseline.outline.rowIds) {
    const row = images.get(rowId) ?? current.get(rowId);
    if (!row) return null;
    rows.push(row);
  }
  return { ...baseline.overview, forensicTimeline: rows };
}
