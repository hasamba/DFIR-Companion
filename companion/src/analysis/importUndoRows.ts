import { isDeepStrictEqual } from "node:util";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { iocJournalRef, type ImportBaseline } from "./importBaseline.js";
import type { IocJournalRef } from "./iocJournal.js";
import { iocUndoFromJournal } from "./iocJournalDiff.js";
import type { JournalEntry } from "./forensicRows.js";
import type { StateStore } from "./stateStore.js";
import {
  computeUndoDelta,
  type KeyedArrayDelta,
  type RestoredRow,
  type StateDelta,
} from "./importUndoDelta.js";
import type { ImportCheckpoint } from "./importUndo.js";
import { isManualId } from "./manualId.js";

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
  // #1874: with an IOC outline the IOCs come from the IOC journal, not from two full lists.
  const iocRef = iocJournalRef(baseline);
  const afterOverview = iocRef
    ? await store.loadOverviewWithoutIocs(caseId)
    : await store.loadOverview(caseId);
  const counts = {
    events: before.ids.length,
    iocs: iocRef ? iocRef.before.ids.length : (baseline.overview.iocs?.length ?? 0),
    findings: baseline.overview.findings?.length ?? 0,
  };
  const baseRows = new Set(before.rowIds);
  const images = new Map(journal.filter((j) => baseRows.has(j.rowId)).map((j) => [j.rowId, j.event]));
  if (!uniqueIds(before.ids) || !uniqueIds(after.ids)) {
    const target = await rebuildBefore(store, baseline, images);
    if (!target) return null;
    if (iocRef) {
      const lists = await store.iocJournal.fullLists(iocRef, "forensic ids are not unique");
      if (!lists) return null;
      target.iocs = lists.before;
    }
    const current = await store.load(caseId);
    const delta = computeUndoDelta(keepManualRows(target, current), current);
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
  if (iocRef && !(await putIocDelta(store, iocRef, delta))) return null;
  return { label, at, delta, counts };
}

// The IOC part of the delta, from the IOC journal (analysis/iocJournal.ts). When the IOC ids are not
// unique strings, computeUndoDelta over the two whole lists decides, as it did before. False when the
// journal cannot account for the import.
async function putIocDelta(store: StateStore, ref: IocJournalRef, delta: StateDelta): Promise<boolean> {
  const keyed = await iocUndoFromJournal(store.iocJournal, ref);
  if (!keyed) return false;
  if (keyed !== "whole") {
    delta.keyed.iocs = keyed;
    return true;
  }
  const lists = await store.iocJournal.fullLists(ref, "IOC ids are not unique");
  if (!lists) return false;
  const part = computeUndoDelta(
    { iocs: lists.before } as unknown as InvestigationState,
    { iocs: lists.after } as unknown as InvestigationState,
  );
  delete delta.keyed.iocs;
  delete delta.fields.iocs;
  if (part.keyed.iocs) delta.keyed.iocs = part.keyed.iocs;
  if (Object.hasOwn(part.fields, "iocs")) delta.fields.iocs = part.fields.iocs;
  return true;
}

// The whole-timeline fallback restores the target as given, so the manual events added since the
// baseline join it (#1904) — each after the nearest row before it that the target holds, or first — to survive the undo.
function keepManualRows(target: InvestigationState, current: InvestigationState): InvestigationState {
  const had = new Set(target.forensicTimeline.map((e) => e.id));
  const rows = [...target.forensicTimeline];
  current.forensicTimeline.forEach((e, i) => {
    if (had.has(e.id) || !isManualId(e.id)) return;
    let prev = -1;
    for (let j = i - 1; j >= 0 && prev < 0; j--) {
      const id = current.forensicTimeline[j].id;
      if (had.has(id)) prev = rows.map((r) => r.id).lastIndexOf(id);
    }
    rows.splice(prev + 1, 0, e);
    had.add(e.id);
  });
  return { ...target, forensicTimeline: rows };
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
  // #1904: a manual event the analyst added while the import held the case is not the import's to
  // undo. Left out of `added`, it is a row the delta never saw, and undo keeps it where it is.
  const added = afterIds.filter((id) => !beforeSet.has(id) && !isManualId(id));
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
