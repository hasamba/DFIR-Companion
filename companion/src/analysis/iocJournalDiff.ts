import { isDeepStrictEqual } from "node:util";
import { diffIocs, type DiffIoc, type IocsDiff } from "./iocsDiff.js";
import type { KeyedArrayDelta, RestoredRow } from "./importUndoDelta.js";
import type { IocJournalReader, IocJournalRef, IocRow } from "./iocJournal.js";

// The settle's IOC diff and the undo checkpoint's IOC delta, from the IOC journal (#1874). The reads
// are analysis/iocJournal.ts's; this is the arithmetic that makes them equal the whole-list results.

const valueOf = (row: IocRow | undefined): unknown =>
  row?.payload && typeof row.payload === "object" ? (row.payload as { value?: unknown }).value : undefined;

type Seen = Map<unknown, { pos: number; ioc: DiffIoc }>;

// First row (lowest position) per value, as diffIocs's byValue keeps the first occurrence.
function firstByValue(entries: { pos: number; row: IocRow }[]): Seen {
  const out: Seen = new Map();
  for (const { pos, row } of entries.sort((a, b) => a.pos - b.pos)) {
    const value = valueOf(row);
    if (!value || out.has(value)) continue;
    const ioc = row.payload as { value: string; type: string };
    out.set(value, { pos, ioc: { value: ioc.value, type: ioc.type } });
  }
  return out;
}

const onlyIn = (side: Seen, other: Seen, held: Set<unknown>): DiffIoc[] =>
  [...side]
    .filter(([value]) => !other.has(value) && !held.has(value))
    .sort((a, b) => a[1].pos - b[1].pos)
    .map(([, e]) => e.ioc);

/**
 * diffIocs(before, after) over the whole IOC lists, from the journal (#1874).
 *
 * diffIocs reports the values present on one side only, each as its first IOC. An IOC row nothing
 * wrote while the journal was armed is the same before and after, so a value such a row holds is on
 * both sides and in neither list. Every other row is journaled (its image before, its current row
 * after if still present) or new (after only); their values are the only ones that can differ, and
 * for those, presence, the first IOC and the order come from these rows and their list positions.
 *
 * An object or array value anywhere breaks that argument (diffIocs compares it by identity, so it is
 * never equal to itself across two loads): then the whole lists are read. Null when the journal is gone.
 */
export async function iocsDiffFromJournal(
  reader: IocJournalReader,
  ref: IocJournalRef,
): Promise<IocsDiff | null> {
  const got = await reader.diffInputs(ref);
  if (!got) return null;
  if (ref.before.objects > 0 || got.after.objects > 0) {
    const lists = await reader.fullLists(ref, "an IOC value is an object or array");
    return lists ? diffIocs(lists.before, lists.after) : null;
  }
  const beforePos = new Map(ref.before.rowIds.map((rowId, i) => [rowId, i]));
  const afterPos = new Map(got.after.rowIds.map((rowId, i) => [rowId, i]));
  const before = firstByValue(got.images.map((row) => ({ pos: beforePos.get(row.rowId) ?? -1, row })));
  const after = firstByValue(got.current.map((row) => ({ pos: afterPos.get(row.rowId) ?? -1, row })));
  const held = new Set(got.holders);
  return { added: onlyIn(after, before, held), removed: onlyIn(before, after, held) };
}

const uniqueStrings = (ids: readonly unknown[]): ids is string[] =>
  ids.every((id) => typeof id === "string") && new Set(ids).size === ids.length;

/**
 * The IOC part of an import's undo delta from the journal (#1874) — what computeUndoDelta's keyed diff
 * gives for the whole lists: `added` = ids after and not before, `restore` = each baseline IOC whose
 * current row with that id is not deep-equal to its pre-import image (an IOC nothing wrote is
 * unchanged), `order` when the unchanged IOCs moved. Returns "whole" when the ids before or after are
 * not unique strings (computeUndoDelta then stores the whole list), null when the journal is gone or a
 * removed IOC left no image.
 */
export async function iocUndoFromJournal(
  reader: IocJournalReader,
  ref: IocJournalRef,
): Promise<KeyedArrayDelta | "whole" | null> {
  const got = await reader.undoInputs(ref);
  if (!got) return null;
  const beforeIds = ref.before.ids;
  const afterIds = got.after.ids;
  if (!uniqueStrings(beforeIds) || !uniqueStrings(afterIds)) return "whole";
  const beforeRow = new Map(ref.before.rowIds.map((rowId, i) => [rowId, beforeIds[i]]));
  const imageById = new Map<string, unknown>();
  for (const image of got.images) {
    const id = beforeRow.get(image.rowId);
    if (id !== undefined) imageById.set(id, image.payload);
  }
  const afterSet = new Set(afterIds);
  if (beforeIds.some((id) => !afterSet.has(id) && !imageById.has(id))) return null;
  const current = new Map(
    got.current.filter((r) => imageById.has(r.payload?.id)).map((r) => [r.payload.id, r.payload]),
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
