import { isDeepStrictEqual } from "node:util";
import type { InvestigationState } from "./stateTypes.js";

// #1874 item 3: an import's undo checkpoint is an INVERSE DELTA, not a full copy of the case. At 70k
// events one full-state checkpoint was 514 MB, and a case above ~73k events could not be serialized
// at all (V8's maximum string length). The delta holds only what the import touched in the two
// large collections, plus the before-value of every small field.
//
// What a delta holds (see computeUndoDelta):
//  - `keyed`: the forensic timeline and the IOCs, diffed by row id. `added` is every id the import
//    added (undo removes them). `restore` is the pre-import image of every row the import changed or
//    removed, with its pre-import neighbour and index, so undo puts it back where it was. `order` is
//    the full pre-import id order, present only when the import reordered rows it did not touch.
//  - `fields`: the before-value of EVERY other top-level field (findings, MITRE, narrative, host
//    renames, …), stored even when the import left it unchanged. The synthesis that runs after an
//    import rewrites these, and undo has always reverted that synthesis too.
//  - `absent`: top-level fields the pre-import state did not have; undo deletes them.
//
// THE RULE WHEN ANOTHER WRITER CHANGED THE CASE AFTER THE IMPORT (the old full-copy undo simply
// overwrote everything):
//  - small fields go back to their pre-import values, as before;
//  - a row or IOC the import ADDED is removed, even if edited since;
//  - a row or IOC the import CHANGED or REMOVED is put back exactly as it was before the import;
//  - a row or IOC the import did NOT touch is left as it is now — a later analyst edit, an
//    enrichment result, or a row another writer added after the import survives the undo. A row
//    added later stays next to the row it followed.
// Nothing references are rewritten: a surviving row may name a finding the undo took back, the same
// dangling reference every re-synthesis can leave and every reader already tolerates.
// When nothing else changed the case, applyUndoDelta(after, computeUndoDelta(before, after)) is
// deep-equal to `before`, including the order of both collections.

/** Top-level fields diffed row by row. Everything else is stored whole. */
export const KEYED_FIELDS = ["forensicTimeline", "iocs"] as const;

export interface RestoredRow {
  /** Index in the target list. Used only when `after` is gone from the current list. */
  i: number;
  /** Id of the row that precedes this one in the target list; null for the first row. */
  after: string | null;
  row: unknown;
}

export interface KeyedArrayDelta {
  added: string[];
  restore: RestoredRow[]; // ascending by `i`
  order?: string[];
}

export interface StateDelta {
  v: 1;
  fields: Record<string, unknown>;
  absent: string[];
  keyed: Record<string, KeyedArrayDelta>;
}

type Row = { id: string };
type Loose = Record<string, unknown>;

// Rows are diffable only when every one has a string id and no id repeats; otherwise the field is
// stored whole, which is always correct, only larger.
function idsOf(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  const seen = new Set<string>();
  for (const r of v) {
    const id = r && typeof r === "object" ? (r as Loose).id : undefined;
    if (typeof id !== "string" || seen.has(id)) return null;
    seen.add(id);
  }
  return [...seen];
}

function diffKeyed(target: Row[], from: Row[]): KeyedArrayDelta {
  const fromById = new Map(from.map((r) => [r.id, r]));
  const targetIds = new Set<string>();
  const unchanged = new Set<string>();
  const restore: RestoredRow[] = [];
  target.forEach((row, i) => {
    targetIds.add(row.id);
    const cur = fromById.get(row.id);
    if (cur !== undefined && isDeepStrictEqual(cur, row)) unchanged.add(row.id);
    else restore.push({ i, after: i === 0 ? null : target[i - 1].id, row });
  });
  const added = from.filter((r) => !targetIds.has(r.id)).map((r) => r.id);
  const inTarget = target.filter((r) => unchanged.has(r.id));
  const inFrom = from.filter((r) => unchanged.has(r.id));
  const sameOrder = inTarget.every((r, k) => r.id === inFrom[k].id);
  return sameOrder ? { added, restore } : { added, restore, order: target.map((r) => r.id) };
}

/**
 * The delta that turns `from` back into `target`. An import checkpoint is
 * computeUndoDelta(stateBefore, stateAfter); the redo entry an undo pushes is
 * computeUndoDelta(current, restored). Pure: neither input is modified, and the delta shares row
 * objects with `target` (it is serialized before anything could mutate them).
 */
export function computeUndoDelta(target: InvestigationState, from: InvestigationState): StateDelta {
  const t = target as unknown as Loose;
  const f = from as unknown as Loose;
  const delta: StateDelta = { v: 1, fields: {}, absent: [], keyed: {} };
  for (const key of new Set([...Object.keys(t), ...Object.keys(f)])) {
    const keyed = (KEYED_FIELDS as readonly string[]).includes(key);
    if (keyed && idsOf(t[key]) && idsOf(f[key])) {
      delta.keyed[key] = diffKeyed(t[key] as Row[], f[key] as Row[]);
    } else if (Object.hasOwn(t, key) && t[key] !== undefined) {
      delta.fields[key] = t[key];
    } else {
      delta.absent.push(key);
    }
  }
  return delta;
}

// Target order is known in full: lay it out, then put each foreign row (one the delta never saw)
// right after the row it follows in the current list.
function applyWithOrder(cur: Row[], d: KeyedArrayDelta, order: string[]): Row[] {
  const restored = new Map(d.restore.map((r) => [(r.row as Row).id, r.row as Row]));
  const dropped = new Set([...d.added, ...restored.keys()]);
  const orderSet = new Set(order);
  const curById = new Map(cur.map((r) => [r.id, r]));
  const foreignAfter = new Map<string | null, Row[]>();
  let last: string | null = null;
  for (const r of cur) {
    // A restored row is still a target row, so it anchors the foreign rows that follow it.
    if (orderSet.has(r.id)) last = r.id;
    else if (!dropped.has(r.id)) {
      const list = foreignAfter.get(last);
      if (list) list.push(r);
      else foreignAfter.set(last, [r]);
    }
  }
  const out: Row[] = [...(foreignAfter.get(null) ?? [])];
  for (const id of order) {
    const row = restored.get(id) ?? (dropped.has(id) ? undefined : curById.get(id));
    if (!row) continue;
    out.push(row, ...(foreignAfter.get(id) ?? []));
  }
  return out;
}

// Survivors keep their current order; each restored row goes back right after its target
// neighbour. Processing ascending by target index makes that exact: a row's neighbour is either a
// survivor or a restored row placed before it.
function applyByAnchor(cur: Row[], d: KeyedArrayDelta): Row[] {
  const restoredIds = new Set(d.restore.map((r) => (r.row as Row).id));
  const dropped = new Set([...d.added, ...restoredIds]);
  const survivors = cur.filter((r) => !dropped.has(r.id));
  const next = new Map<string | null, RestoredRow>(d.restore.map((r) => [r.after, r]));
  const out: Row[] = [];
  const placed = new Set<RestoredRow>();
  const chain = (id: string | null): void => {
    for (let r = next.get(id); r && !placed.has(r); r = next.get((r.row as Row).id)) {
      placed.add(r);
      out.push(r.row as Row);
    }
  };
  chain(null);
  for (const row of survivors) {
    out.push(row);
    chain(row.id);
  }
  // A neighbour another writer deleted since: fall back to the row's old index.
  for (const r of d.restore) {
    if (placed.has(r)) continue;
    placed.add(r);
    out.splice(Math.min(r.i, out.length), 0, r.row as Row);
    chain((r.row as Row).id);
  }
  return out;
}

/** Apply a delta to the CURRENT state. Pure: returns a new state object. */
export function applyUndoDelta(current: InvestigationState, delta: StateDelta): InvestigationState {
  const next: Loose = { ...(current as unknown as Loose) };
  for (const key of delta.absent) delete next[key];
  for (const [key, value] of Object.entries(delta.fields)) next[key] = value;
  for (const [key, d] of Object.entries(delta.keyed)) {
    const cur = Array.isArray(next[key]) ? (next[key] as Row[]) : [];
    next[key] = d.order ? applyWithOrder(cur, d, d.order) : applyByAnchor(cur, d);
  }
  return next as unknown as InvestigationState;
}

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");

function isKeyedDelta(v: unknown): v is KeyedArrayDelta {
  if (!v || typeof v !== "object") return false;
  const d = v as Loose;
  if (!isStringArray(d.added) || !Array.isArray(d.restore)) return false;
  if (d.order !== undefined && !isStringArray(d.order)) return false;
  return d.restore.every((r: unknown) => {
    const o = r && typeof r === "object" ? (r as Loose) : null;
    const row = o?.row && typeof o.row === "object" ? (o.row as Loose) : null;
    return (
      !!o &&
      Number.isSafeInteger(o.i) &&
      (o.after === null || typeof o.after === "string") &&
      typeof row?.id === "string"
    );
  });
}

/** Validates a delta read back from the stack file (our own output, but maybe truncated/edited). */
export function isStateDelta(v: unknown): v is StateDelta {
  if (!v || typeof v !== "object") return false;
  const d = v as Loose;
  if (d.v !== 1 || !d.fields || typeof d.fields !== "object" || Array.isArray(d.fields)) return false;
  if (!isStringArray(d.absent) || !d.keyed || typeof d.keyed !== "object") return false;
  return Object.values(d.keyed as Loose).every(isKeyedDelta);
}
