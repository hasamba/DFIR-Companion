import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { applyUndoDelta, computeUndoDelta, isStateDelta, type StateDelta } from "./importUndoDelta.js";
import { carryHostRenames, renameLedgerChanged, type RenameLedger } from "./hostRenameCarry.js";

// Per-case UNDO / REDO of imports (#76). A single import can flood the dashboard — it grows the
// forensic timeline + IOCs, and the synthesis that follows rewrites the findings / MITRE / attacker
// path. Undoing an import takes back the events, the IOCs, AND the findings it produced, with no AI
// call (we have the exact prior conclusions — re-synthesizing would cost money and might not
// reproduce them). Since #1874 a checkpoint is an inverse DELTA (importUndoDelta.ts, which also
// documents what happens when another writer changed the case after the import); a stack file
// written before that holds full-state checkpoints, which still undo and redo verbatim.
// Stored in a side file (`state/import-undo-stack.json`), NOT part of InvestigationState itself. A
// machine-local convenience, intentionally excluded from the portable case snapshot.

export interface CheckpointCounts {
  events: number;
  iocs: number;
  findings: number;
}

/**
 * Super-timeline rows an action rewrote in place (#2220: a Sigma re-grade). `restore` is what this
 * step writes back to the super-timeline store, by id; `reapply` is what the mirror step writes.
 */
export interface SuperRowsUndo {
  restore: ForensicEvent[];
  reapply: ForensicEvent[];
}

export interface ImportCheckpoint {
  label: string; // what this checkpoint precedes, e.g. "thor (0003_thor.json)"
  at: string; // ISO time the checkpoint was captured
  // Exactly one of the two below. `state`: a legacy full copy of the state to restore (written
  // before #1874, still honoured). `delta`: what turns the state at the top of the stack back into
  // the state to restore, with that state's `counts` for the dashboard summary.
  state?: InvestigationState;
  delta?: StateDelta;
  counts?: CheckpointCounts;
  superRows?: SuperRowsUndo;
}

/** The mirror entry of `top`: the same super rows, the pair swapped (none when `top` has none). */
function mirrorOf(top: ImportCheckpoint, entry: ImportCheckpoint): ImportCheckpoint {
  const s = top.superRows;
  return s ? { ...entry, superRows: { restore: s.reapply, reapply: s.restore } } : entry;
}

const countsOf = (s: InvestigationState): CheckpointCounts => ({
  events: s.forensicTimeline?.length ?? 0,
  iocs: s.iocs?.length ?? 0,
  findings: s.findings?.length ?? 0,
});

/** A checkpoint that turns `from` back into `target` — the only way this module builds one. */
export function deltaCheckpoint(
  label: string,
  at: string,
  target: InvestigationState,
  from: InvestigationState,
): ImportCheckpoint {
  return { label, at, delta: computeUndoDelta(target, from), counts: countsOf(target) };
}

function restoreOf(c: ImportCheckpoint, current: InvestigationState): InvestigationState {
  if (c.state) return c.state;
  if (c.delta) return applyUndoDelta(current, c.delta);
  throw new Error("import undo checkpoint holds neither a state nor a delta");
}

export interface ImportUndoStack {
  undo: ImportCheckpoint[]; // pre-import snapshots, oldest -> newest (the top to undo is last)
  redo: ImportCheckpoint[]; // states that were rolled back, oldest -> newest (top to redo is last)
}

// Default number of undo levels kept. The issue asks for "multiple undo's and redo's"; each level
// holds what one import changed, so the depth is bounded (override via DFIR_IMPORT_UNDO_DEPTH).
export const DEFAULT_UNDO_DEPTH = 10;

// Depth alone doesn't bound the file's actual size: 10 full-state snapshots of a case whose
// timeline has grown into the tens-of-thousands of events is tens-to-hundreds of MB "by design".
// A large bulk import (many files in quick succession) can balloon the undo stack into the
// hundreds of MB and, combined with every checkpoint re-serializing the whole growing stack,
// contribute to an OOM. So checkpoints are ALSO capped by aggregate serialized size, evicting the
// oldest first — override via DFIR_UNDO_MAX_MB. 200MB keeps the stack far below multi-GB heap
// budgets while still giving a useful amount of undo history for small-to-medium cases.
export const DEFAULT_UNDO_MAX_BYTES = 200 * 1024 * 1024;

// Read DFIR_UNDO_MAX_MB (megabytes) from the environment; falls back to DEFAULT_UNDO_MAX_BYTES on
// an unset, zero, negative, or unparseable value (mirrors atomicWriteRetries()'s parsing).
export function undoMaxBytesFromEnv(): number {
  const n = Number(process.env.DFIR_UNDO_MAX_MB);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) * 1024 * 1024 : DEFAULT_UNDO_MAX_BYTES;
}

export function emptyUndoStack(): ImportUndoStack {
  return { undo: [], redo: [] };
}

// --- Size measurement (#qa-kimi A). The budget is measured against the exact bytes the file
// holds: each checkpoint is written as its own compact JSON entry, and the entry that was measured
// is the entry that is written. Two per-object caches keep a push from serializing anything twice:
//  - `encoded`: the compact UTF-8 entry, made at most once per checkpoint object and reused by save().
//  - `knownBytes`: an entry's size read from the file's own `bytes` index, so the checkpoints a push
//    loads from disk are measured without re-serializing them.
// Both are WeakMaps, so an entry dies with its checkpoint object (the stack is reloaded per mutate).
// Checkpoints are never mutated after creation, so a cached entry cannot go stale.
const encoded = new WeakMap<ImportCheckpoint, Buffer>();
const knownBytes = new WeakMap<ImportCheckpoint, number>();

function encodeCheckpoint(c: ImportCheckpoint): Buffer {
  let buf = encoded.get(c);
  if (!buf) {
    buf = Buffer.from(JSON.stringify(c), "utf8");
    encoded.set(c, buf);
    knownBytes.set(c, buf.length);
  }
  return buf;
}

function checkpointBytes(c: ImportCheckpoint): number {
  return knownBytes.get(c) ?? encodeCheckpoint(c).length;
}

// Drop oldest-first entries until the list's serialized size (entries plus separating commas) fits
// `maxBytes`. The NEWEST entry is always kept, even if it alone exceeds the budget: undo then becomes
// single-level for a case that large rather than unavailable, and the file can exceed the budget
// by that one entry. A non-positive maxBytes disables the cap.
// The budget applies to each list on its own. A push clears redo, so after any import the whole file
// is the undo list plus a fixed envelope of a few hundred bytes. A run of undos with no import in
// between can hold a full undo list and a full redo list — up to twice the budget.
function capBySize(list: ImportCheckpoint[], maxBytes: number): ImportCheckpoint[] {
  if (!(maxBytes > 0) || list.length === 0) return list;
  const sizes = list.map(checkpointBytes);
  let total = sizes.reduce((a, b) => a + b, 0) + (list.length - 1);
  let start = 0;
  while (total > maxBytes && start < list.length - 1) {
    total -= sizes[start] + 1;
    start++;
  }
  return start === 0 ? list : list.slice(start);
}

// Push a PRE-import checkpoint onto the undo stack. A new import invalidates the redo history
// (standard undo/redo semantics — you can't redo past a fresh branch). Caps the undo depth AND
// aggregate byte size, dropping the oldest checkpoints first.
export function pushCheckpoint(
  stack: ImportUndoStack,
  checkpoint: ImportCheckpoint,
  maxDepth: number = DEFAULT_UNDO_DEPTH,
  maxBytes: number = DEFAULT_UNDO_MAX_BYTES,
): ImportUndoStack {
  const depth = Math.max(1, Math.floor(maxDepth));
  let undo = [...stack.undo, checkpoint];
  if (undo.length > depth) undo = undo.slice(undo.length - depth);
  return { undo: capBySize(undo, maxBytes), redo: [] };
}

/** One undo or redo step: the new stack, the state to save, and the super rows to write (#2220). */
export interface UndoStepResult {
  stack: ImportUndoStack;
  restore: InvestigationState;
  superRows?: SuperRowsUndo;
}

// Undo the latest import: pop the top pre-import checkpoint to RESTORE, and push the CURRENT
// (post-import) state onto the redo stack so it can be re-applied. Returns null when there is
// nothing to undo. The redo entry inherits the popped checkpoint's label (redoing re-applies that
// same import). The redo stack is capped the same way the undo stack is — otherwise repeated
// undos with no intervening import grow it without bound. Pure — the caller writes `stack` and
// saves `restore` as the investigation state.
export function applyUndo(
  stack: ImportUndoStack,
  current: InvestigationState,
  at: string = new Date().toISOString(),
  maxDepth: number = DEFAULT_UNDO_DEPTH,
  maxBytes: number = DEFAULT_UNDO_MAX_BYTES,
): UndoStepResult | null {
  if (stack.undo.length === 0) return null;
  const top = stack.undo[stack.undo.length - 1];
  const restore = restoreOf(top, current);
  const redoEntry = mirrorOf(top, deltaCheckpoint(top.label, at, current, restore));
  const depth = Math.max(1, Math.floor(maxDepth));
  let redo = [...stack.redo, redoEntry];
  if (redo.length > depth) redo = redo.slice(redo.length - depth);
  return {
    stack: { undo: stack.undo.slice(0, -1), redo: capBySize(redo, maxBytes) },
    restore,
    ...(top.superRows ? { superRows: top.superRows } : {}),
  };
}

// Redo the most-recently-undone import: pop the top redo checkpoint to RESTORE, and push the
// current state back onto the undo stack. The mirror image of applyUndo (same depth+size cap on
// the undo stack it grows). Returns null when there is nothing to redo.
export function applyRedo(
  stack: ImportUndoStack,
  current: InvestigationState,
  at: string = new Date().toISOString(),
  maxDepth: number = DEFAULT_UNDO_DEPTH,
  maxBytes: number = DEFAULT_UNDO_MAX_BYTES,
): UndoStepResult | null {
  if (stack.redo.length === 0) return null;
  const top = stack.redo[stack.redo.length - 1];
  const restore = restoreOf(top, current);
  const undoEntry = mirrorOf(top, deltaCheckpoint(top.label, at, current, restore));
  const depth = Math.max(1, Math.floor(maxDepth));
  let undo = [...stack.undo, undoEntry];
  if (undo.length > depth) undo = undo.slice(undo.length - depth);
  return {
    stack: { undo: capBySize(undo, maxBytes), redo: stack.redo.slice(0, -1) },
    restore,
    ...(top.superRows ? { superRows: top.superRows } : {}),
  };
}

// --- Lightweight summary for the dashboard (the GET route returns this, not the raw snapshots,
// which can be megabytes). Just the labels/times + how big each checkpoint is. ------------------

export interface CheckpointSummary {
  label: string;
  at: string;
  events: number; // forensicTimeline length at that checkpoint
  iocs: number; // IOC count at that checkpoint
  findings: number; // findings count at that checkpoint
}

export interface UndoStackSummary {
  canUndo: boolean;
  canRedo: boolean;
  maxDepth: number;
  nextUndo: CheckpointSummary | null; // what "Undo" will roll back (top of the undo stack)
  nextRedo: CheckpointSummary | null; // what "Redo" will re-apply (top of the redo stack)
  undo: CheckpointSummary[]; // oldest -> newest
  redo: CheckpointSummary[];
}

const summarize = (c: ImportCheckpoint): CheckpointSummary => ({
  label: c.label,
  at: c.at,
  ...(c.state ? countsOf(c.state) : (c.counts ?? { events: 0, iocs: 0, findings: 0 })),
});

export function summarizeUndoStack(
  stack: ImportUndoStack,
  maxDepth: number = DEFAULT_UNDO_DEPTH,
): UndoStackSummary {
  const top = (a: ImportCheckpoint[]): ImportCheckpoint | undefined => a[a.length - 1];
  const u = top(stack.undo);
  const r = top(stack.redo);
  return {
    canUndo: stack.undo.length > 0,
    canRedo: stack.redo.length > 0,
    maxDepth,
    nextUndo: u ? summarize(u) : null,
    nextRedo: r ? summarize(r) : null,
    undo: stack.undo.map(summarize),
    redo: stack.redo.map(summarize),
  };
}

// Coerce a parsed JSON value into a valid stack. The file is our own output, but a truncated /
// partial write (or a hand-edit) must load as a clean stack rather than throw — mirrors
// StateStore's trust-our-own-data approach: the structure is validated here; a checkpoint with no
// usable `state` object and no valid `delta` is dropped (it could not be restored anyway).
// The file may carry a `bytes` index ({ undo: number[], redo: number[] }) — the size of each written
// entry, so a later push can measure the stack without re-serializing it. A legacy file (pretty-
// printed, no index) loads the same way; its entries are simply measured on the next push.
export function normalizeStack(raw: unknown): ImportUndoStack {
  const obj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const idx = obj.bytes && typeof obj.bytes === "object" ? (obj.bytes as Record<string, unknown>) : {};
  return { undo: normalizeList(obj.undo, idx.undo), redo: normalizeList(obj.redo, idx.redo) };
}

function normalizeCounts(v: unknown): CheckpointCounts {
  const o = v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  const n = (x: unknown): number => (Number.isSafeInteger(x) && (x as number) >= 0 ? (x as number) : 0);
  return { events: n(o.events), iocs: n(o.iocs), findings: n(o.findings) };
}

const isRowList = (v: unknown): v is ForensicEvent[] =>
  Array.isArray(v) &&
  v.every((e) => !!e && typeof e === "object" && typeof (e as { id?: unknown }).id === "string");

function normalizeSuperRows(v: unknown): SuperRowsUndo | undefined {
  if (!v || typeof v !== "object") return undefined;
  const o = v as Record<string, unknown>;
  return isRowList(o.restore) && isRowList(o.reapply)
    ? { restore: o.restore, reapply: o.reapply }
    : undefined;
}

function normalizeList(v: unknown, sizes: unknown): ImportCheckpoint[] {
  if (!Array.isArray(v)) return [];
  // Trust the index only when it lines up one-to-one with the entries it describes.
  const idx = Array.isArray(sizes) && sizes.length === v.length ? sizes : [];
  const out: ImportCheckpoint[] = [];
  v.forEach((item: unknown, i) => {
    if (!item || typeof item !== "object") return;
    const o = item as Record<string, unknown>;
    const label = typeof o.label === "string" ? o.label : "";
    const at = typeof o.at === "string" ? o.at : "";
    let checkpoint: ImportCheckpoint;
    if (o.state && typeof o.state === "object") {
      checkpoint = { label, at, state: o.state as InvestigationState };
    } else if (isStateDelta(o.delta)) {
      checkpoint = { label, at, delta: o.delta, counts: normalizeCounts(o.counts) };
    } else return; // unrestorable — drop it
    // Malformed super rows are dropped on their own: the checkpoint still restores the state.
    const superRows = normalizeSuperRows(o.superRows);
    if (superRows) checkpoint = { ...checkpoint, superRows };
    const n: unknown = idx[i];
    // A coerced label/at no longer matches the stored entry, so its size is re-measured instead.
    if (
      typeof n === "number" &&
      Number.isSafeInteger(n) &&
      n > 0 &&
      o.label === checkpoint.label &&
      o.at === checkpoint.at &&
      (o.superRows === undefined || superRows)
    )
      knownBytes.set(checkpoint, n);
    out.push(checkpoint);
  });
  return out;
}

// Serialize a stack as compact JSON: every checkpoint is one entry encoded exactly once (reusing the
// entry measured by capBySize), followed by the `bytes` index. Built as a Buffer so the file as a
// whole is not bound by V8's maximum string length — only a single checkpoint is.
export function encodeStack(stack: ImportUndoStack): Buffer {
  const undo = stack.undo.map(encodeCheckpoint);
  const redo = stack.redo.map(encodeCheckpoint);
  const comma = Buffer.from(",");
  const join = (bufs: Buffer[]): Buffer[] => bufs.flatMap((b, i) => (i === 0 ? [b] : [comma, b]));
  const index = JSON.stringify({ undo: undo.map((b) => b.length), redo: redo.map((b) => b.length) });
  return Buffer.concat([
    Buffer.from('{"undo":['),
    ...join(undo),
    Buffer.from('],"redo":['),
    ...join(redo),
    Buffer.from(`],"bytes":${index}}`),
  ]);
}

export class ImportUndoStore {
  // Per-case async mutex guarding the load->mutate->save critical section (see mutate()). Without
  // it, two concurrent load-modify-save calls on the same case's undo stack (e.g. overlapping
  // bulk-import requests) race: the second save clobbers the first, silently dropping a
  // checkpoint, and both writers spawn simultaneous multi-MB atomic-write temp files for the same
  // file. Private (not the pipeline's shared StateLock) — this only ever guards
  // import-undo-stack.json, mirrors HypothesisStore's own lock.
  private readonly lock = new StateLock();

  constructor(
    private readonly cases: CaseStore,
    private readonly maxDepth: number = DEFAULT_UNDO_DEPTH,
    private readonly maxBytes: number = DEFAULT_UNDO_MAX_BYTES,
  ) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "import-undo-stack.json");
  }

  // How many undo levels this store keeps (used by the push helper + surfaced in the summary).
  depth(): number {
    return Math.max(1, Math.floor(this.maxDepth));
  }

  // Aggregate byte budget applied on top of depth (used by the push/undo/redo helpers).
  byteBudget(): number {
    return this.maxBytes;
  }

  async load(caseId: string): Promise<ImportUndoStack> {
    try {
      return normalizeStack(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyUndoStack();
      throw err;
    }
  }

  async save(caseId: string, stack: ImportUndoStack): Promise<void> {
    await atomicWrite(this.path(caseId), encodeStack(stack));
  }

  // Atomically load -> transform -> save under this case's lock. Use this instead of manual
  // load()/save() pairs for any read-modify-write (pushing a checkpoint, undo, redo) so concurrent
  // callers serialize instead of racing. `fn` may be async: undo/redo save the restored state inside
  // it, so a failed state save throws before the stack is written and the checkpoint stays put.
  async mutate<T>(
    caseId: string,
    fn: (
      stack: ImportUndoStack,
    ) => { stack: ImportUndoStack; result: T } | Promise<{ stack: ImportUndoStack; result: T }>,
  ): Promise<T> {
    return this.lock.runExclusive(caseId, async () => {
      const { stack, result } = await fn(await this.load(caseId));
      await this.save(caseId, stack);
      return result;
    });
  }
}

export interface UndoStepDeps {
  undoStore: ImportUndoStore;
  stateStore: {
    load(caseId: string): Promise<InvestigationState>;
    save(s: InvestigationState): Promise<void>;
  };
  importLock: { runExclusive<T>(caseId: string, fn: () => Promise<T>): Promise<T> };
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  /** The super-timeline store, typed by the one method a step uses (#2220). Absent: rows untouched. */
  superTimeline?: { rehome(caseId: string, events: ForensicEvent[]): Promise<number> };
  /**
   * Re-homes the super-timeline against the ledger a step restored (#2221). Called only when the
   * step changed the ledger, after it committed, under the import lock but not the state lock (a
   * full scan). Absent: the super-timeline keeps the host names it had.
   */
  rehomeSuper?: (caseId: string, ledger: RenameLedger) => Promise<number>;
}

// One undo or redo step, for the routes. The restored state is saved verbatim — findings, IOCs,
// timeline, MITRE, attacker path, the lot (no AI re-synthesis) — keeping the case id and stamping
// updatedAt. A checkpoint is a delta applied to the CURRENT state (#1874), so the step holds the
// import section (no import is mid-write) and the state lock (no other writer between the load and
// the save), in the order every import takes them. The state is saved INSIDE the stack mutation: a
// failed state save throws before the stack is written, so the checkpoint stays on the stack. A
// failed STACK write after a good state save puts the pre-step state back, so the stack and the
// state never disagree (a retry would otherwise re-apply the delta and record an empty redo). Only a
// process crash between the two writes can still leave them apart. `summary` is null when there is
// nothing to undo/redo.
// A checkpoint with super rows (#2220) also writes its `restore` rows to the super-timeline by id,
// after the state; a failed stack write puts the `reapply` rows back too. `superChanged` says the
// step rewrote super-timeline rows, so the route can announce it.
export async function runUndoStep(
  deps: UndoStepDeps,
  caseId: string,
  step: typeof applyUndo,
): Promise<{ summary: UndoStackSummary | null; next: InvestigationState | null; superChanged: boolean }> {
  const { undoStore, stateStore, superTimeline } = deps;
  let next: InvestigationState | null = null;
  let superWritten: SuperRowsUndo | undefined;
  let stateBefore: InvestigationState | null = null;
  let renamedSuper = false;
  const summary = await deps.importLock.runExclusive(caseId, async () => {
    const stepped = await deps.runStateExclusive(caseId, async () => {
      const state = await stateStore.load(caseId);
      stateBefore = state;
      try {
        return await undoStore.mutate(caseId, async (stack) => {
          const result = step(stack, state, undefined, undoStore.depth(), undoStore.byteBudget());
          if (!result) return { stack, result: null };
          const saved: InvestigationState = {
            ...followLedger(state, result.restore),
            caseId,
            updatedAt: new Date().toISOString(),
          };
          await stateStore.save(saved);
          next = saved;
          if (superTimeline && result.superRows?.restore.length) {
            superWritten = result.superRows; // set first: a partial write is rolled back as well
            await superTimeline.rehome(caseId, result.superRows.restore);
          }
          return { stack: result.stack, result: summarizeUndoStack(result.stack, undoStore.depth()) };
        });
      } catch (err) {
        if (next) {
          next = null;
          await stateStore.save(state); // the stack write failed: put the case back as it was
        }
        if (superTimeline && superWritten) {
          const rows = superWritten.reapply;
          superWritten = undefined;
          await superTimeline.rehome(caseId, rows); // and the super-timeline rows with it
        }
        throw err;
      }
    });
    if (stateBefore && next && deps.rehomeSuper && renameLedgerChanged(stateBefore, next))
      renamedSuper = await rehomeSuperQuietly(deps.rehomeSuper, caseId, next);
    return stepped;
  });
  return { summary, next, superChanged: superWritten !== undefined || renamedSuper };
}

// The forensic half of #2221: a step that changes the ledger re-homes every row the restore keeps
// (one another writer added after the import included) against the ledger it restores, so the
// forensic rows and their super-timeline copies follow the same ledger.
function followLedger(before: RenameLedger, restored: InvestigationState): InvestigationState {
  if (!renameLedgerChanged(before, restored)) return restored;
  return carryHostRenames(restored, { evenWithoutLedger: true }).state;
}

// Non-fatal, like settle's own super re-home: the restore is already committed. A throw may follow a
// partly written batch, so it still counts as a change and the dashboard re-reads the super-timeline.
async function rehomeSuperQuietly(
  rehome: NonNullable<UndoStepDeps["rehomeSuper"]>,
  caseId: string,
  ledger: RenameLedger,
): Promise<boolean> {
  try {
    return (await rehome(caseId, ledger)) > 0;
  } catch {
    return true;
  }
}
