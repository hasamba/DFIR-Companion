import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type { InvestigationState } from "./stateTypes.js";

// Per-case UNDO / REDO of imports (#76). A single import can flood the dashboard — it grows the
// forensic timeline + IOCs, and the synthesis that follows rewrites the findings / MITRE / attacker
// path. So undo snapshots the WHOLE pre-import InvestigationState and restores it verbatim: undoing
// an import takes back the events, the IOCs, AND the findings it produced, with no AI call (we have
// the exact prior conclusions — re-synthesizing would cost money and might not reproduce them).
// Stored in a side file (`state/import-undo-stack.json`), NOT part of InvestigationState itself. A
// machine-local convenience, intentionally excluded from the portable case snapshot.

export interface ImportCheckpoint {
  label: string;            // what this checkpoint precedes, e.g. "thor (0003_thor.json)"
  at: string;               // ISO time the checkpoint was captured
  state: InvestigationState; // the full investigation state at that point
}

export interface ImportUndoStack {
  undo: ImportCheckpoint[];   // pre-import snapshots, oldest -> newest (the top to undo is last)
  redo: ImportCheckpoint[];   // states that were rolled back, oldest -> newest (top to redo is last)
}

// Default number of undo levels kept. The issue asks for "multiple undo's and redo's"; each level
// is a full copy of the investigation state, so the depth is bounded (override via DFIR_IMPORT_UNDO_DEPTH).
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

function checkpointBytes(c: ImportCheckpoint): number {
  return Buffer.byteLength(JSON.stringify(c.state));
}

// Drop oldest-first entries until the list's total serialized size fits `maxBytes`. Always keeps
// at least the newest entry, even if it alone exceeds the budget — undo becomes single-level for
// a case that large rather than unavailable. A non-positive maxBytes disables the cap.
function capBySize(list: ImportCheckpoint[], maxBytes: number): ImportCheckpoint[] {
  if (!(maxBytes > 0) || list.length === 0) return list;
  const sizes = list.map(checkpointBytes);
  let total = sizes.reduce((a, b) => a + b, 0);
  let start = 0;
  while (total > maxBytes && start < list.length - 1) {
    total -= sizes[start];
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
): { stack: ImportUndoStack; restore: InvestigationState } | null {
  if (stack.undo.length === 0) return null;
  const top = stack.undo[stack.undo.length - 1];
  const redoEntry: ImportCheckpoint = { label: top.label, at, state: current };
  const depth = Math.max(1, Math.floor(maxDepth));
  let redo = [...stack.redo, redoEntry];
  if (redo.length > depth) redo = redo.slice(redo.length - depth);
  return {
    stack: { undo: stack.undo.slice(0, -1), redo: capBySize(redo, maxBytes) },
    restore: top.state,
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
): { stack: ImportUndoStack; restore: InvestigationState } | null {
  if (stack.redo.length === 0) return null;
  const top = stack.redo[stack.redo.length - 1];
  const undoEntry: ImportCheckpoint = { label: top.label, at, state: current };
  const depth = Math.max(1, Math.floor(maxDepth));
  let undo = [...stack.undo, undoEntry];
  if (undo.length > depth) undo = undo.slice(undo.length - depth);
  return {
    stack: { undo: capBySize(undo, maxBytes), redo: stack.redo.slice(0, -1) },
    restore: top.state,
  };
}

// --- Lightweight summary for the dashboard (the GET route returns this, not the raw snapshots,
// which can be megabytes). Just the labels/times + how big each checkpoint is. ------------------

export interface CheckpointSummary {
  label: string;
  at: string;
  events: number;   // forensicTimeline length at that checkpoint
  iocs: number;     // IOC count at that checkpoint
  findings: number; // findings count at that checkpoint
}

export interface UndoStackSummary {
  canUndo: boolean;
  canRedo: boolean;
  maxDepth: number;
  nextUndo: CheckpointSummary | null;   // what "Undo" will roll back (top of the undo stack)
  nextRedo: CheckpointSummary | null;   // what "Redo" will re-apply (top of the redo stack)
  undo: CheckpointSummary[];            // oldest -> newest
  redo: CheckpointSummary[];
}

const summarize = (c: ImportCheckpoint): CheckpointSummary => ({
  label: c.label,
  at: c.at,
  events: c.state.forensicTimeline.length,
  iocs: c.state.iocs.length,
  findings: c.state.findings.length,
});

export function summarizeUndoStack(stack: ImportUndoStack, maxDepth: number = DEFAULT_UNDO_DEPTH): UndoStackSummary {
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
// usable `state` object is dropped (it could not be restored anyway).
export function normalizeStack(raw: unknown): ImportUndoStack {
  const obj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return { undo: normalizeList(obj.undo), redo: normalizeList(obj.redo) };
}

function normalizeList(v: unknown): ImportCheckpoint[] {
  if (!Array.isArray(v)) return [];
  const out: ImportCheckpoint[] = [];
  for (const item of v) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    if (!o.state || typeof o.state !== "object") continue; // unrestorable — drop it
    out.push({
      label: typeof o.label === "string" ? o.label : "",
      at: typeof o.at === "string" ? o.at : "",
      state: o.state as InvestigationState,
    });
  }
  return out;
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
    await atomicWrite(this.path(caseId), JSON.stringify(stack, null, 2));
  }

  // Atomically load -> transform -> save under this case's lock. Use this instead of manual
  // load()/save() pairs for any read-modify-write (pushing a checkpoint, undo, redo) so concurrent
  // callers serialize instead of racing.
  async mutate<T>(caseId: string, fn: (stack: ImportUndoStack) => { stack: ImportUndoStack; result: T }): Promise<T> {
    return this.lock.runExclusive(caseId, async () => {
      const { stack, result } = fn(await this.load(caseId));
      await this.save(caseId, stack);
      return result;
    });
  }
}
