/**
 * Which incarnation of a case a piece of work belongs to, and the check that keeps a deleted case's
 * late work out of its folder and out of a new case with the same id (#1855).
 *
 * Each case.json carries a random `generation`, written when the case is created, seeded or
 * imported. Work remembers the generation it started under (`runInCaseScope`), and every guarded
 * write asks `beginCaseWrite` first. A write is refused — before anything is created — when:
 *   - the case folder is being deleted, archived or restored right now ("closing");
 *   - the work's case is gone, was replaced by a new case with the same id, or moved;
 *   - the folder was deleted or moved away in this process and holds no case.json (a "tombstone").
 *     This last rule needs no scope, so even work that never captured a generation cannot
 *     recreate a deleted case's folder.
 *
 * A case.json without the field is a case created before #1855: it reads as LEGACY_GENERATION,
 * and nothing rewrites it just to add one.
 *
 * The scope uses AsyncLocalStorage.run() only. enterWith() is not used on purpose: in a timer or
 * event callback it sticks to that callback's resource and leaks into every later tick.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";

export const ARCHIVED_DIRNAME = "_archived";
export const LEGACY_GENERATION = "legacy";
/** Captured for work that starts after its case folder was already deleted: it never matches. */
const GONE_GENERATION = "\0gone";
const UNREADABLE_GENERATION = "\0unreadable";

export type CaseWriteRefusal = "deleted" | "replaced" | "moved";

const REASON_TEXT: Record<CaseWriteRefusal, string> = {
  deleted: "the case was deleted",
  replaced: "the case was deleted and a new case now uses its id",
  moved: "the case folder was moved (archive or restore)",
};

/** A write from work that does not belong to the case's current incarnation. Nothing was written. */
export class CaseWriteRefusedError extends Error {
  readonly code = "DFIR_CASE_WRITE_REFUSED";
  constructor(
    readonly path: string,
    readonly reason: CaseWriteRefusal,
  ) {
    super(`refused a late write to ${path}: ${REASON_TEXT[reason]}`);
    this.name = "CaseWriteRefusedError";
  }
}

export function isCaseWriteRefused(err: unknown): err is CaseWriteRefusedError {
  return (err as { code?: unknown } | null)?.code === "DFIR_CASE_WRITE_REFUSED";
}

export function newCaseGeneration(): string {
  return randomUUID();
}

/** The generation a case.json records; LEGACY_GENERATION for one written before #1855. */
export function generationOf(meta: unknown): string {
  const value = (meta as { generation?: unknown } | null)?.generation;
  return typeof value === "string" && value.length > 0 ? value : LEGACY_GENERATION;
}

let reporter: ((err: CaseWriteRefusedError) => void) | null = null;

/** Where refusals are logged (the server wires its logger). Reporting never throws. */
export function setCaseWriteRefusalReporter(report: ((err: CaseWriteRefusedError) => void) | null): void {
  reporter = report;
}

interface CaseDirs {
  active: string;
  archived: string;
}

interface ScopeEntry extends CaseDirs {
  generation: string;
}

const scope = new AsyncLocalStorage<ReadonlyMap<string, ScopeEntry>>();
const tombstones = new Map<string, CaseWriteRefusal>();
const closing = new Map<string, { reason: CaseWriteRefusal; count: number }>();
const inflight = new Set<{ path: string }>();
const settledWaiters = new Set<() => void>();

/** Both places a case can live, resolved so every comparison below is on one spelling. */
export function caseDirsOf(casesRoot: string, caseId: string): CaseDirs {
  return {
    active: resolve(casesRoot, caseId),
    archived: resolve(casesRoot, ARCHIVED_DIRNAME, caseId),
  };
}

function isUnder(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir + sep);
}

// A tiny synchronous read, so a check never yields between deciding and the write it admits (and
// the SQLite writer keeps its FIFO order).
function readCurrent(dirs: CaseDirs): { dir: string; generation: string } | null {
  for (const dir of [dirs.active, dirs.archived]) {
    let raw: string;
    try {
      raw = readFileSync(join(dir, "case.json"), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      return { dir, generation: UNREADABLE_GENERATION };
    }
    try {
      return { dir, generation: generationOf(JSON.parse(raw)) };
    } catch {
      return { dir, generation: UNREADABLE_GENERATION };
    }
  }
  return null;
}

function isSafeCaseId(caseId: string): boolean {
  return caseId.length > 0 && !/[\\/]/.test(caseId) && caseId !== "." && !caseId.includes("..");
}

/**
 * Run `fn` — and everything it starts — as work of the case's CURRENT incarnation. `generation`
 * passes one already observed (a sweep that listed the cases), so the capture cannot pick up a
 * newer case created in between. First capture wins: inside an existing scope for the same case,
 * `fn` keeps the older generation, so a tail kicked by old work stays old work.
 */
export function runInCaseScope<T>(casesRoot: string, caseId: string, fn: () => T, generation?: string): T {
  if (!isSafeCaseId(caseId)) return fn();
  const dirs = caseDirsOf(casesRoot, caseId);
  const current = scope.getStore();
  if (current?.has(dirs.active)) return fn();
  let captured = generation;
  if (captured === undefined) {
    const now = readCurrent(dirs);
    if (now) captured = now.generation;
    else if (tombstones.has(dirs.active) || tombstones.has(dirs.archived)) captured = GONE_GENERATION;
    else return fn(); // never created (yet): the unscoped rules apply
  }
  const next = new Map(current ?? []);
  next.set(dirs.active, { ...dirs, generation: captured });
  return scope.run(next, fn);
}

/**
 * Capture the case's incarnation NOW and return a runner that puts later work in that scope — for
 * work that is started after a response went out, or from a callback that runs elsewhere (#1866).
 */
export function captureCaseScope(casesRoot: string, caseId: string): <T>(fn: () => T) => T {
  const generation = runInCaseScope(casesRoot, caseId, () => capturedGeneration(casesRoot, caseId));
  return (fn) => (generation === null ? fn() : runInCaseScope(casesRoot, caseId, fn, generation));
}

/** The generation this async context captured for the case, or null when it captured none. */
export function capturedGeneration(casesRoot: string, caseId: string): string | null {
  if (!isSafeCaseId(caseId)) return null;
  return scope.getStore()?.get(caseDirsOf(casesRoot, caseId).active)?.generation ?? null;
}

/** The generation of a case that has no case.json and was never deleted in this process. */
export const NO_CASE_GENERATION = "\0none";

/**
 * The incarnation this async context works for (#1866): the captured generation inside a scope,
 * else the one case.json records now. A folder deleted in this process reads as "gone"; a case
 * that never existed reads as NO_CASE_GENERATION. Per-case in-memory state keys on this, so old
 * work and a same-id successor never share an entry.
 */
export function currentGeneration(casesRoot: string, caseId: string): string {
  if (typeof casesRoot !== "string" || !isSafeCaseId(caseId)) return NO_CASE_GENERATION;
  const dirs = caseDirsOf(casesRoot, caseId);
  const captured = scope.getStore()?.get(dirs.active)?.generation;
  if (captured !== undefined) return captured;
  const now = readCurrent(dirs);
  if (now) return now.generation;
  return tombstones.has(dirs.active) || tombstones.has(dirs.archived) ? GONE_GENERATION : NO_CASE_GENERATION;
}

/**
 * Run `fn` as work of the incarnation `generation` names — one read back from per-case state. A
 * NO_CASE_GENERATION entry runs unscoped, as it was recorded: a scope for a case that never existed
 * would refuse every write.
 */
export function runInGenerationScope<T>(casesRoot: string, caseId: string, generation: string, fn: () => T): T {
  return generation === NO_CASE_GENERATION ? fn() : runInCaseScope(casesRoot, caseId, fn, generation);
}

/**
 * Run `fn` with no case captured — for a shared worker that starts one case's queued item from
 * the tail of another's (#1866). Without it the new item inherits the finished item's scope, and
 * "first capture wins" would pin it to that item's case incarnation.
 */
export function runOutsideCaseScope<T>(fn: () => T): T {
  return scope.exit(fn);
}

function refusalFor(target: string): CaseWriteRefusal | null {
  for (const [dir, mark] of closing) if (isUnder(target, dir)) return mark.reason;
  for (const entry of scope.getStore()?.values() ?? []) {
    if (!isUnder(target, entry.active) && !isUnder(target, entry.archived)) continue;
    const now = readCurrent(entry);
    if (!now || entry.generation === GONE_GENERATION) return "deleted";
    if (now.generation !== entry.generation) return "replaced";
    return isUnder(target, now.dir) ? null : "moved";
  }
  for (const [dir, reason] of tombstones) {
    if (isUnder(target, dir) && !existsSync(join(dir, "case.json"))) return reason;
  }
  return null;
}

/**
 * Would a write under `path` be refused right now? Reports nothing — for a writer that must not
 * recurse into the refusal reporter (the case log file sink, whose own lines carry the case id).
 */
export function caseWriteRefusalFor(path: string): CaseWriteRefusal | null {
  return refusalFor(resolve(path));
}

/**
 * Admit one write (or removal) under `path`, or throw CaseWriteRefusedError. Call it BEFORE any
 * mkdir/open/rename, and call the returned release when the write has finished (success or not):
 * a delete waits for admitted writes before it removes the folder.
 */
export function beginCaseWrite(path: string): () => void {
  const target = resolve(path);
  const refusal = refusalFor(target);
  if (refusal) {
    const err = new CaseWriteRefusedError(target, refusal);
    try {
      reporter?.(err);
    } catch {
      /* logging is best-effort */
    }
    throw err;
  }
  const token = { path: target };
  inflight.add(token);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    inflight.delete(token);
    for (const wake of [...settledWaiters]) wake();
  };
}

/** `fn` as one admitted write under `path` (see beginCaseWrite). */
export async function withCaseWrite<T>(path: string, fn: () => Promise<T>): Promise<T> {
  const release = beginCaseWrite(path);
  try {
    return await fn();
  } finally {
    release();
  }
}

function hasInflightUnder(dirs: readonly string[]): boolean {
  for (const token of inflight) if (dirs.some((dir) => isUnder(token.path, dir))) return true;
  return false;
}

function waitForSettle(deadline: number): Promise<boolean> {
  return new Promise((done) => {
    const timer = setTimeout(() => finish(false), Math.max(0, deadline - Date.now()));
    const finish = (settled: boolean): void => {
      clearTimeout(timer);
      settledWaiters.delete(wake);
      done(settled);
    };
    const wake = (): void => finish(true);
    settledWaiters.add(wake);
  });
}

/**
 * Close the case folders to new writes and wait for the admitted ones to finish. On success returns
 * `reopen(tombstone?)`, which lifts the mark and, with a list, tombstones those folders. When writes
 * are still running after `timeoutMs`, the mark is lifted and `onTimeout()` is thrown: a folder is
 * never removed or moved under an admitted write.
 */
export async function closeCaseFolders(
  dirs: readonly string[],
  reason: CaseWriteRefusal,
  timeoutMs: number,
  onTimeout: () => Error,
): Promise<(tombstone?: readonly string[]) => void> {
  const resolved = dirs.map((dir) => resolve(dir));
  for (const dir of resolved) {
    const mark = closing.get(dir);
    closing.set(dir, { reason, count: (mark?.count ?? 0) + 1 });
  }
  let open = true;
  const reopen = (tombstone: readonly string[] = []): void => {
    if (!open) return;
    open = false;
    for (const dir of tombstone) tombstones.set(resolve(dir), reason);
    for (const dir of resolved) {
      const mark = closing.get(dir);
      if (mark && mark.count > 1) closing.set(dir, { ...mark, count: mark.count - 1 });
      else closing.delete(dir);
    }
  };
  const deadline = Date.now() + timeoutMs;
  while (hasInflightUnder(resolved)) {
    if (Date.now() >= deadline || !(await waitForSettle(deadline))) {
      if (!hasInflightUnder(resolved)) break;
      reopen();
      throw onTimeout();
    }
  }
  return reopen;
}

export type Vacated = readonly ("active" | "archived")[];

/**
 * Run a lifecycle step (delete, archive, restore, reseed) with the case closed to new writes, after
 * the admitted ones finished. The places in `vacated` are tombstoned when the step succeeds — and
 * after a failed delete too: a part-removed folder must not be refilled by late work.
 */
export async function runWhileCaseClosed<T>(
  casesRoot: string,
  caseId: string,
  opts: { reason: CaseWriteRefusal; timeoutMs: number; busy: () => Error },
  act: () => Promise<T>,
  vacated: Vacated,
): Promise<T> {
  const dirs = caseDirsOf(casesRoot, caseId);
  const reopen = await closeCaseFolders([dirs.active, dirs.archived], opts.reason, opts.timeoutMs, opts.busy);
  let done = false;
  try {
    const value = await act();
    done = true;
    return value;
  } finally {
    reopen(done || opts.reason === "deleted" ? vacated.map((place) => dirs[place]) : []);
  }
}
