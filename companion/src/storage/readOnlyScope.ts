import { AsyncLocalStorage } from "node:async_hooks";

/**
 * A read-only window over the case store (#2491).
 *
 * "Preview what the AI will see" runs the REAL AI action — the same prompt builder, the same masking
 * function — and stops it at the provider call. Some actions write before they ask (explainEvent and
 * starredReport promote raw rows; second look promotes and then re-synthesizes; synthesis records its
 * clock-skew detection). A preview must change nothing, so this scope does two things:
 *
 * - `beginCaseWrite` (caseIncarnation.ts) — the chokepoint every case-file write is admitted through —
 *   refuses with ReadOnlyScopeWriteError while the scope is active. A writer this design missed is a
 *   loud failure, never a silent write to a real case.
 * - The investigation state gets an in-memory overlay: StateStore.save writes to it and StateStore.load
 *   reads it first, so an action that promotes and then reads its own promotion sees it, exactly as the
 *   real run would, while the case on disk stays untouched.
 *
 * AsyncLocalStorage, not a process flag: a real AI run for another request (or the same case) that is
 * in flight at the same moment is outside this async context and writes normally.
 */
interface ReadOnlyScope {
  readonly states: Map<string, unknown>;
}

const scope = new AsyncLocalStorage<ReadOnlyScope>();

/** A case write attempted inside a read-only scope. Names the path, never its content. */
export class ReadOnlyScopeWriteError extends Error {
  constructor(readonly path: string) {
    super(`a preview may not write case data (refused: ${path})`);
    this.name = "ReadOnlyScopeWriteError";
  }
}

/** Run `fn` with case writes refused and the investigation state held in memory. */
export function runReadOnly<T>(fn: () => Promise<T>): Promise<T> {
  return scope.run({ states: new Map() }, fn);
}

/** True inside runReadOnly. */
export function isReadOnlyScope(): boolean {
  return scope.getStore() !== undefined;
}

/** Throw when a case write is attempted inside a read-only scope. */
export function refuseWriteInReadOnlyScope(path: string): void {
  if (scope.getStore()) throw new ReadOnlyScopeWriteError(path);
}

/**
 * The state overlay: `undefined` outside a scope (the caller writes to disk), otherwise the map an
 * in-scope save writes to and an in-scope load reads first. Keyed by case id.
 */
export function readOnlyStateOverlay(): Map<string, unknown> | undefined {
  return scope.getStore()?.states;
}
