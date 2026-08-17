import { StateLock } from "./stateLock.js";

/**
 * Per-case IMPORT mutex: one writer at a time through the whole import critical section —
 * snapshot → merge → diff → import-meta → undo checkpoint.
 *
 * Distinct from StateLock, which serializes only the short load→save of a state mutation (and which
 * an import itself takes, repeatedly, from inside this section — so the two must never be the same
 * instance). What this one protects is not the state file but the ARITHMETIC an import does about
 * itself: "+N events" is the difference between a snapshot and the state after the merge, so any
 * foreign write landing in between is counted as this import's own, and lands in the undo
 * checkpoint the import pushes. Undoing that import would then revert the other writer's evidence.
 *
 * Every path that imports into a case takes it: the two /import routes, the streamed ingest behind
 * /push, the MCP ingest and the Velociraptor monitors, the hunt collect, and the external hunt/flow
 * ingest. The job queue is NOT a substitute — DFIR_JOBS_PER_CASE is an operator setting, and above 1
 * admission stops meaning exclusivity.
 *
 * Acquire order, where a caller takes both: job slot first, then this lock. Never the reverse.
 *
 * NOT REENTRANT. `ingestStreamed` takes it internally, so a caller must never wrap a call to it in
 * a section of its own — that self-deadlocks the case for the life of the process. Take it around
 * code that imports through the pipeline directly (dispatchImport, importVelociraptor), never around
 * something that already holds it.
 */
export class ImportLock {
  private readonly lock = new StateLock();

  /** Run `fn` with the case's import section held. Prefer this — the release cannot be forgotten. */
  runExclusive<T>(caseId: string, fn: () => Promise<T>): Promise<T> {
    return this.lock.runExclusive(caseId, fn);
  }

  /**
   * Hold the section across callbacks that cannot be expressed as one function — a promise chain
   * whose diff runs in a later `.then`. Resolves once the section is granted; call the returned
   * release from a `finally`. FORGETTING IT WEDGES EVERY LATER IMPORT FOR THE CASE.
   */
  acquire(caseId: string): Promise<() => void> {
    return new Promise<() => void>((granted) => {
      // The queued task resolves only when the holder releases, so the chain's tail IS the hold.
      // `granted` fires the moment the task starts, which is the moment the lock is ours.
      void this.lock.runExclusive(caseId, () => new Promise<void>((release) => granted(() => release())));
    });
  }
}
