import type { RouteContext } from "./context.js";
import type { RegisteredJob } from "../analysis/jobManager.js";
import { IMPORT_JOB_PENDING_DETAIL } from "./importJobTracking.js";

/**
 * The job row a dedicated `import-*` route's background commit runs under (#2407).
 *
 * Before this, the ~24 dedicated import kinds (thor, siem, chainsaw, wazuh, leapp, …) never
 * registered a job: they did not appear in the Jobs panel, and everything that asks "is the case
 * busy?" — the AI status, the out-of-date marker, synthesis deferral — read only jobs, so it saw an
 * idle case while one ran. The generic route always registered one; this gives the shared commit
 * spine the same row.
 *
 * Cancellable while it waits AND while it runs (#2425). Every dedicated importer checks the job's
 * signal inside the state lock right before its merge (analysis/ingest/importState.ts
 * abortIfCancelled), and the batched ones between batches. So a cancel either merges nothing — the
 * stored evidence stays, the case is as it was — or, for an importer that keeps the batches it
 * already merged (CSV / log, as on the generic route), leaves a partial import that the spine settles
 * and records like any other, so Undo removes it. Cancel closes once the importer has returned: the
 * close and the signal check run in one synchronous turn, atomic with JobManager.cancel().
 *
 * A cancel frees the case's job slot at once, while the importer only stops at its next check. So
 * the moment the job is cancelled the import holds the case in memory instead (analysis/caseHolds.ts):
 * no synthesis or other job of the case starts until this import has stopped and settled. The same
 * hold covers degraded mode — a job ledger that refused the row — where the import still runs, so the
 * evidence is processed, but first waits for the case's running jobs and keeps new ones out.
 * Not resumable: the evidence is stored before the 202, so a failed or cancelled run is re-imported.
 */
export interface DedicatedImportJob {
  /**
   * Waits for the job's admission. True: run. False: the job was stopped before it started (the
   * analyst cancelled it, or its case was deleted, while it queued) — do not run. A job-ledger
   * failure is reported and answers true once the case is held and idle: the stored evidence is
   * processed anyway, without a job row.
   */
  admitted(): Promise<boolean>;
  /** The job's Cancel, handed to the importer. Undefined when there is no job manager. */
  readonly signal: AbortSignal | undefined;
  /** Close Cancel; true when a cancel already landed. Call it once the importer has returned. */
  closeCancel(): boolean;
  /** The error a stopped job's run throws, which `isStopped` recognises. */
  stopped(): Error;
  isStopped(err: unknown): boolean;
  finish(): Promise<void>;
  fail(err: unknown): Promise<void>;
  /** End the in-memory hold, when one was taken. Call it from the spine's `finally`. */
  release(): void;
}

const STOPPED = "dedicated import stopped before it started";

export function admitDedicatedImport(
  ctx: RouteContext,
  commit: { caseId: string; kind: string; storedName: string },
): DedicatedImportJob {
  const manager = ctx.options.jobManager;
  const job: RegisteredJob | undefined = manager?.register({
    caseId: commit.caseId,
    kind: "import",
    label: `${commit.kind}: ${commit.storedName}`,
    detail: IMPORT_JOB_PENDING_DETAIL,
    cancellable: true, // closed once the importer has returned — see closeCancel
    parameters: { kind: commit.kind, storedName: commit.storedName },
  });
  // A stopped admission still reports its end: a cancel that lands while the start is being written
  // records the job as running work that must report (#1831), or a later delete of the case would
  // block re-creating its id until a restart. finish() is a no-op on the terminal row.
  const settleStopped = async (jobId: string): Promise<false> => {
    await manager?.finish(jobId);
    return false;
  };
  const stoppedError = new Error(STOPPED);
  stoppedError.name = "AbortError";
  let releaseHold: (() => void) | undefined;
  const holdCase = (): void => {
    if (manager && !releaseHold) releaseHold = manager.caseHolds.hold(commit.caseId);
  };
  return {
    async admitted() {
      if (!job || !manager) return true;
      try {
        await job.ready;
      } catch (err) {
        if ((err as Error).name === "AbortError") return settleStopped(job.jobId);
        const reason = (err as Error).message;
        ctx.serverLogger.warn(
          `[import] ${commit.caseId}: ${commit.kind} import has no job row (${reason}); processing it anyway`,
          { caseId: commit.caseId },
        );
        // A row the ledger never stored can stay queued in memory, where a later pass would admit it
        // with nobody to run it. End it, then hold the case so nothing overlaps this import.
        const refused = new Error(
          `the job ledger refused this import's row (${reason}); the evidence is processed anyway`,
        );
        await manager.fail(job.jobId, refused, { code: "ledger_write_failed", retryable: false });
        holdCase();
        await manager.caseHolds.whenIdle(commit.caseId);
        return true;
      }
      if (job.signal?.aborted) return settleStopped(job.jobId);
      // cancel() aborts BEFORE it frees the slot, so this hold lands first (see the file header).
      job.signal?.addEventListener("abort", holdCase, { once: true });
      return true;
    },
    signal: job?.signal,
    closeCancel() {
      if (!job) return false;
      // No await between these two lines: that is what makes them atomic with cancel().
      manager?.setCancellable(job.jobId, false);
      return job.signal?.aborted === true;
    },
    stopped: () => stoppedError,
    isStopped: (err) => err === stoppedError,
    async finish() {
      if (job) await manager?.finish(job.jobId);
    },
    async fail(err) {
      if (job) await manager?.fail(job.jobId, err, { code: "import_failed", retryable: false });
    },
    release() {
      job?.signal?.removeEventListener("abort", holdCase);
      releaseHold?.();
    },
  };
}
