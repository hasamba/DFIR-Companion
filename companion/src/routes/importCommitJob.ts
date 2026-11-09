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
 * Cancellable only while QUEUED (#2425). None of these importers takes an abort signal yet, and a
 * cancel frees the case's slot at once, so a cancel while the importer runs would let other case
 * work start while rows were still being written. So Cancel closes at the moment of admission: the
 * close and the check of the signal happen in one synchronous turn, which makes them atomic with
 * JobManager.cancel() — either the cancel already landed (the import never starts) or it is refused.
 * Not resumable: the evidence is stored before the 202, so a failed or cancelled run is re-imported.
 */
export interface DedicatedImportJob {
  /**
   * Waits for the job's admission. True: run. False: the job was stopped before it started (the
   * analyst cancelled it, or its case was deleted, while it queued) — do not run. A job-ledger
   * failure is reported and answers true: the stored evidence is processed anyway, unregistered, as
   * it was before #2407.
   */
  admitted(): Promise<boolean>;
  /** The error a stopped job's run throws, which `isStopped` recognises. */
  stopped(): Error;
  isStopped(err: unknown): boolean;
  finish(): Promise<void>;
  fail(err: unknown): Promise<void>;
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
    cancellable: true, // while queued only — closed at admission, below
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
  return {
    async admitted() {
      if (!job) return true;
      try {
        await job.ready;
      } catch (err) {
        if ((err as Error).name === "AbortError") return settleStopped(job.jobId);
        ctx.serverLogger.warn(
          `[import] ${commit.caseId}: ${commit.kind} import has no job row (${(err as Error).message}); processing it anyway`,
          { caseId: commit.caseId },
        );
        return true;
      }
      // No await between these two lines: that is what makes them atomic with cancel().
      manager?.setCancellable(job.jobId, false);
      if (job.signal?.aborted) return settleStopped(job.jobId);
      return true;
    },
    stopped: () => stoppedError,
    isStopped: (err) => err === stoppedError,
    async finish() {
      if (job) await manager?.finish(job.jobId);
    },
    async fail(err) {
      if (job) await manager?.fail(job.jobId, err, { code: "import_failed", retryable: false });
    },
  };
}
