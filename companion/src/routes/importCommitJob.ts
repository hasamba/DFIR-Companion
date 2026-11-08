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
 * Not cancellable and not resumable: none of these importers takes an abort signal yet, and the
 * evidence is already stored before the 202, so a failed run is re-imported, not resumed.
 */
export interface DedicatedImportJob {
  /**
   * Waits for the job's admission. True: run. False: the job was stopped before it started (its
   * case was deleted while it queued) — do not run. A job-ledger failure is reported and answers
   * true: the stored evidence is processed anyway, unregistered, as it was before #2407.
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
    parameters: { kind: commit.kind, storedName: commit.storedName },
  });
  const stoppedError = new Error(STOPPED);
  stoppedError.name = "AbortError";
  return {
    async admitted() {
      if (!job) return true;
      try {
        await job.ready;
        return true;
      } catch (err) {
        if ((err as Error).name === "AbortError") return false;
        ctx.serverLogger.warn(
          `[import] ${commit.caseId}: ${commit.kind} import has no job row (${(err as Error).message}); processing it anyway`,
          { caseId: commit.caseId },
        );
        return true;
      }
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
