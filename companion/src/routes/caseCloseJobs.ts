/**
 * Closing or archiving a case stops the analysis still running on it (#2437).
 *
 * A synthesis, deep pass or enrichment that was running when the analyst pressed Close used to
 * finish and write its conclusions into the frozen case. Cancelling the job aborts its signal, and
 * the run stops at its next superseded check, before it persists. The route then reports the run
 * as cancelled (499), not as an AI error.
 *
 * Only these three kinds are stopped. Import, MCP and cloud-collect jobs are left alone: a running
 * import finishes and is recorded (#2404), and a running cloud collection already refuses the
 * close. The kinds #2425 made into jobs (Sigma re-grade, Jev review, containment check) are not
 * cancellable and finish on their own; second look and second opinion are not stopped either.
 */
import type { JobManager } from "../analysis/jobManager.js";
import type { JobKind } from "../analysis/jobRegistry.js";

const CONCLUSION_JOB_KINDS: ReadonlySet<JobKind> = new Set<JobKind>(["synthesis", "deep-pass", "enrichment"]);

/** Cancels the case's queued or running conclusion jobs; returns how many were cancelled. */
export async function stopConclusionJobs(
  ctx: { readonly options: { readonly jobManager?: JobManager } },
  caseId: string,
): Promise<number> {
  const jobManager = ctx.options.jobManager;
  if (!jobManager) return 0;
  const targets = jobManager
    .list(caseId)
    .filter(
      (job) =>
        CONCLUSION_JOB_KINDS.has(job.kind) &&
        job.cancellable &&
        (job.status === "queued" || job.status === "running"),
    );
  let stopped = 0;
  for (const job of targets) {
    const result = await jobManager.cancel(job.id).catch(() => ({ ok: false }));
    if (result.ok) stopped += 1;
  }
  return stopped;
}
