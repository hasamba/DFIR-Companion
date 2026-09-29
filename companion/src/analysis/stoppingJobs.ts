/**
 * Jobs of a deleted case that are still winding down (#1831).
 *
 * `JobManager.forgetCase` aborts a deleted case's jobs and drops their rows, but it cannot stop the
 * work functions on the spot: a running import or synthesis keeps going until it notices the abort
 * (and a job with no abort signal runs to its end). A case created with the same id in that window
 * would receive the old case's late writes. So the ids of those jobs are kept here, per case, until
 * each one reports its end through the job manager (finish / fail / hold). While any remain, a
 * create of that id is refused.
 *
 * No time limit, on purpose: a limit would let a slow job that is still writing expire and then
 * write into the new case. A work function that never reports keeps the id blocked until the
 * companion restarts — which also ends the work, so that is the safe way out.
 *
 * A job registered for the case while its old jobs are still stopping (a follow-on import or
 * re-synthesis the old work kicked off) joins the same set, so it holds the id too.
 */
export class StoppingJobs {
  private readonly byCase = new Map<string, Set<string>>();
  private readonly caseOf = new Map<string, string>();
  // Running jobs cancelled or superseded before any delete: their row is terminal or gone, but the
  // work may still be running. A later delete of the case holds them too.
  private readonly abortedRunning = new Map<string, string>();

  /** Record a deleted case's running jobs, and its cancelled ones still winding down: their work may
   *  not have stopped yet. A queued job never started (its admission is rejected), so it is not held. */
  add(caseId: string, jobs: readonly { id: string; status: string }[]): void {
    for (const job of jobs) if (job.status === "running") this.track(caseId, job.id);
    for (const [jobId, owner] of this.abortedRunning) if (owner === caseId) this.track(caseId, jobId);
  }

  /** A running job was cancelled or superseded: remember it until its work reports its end. */
  aborted(job: { id: string; caseId: string | null; status: string }): void {
    if (job.caseId !== null && job.status === "running") this.abortedRunning.set(job.id, job.caseId);
  }

  /** A job registered for a case whose old jobs are still stopping belongs to the old case. */
  adopt(caseId: string | null, jobId: string): void {
    if (caseId !== null && this.byCase.has(caseId)) this.track(caseId, jobId);
  }

  /** The job's work reported its end. */
  settle(jobId: string): void {
    this.abortedRunning.delete(jobId);
    const caseId = this.caseOf.get(jobId);
    if (caseId === undefined) return;
    this.caseOf.delete(jobId);
    const ids = this.byCase.get(caseId);
    ids?.delete(jobId);
    if (ids && ids.size === 0) this.byCase.delete(caseId);
  }

  has(caseId: string): boolean {
    return this.byCase.has(caseId);
  }

  private track(caseId: string, jobId: string): void {
    const ids = this.byCase.get(caseId) ?? new Set<string>();
    ids.add(jobId);
    this.byCase.set(caseId, ids);
    this.caseOf.set(jobId, caseId);
  }
}
