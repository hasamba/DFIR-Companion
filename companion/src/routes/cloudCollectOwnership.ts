// Who owns a cloud collection folder right now (#2402). Only one run may write a collection's
// manifest and checkpoint at a time, however many times Resume is pressed. Three windows have to be
// covered, because the checkpoint's recorded job id is updated only once a run actually starts:
//
//   1. a Resume request still being handled (between its checks and its launch) — `claimResume`;
//   2. a job registered or requeued for the collection but not running yet — the job ledger;
//   3. a worker still finishing after its job was cancelled (cancel marks the row at once; the
//      worker's last page write and checkpoint update come later) — `workerStarted`.

import type { JobManager } from "../analysis/jobManager.js";
import { isTerminal } from "../analysis/jobRegistry.js";

const resumesInFlight = new Set<string>();
const liveWorkers = new Set<string>();

/**
 * Claim the collection for one Resume request. Synchronous, so two requests can never both pass.
 * Returns a release function, or null when another request holds it.
 */
export function claimResume(dir: string): (() => void) | null {
  if (resumesInFlight.has(dir)) return null;
  resumesInFlight.add(dir);
  return () => void resumesInFlight.delete(dir);
}

/** Mark a worker as writing to `dir`. Returns the release, or null when one already is. */
export function workerStarted(dir: string): (() => void) | null {
  if (liveWorkers.has(dir)) return null;
  liveWorkers.add(dir);
  return () => void liveWorkers.delete(dir);
}

export function workerLive(dir: string): boolean {
  return liveWorkers.has(dir);
}

/** Does the job ledger hold a queued or running collect job for this collection? */
export function collectJobPending(manager: JobManager, caseId: string, collectionId: string): boolean {
  return manager
    .list(caseId)
    .some(
      (job) =>
        job.kind === "cloud-collect" &&
        !isTerminal(job.status) &&
        job.parameters?.collectionId === collectionId,
    );
}
