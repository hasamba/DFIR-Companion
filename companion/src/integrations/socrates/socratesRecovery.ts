import type { SocratesJob, SocratesJobStore } from "./socratesJobStore.js";

// Startup recovery of SO-CRATES jobs (#2408). The poller that drives a job lives in memory, so a
// restart used to leave every unfinished job "processing" or "importing" forever. This walks one
// case's job file once the server is up:
//
//   processing -> resumed. Nothing has been imported for it yet, so polling again cannot duplicate
//                 anything; SO-CRATES keys the analysis by MD5, so no re-upload is needed.
//   importing  -> marked interrupted. The restart may have landed some or all of its verdicts, and
//                 there is no way to tell from here. Importing them again could put duplicate
//                 evidence in the case, so the analyst is told and decides.
//
// Finished jobs are left alone, and so is any job a poller in THIS process already owns.

export const INTERRUPTED_IMPORT_MESSAGE =
  "Interrupted by a server restart while its verdicts were being imported — some or all of them " +
  "may already be in the case. Check the timeline, and re-run the file if they are missing.";

export const UNCONFIGURED_MESSAGE =
  "Interrupted by a server restart, and SO-CRATES is no longer configured, so the analysis could " +
  "not be resumed. Configure it in Settings → Tools and re-run the file to collect its results.";

export interface RecoveryDeps {
  store: Pick<SocratesJobStore, "list" | "upsert">;
  /** Is a poller in this process already driving this job? */
  isActive(jobId: string): boolean;
  /** Whether SO-CRATES is configured now — a resumed job needs a server to poll. */
  configured(): boolean;
  /** Start polling a job again (fire and forget — it records its own outcome). */
  resume(caseId: string, job: SocratesJob): void;
  /** Close the drop-log line of a job recovery itself finished. */
  closed(caseId: string, job: SocratesJob): Promise<void>;
  warn(line: string): void;
}

export interface RecoveryCounts {
  resumed: number;
  interrupted: number;
}

export async function recoverSocratesJobs(caseId: string, deps: RecoveryDeps): Promise<RecoveryCounts> {
  const counts: RecoveryCounts = { resumed: 0, interrupted: 0 };
  for (const job of await deps.store.list(caseId)) {
    if (job.status !== "processing" && job.status !== "importing") continue;
    if (deps.isActive(job.jobId)) continue;
    try {
      if (job.status === "processing" && deps.configured()) {
        deps.resume(caseId, job);
        counts.resumed++;
        continue;
      }
      const message = job.status === "importing" ? INTERRUPTED_IMPORT_MESSAGE : UNCONFIGURED_MESSAGE;
      const failed: SocratesJob = {
        ...job,
        status: "error",
        error: message,
        finishedAt: new Date().toISOString(),
      };
      const stored = await deps.store.upsert(caseId, failed);
      counts.interrupted++;
      await deps
        .closed(caseId, stored)
        .catch((err) =>
          deps.warn(`[socrates] job ${job.jobId}: drop-log update failed: ${(err as Error).message}`),
        );
    } catch (err) {
      deps.warn(`[socrates] ${caseId}: could not recover job ${job.jobId}: ${(err as Error).message}`);
    }
  }
  return counts;
}
