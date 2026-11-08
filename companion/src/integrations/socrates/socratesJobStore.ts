import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";
import { StateLock } from "../../analysis/stateLock.js";

// Per-case record of SO-CRATES analyses. Persisted to a side file (state/socrates-jobs.json) so a
// server restart does not strand an in-flight analysis: startup recovery (socratesRecovery.ts,
// #2408) resumes a job still "processing" and marks one caught mid-import as interrupted. Mirrors
// VeloHuntStore; NOT part of InvestigationState.

export type SocratesJobStatus = "processing" | "importing" | "imported" | "error";

export interface SocratesJob {
  jobId: string;
  md5: string;
  sourceName: string; // the file the analyst submitted
  zipEntry?: string; // the entry inside that archive, when the source was a zip
  status: SocratesJobStatus;
  phase?: string; // SO-CRATES analysis phase: network | logs | files
  startedAt: string; // ISO
  finishedAt?: string; // ISO
  addedEvents?: number;
  addedIocs?: number;
  error?: string;
  /** The drop-folder path the file came from, so a resumed job can still close its drop-log line. */
  dropRelpath?: string;
}

/** imported and error are final: nothing moves a job out of them. */
export function isTerminalSocratesStatus(status: SocratesJobStatus): boolean {
  return status === "imported" || status === "error";
}

// The history cap. It is applied when a job is added and only ever drops FINISHED jobs (#2408): an
// in-flight job evicted from this file can never be resumed or reported, so with more than 25 jobs
// running at once the file holds all of them until they finish.
const MAX_JOBS = 25;

function withNewJob(jobs: readonly SocratesJob[], job: SocratesJob): SocratesJob[] {
  const next = [job, ...jobs];
  let excess = next.length - MAX_JOBS;
  if (excess <= 0) return next;
  // Drop the OLDEST finished jobs first (the list is newest first, so walk it from the end).
  const dropped = new Set<number>();
  for (let i = next.length - 1; i > 0 && excess > 0; i--) {
    if (isTerminalSocratesStatus(next[i].status)) {
      dropped.add(i);
      excess--;
    }
  }
  return next.filter((_, i) => !dropped.has(i));
}

// Serializes a case's list->modify->save section on the job file (follow-up to #682). A lost upsert
// leaves a submitted job with no local record, so its result is never collected.
const socratesJobLock = new StateLock();

export class SocratesJobStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "socrates-jobs.json");
  }

  async list(caseId: string): Promise<SocratesJob[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      return Array.isArray(parsed) ? (parsed as SocratesJob[]) : [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(caseId: string, jobId: string): Promise<SocratesJob | null> {
    return (await this.list(caseId)).find((j) => j.jobId === jobId) ?? null;
  }

  /**
   * Add a job (prepended) or update an existing one in place, matched by jobId. A job already
   * imported or errored is final (#2408): a later write to it is ignored and the STORED job is
   * returned, so a stale writer cannot turn a recorded outcome back into "processing" or flip it.
   */
  upsert(caseId: string, job: SocratesJob): Promise<SocratesJob> {
    return socratesJobLock.runExclusive(caseId, async () => {
      const jobs = await this.list(caseId);
      const idx = jobs.findIndex((j) => j.jobId === job.jobId);
      if (idx >= 0 && isTerminalSocratesStatus(jobs[idx].status)) return jobs[idx];
      const next = idx >= 0 ? jobs.map((j, i) => (i === idx ? job : j)) : withNewJob(jobs, job);
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return job;
    });
  }
}
