import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";
import { StateLock } from "../../analysis/stateLock.js";

// Per-case record of SO-CRATES analyses. Persisted to a side file (state/socrates-jobs.json) so a
// server restart does not strand an in-flight analysis — the dashboard still shows it and the
// analyst can see why it never landed. Mirrors VeloHuntStore; NOT part of InvestigationState.

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
}

const MAX_JOBS = 25;

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

  /** Add a job (prepended) or update an existing one in place, matched by jobId. */
  upsert(caseId: string, job: SocratesJob): Promise<SocratesJob> {
    return socratesJobLock.runExclusive(caseId, async () => {
      const jobs = await this.list(caseId);
      const idx = jobs.findIndex((j) => j.jobId === job.jobId);
      const next = idx >= 0 ? jobs.map((j, i) => (i === idx ? job : j)) : [job, ...jobs].slice(0, MAX_JOBS);
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return job;
    });
  }
}
