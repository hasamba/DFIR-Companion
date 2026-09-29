import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { sanitizeManifestValue } from "./analysisRunHash.js";
import { jobSchema, type Job } from "./jobRegistry.js";
import { jobLedgerWorker } from "./jobLedgerWorker.js";
import { beginCaseWrite, isCaseWriteRefused, runOutsideCaseScope } from "../storage/caseIncarnation.js";

const GLOBAL_SCOPE = "global";
const GLOBAL_DB_FILENAME = ".dfir-companion-jobs.sqlite";
const CASE_DB_FILENAME = "jobs.sqlite";

interface PutResult {
  inserted: boolean;
  payload?: string;
}

export class JobLedgerStore {
  constructor(private readonly cases: CaseStore) {}

  private validatedJob(job: Job): Job {
    return jobSchema.parse({
      ...job,
      ...(job.parameters
        ? {
            parameters: sanitizeManifestValue(job.parameters) as Job["parameters"],
          }
        : {}),
    });
  }

  private scopeKey(caseId: string | null): string {
    return caseId === null ? GLOBAL_SCOPE : `case:${caseId}`;
  }

  private dbPath(caseId: string | null): string {
    return caseId === null
      ? join(this.cases.casesRoot, GLOBAL_DB_FILENAME)
      : join(this.cases.stateDir(caseId), CASE_DB_FILENAME);
  }

  /**
   * One ledger write, admitted like any case write (#1866): the worker mkdirs the case's state/
   * folder, so a late write for a deleted case would recreate it. Checked WITHOUT the caller's case
   * scope — the job manager schedules one case's queued job from the tail of another's, whose scope
   * says nothing about this row — so only the floor applies: never a closing or deleted folder.
   */
  private async admitted<T>(caseId: string | null, write: () => Promise<T>): Promise<T> {
    if (caseId === null) return write();
    const release = runOutsideCaseScope(() => beginCaseWrite(this.dbPath(caseId)));
    try {
      return await write();
    } finally {
      release();
    }
  }

  async insert(job: Job): Promise<{ inserted: boolean; existing?: Job }> {
    const validated = this.validatedJob(job);
    const result = await this.admitted(job.caseId, () =>
      jobLedgerWorker.request<PutResult>({
        op: "putJob",
        dbPath: this.dbPath(job.caseId),
        scopeKey: this.scopeKey(job.caseId),
        job: validated,
        payload: JSON.stringify(validated),
        insertOnly: true,
      }),
    );
    return {
      inserted: result.inserted,
      ...(result.payload ? { existing: jobSchema.parse(JSON.parse(result.payload) as unknown) } : {}),
    };
  }

  async update(job: Job): Promise<void> {
    const validated = this.validatedJob(job);
    await this.admitted(job.caseId, () =>
      jobLedgerWorker.request<PutResult>({
        op: "putJob",
        dbPath: this.dbPath(job.caseId),
        scopeKey: this.scopeKey(job.caseId),
        job: validated,
        payload: JSON.stringify(validated),
        insertOnly: false,
      }),
    );
  }

  /**
   * Erase one row. Used for a supersede, where the row is not a record of anything that happened:
   * the newer registration took the work over before this one ran. Returns the rows removed, so a
   * caller that expected exactly one can tell that the row was already gone.
   */
  async delete(job: Pick<Job, "id" | "caseId">): Promise<number> {
    return this.admitted(job.caseId, () =>
      jobLedgerWorker.request<number>({
        op: "deleteJob",
        dbPath: this.dbPath(job.caseId),
        scopeKey: this.scopeKey(job.caseId),
        jobId: job.id,
      }),
    );
  }

  async list(caseId: string | null): Promise<Job[]> {
    // The worker's list opens (and so creates) the database: a list for a case deleted meanwhile
    // (a startup restore racing a delete) reads as empty instead of recreating its folder (#1866).
    const list = () =>
      jobLedgerWorker.request<string[]>({
        op: "listJobs",
        dbPath: this.dbPath(caseId),
        scopeKey: this.scopeKey(caseId),
      });
    const payloads = await this.admitted(caseId, list).catch((err: unknown) => {
      if (isCaseWriteRefused(err)) return [];
      throw err;
    });
    return payloads.map((payload) => jobSchema.parse(JSON.parse(payload) as unknown));
  }

  async listAll(): Promise<Job[]> {
    const cases = await this.cases.listCases();
    const lists = await Promise.all([this.list(null), ...cases.map((item) => this.list(item.caseId))]);
    return lists.flat();
  }

  async prune(caseId: string | null, max: number): Promise<number> {
    return this.admitted(caseId, () =>
      jobLedgerWorker.request<number>({
        op: "pruneJobs",
        dbPath: this.dbPath(caseId),
        scopeKey: this.scopeKey(caseId),
        max: Math.max(1, Math.floor(max)),
      }),
    );
  }
}
