import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { sanitizeManifestValue } from "./analysisRunHash.js";
import { jobSchema, type Job } from "./jobRegistry.js";
import { jobLedgerWorker } from "./jobLedgerWorker.js";

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

  async insert(job: Job): Promise<{ inserted: boolean; existing?: Job }> {
    const validated = this.validatedJob(job);
    const result = await jobLedgerWorker.request<PutResult>({
      op: "putJob",
      dbPath: this.dbPath(job.caseId),
      scopeKey: this.scopeKey(job.caseId),
      job: validated,
      payload: JSON.stringify(validated),
      insertOnly: true,
    });
    return {
      inserted: result.inserted,
      ...(result.payload ? { existing: jobSchema.parse(JSON.parse(result.payload) as unknown) } : {}),
    };
  }

  async update(job: Job): Promise<void> {
    const validated = this.validatedJob(job);
    await jobLedgerWorker.request<PutResult>({
      op: "putJob",
      dbPath: this.dbPath(job.caseId),
      scopeKey: this.scopeKey(job.caseId),
      job: validated,
      payload: JSON.stringify(validated),
      insertOnly: false,
    });
  }

  async list(caseId: string | null): Promise<Job[]> {
    const payloads = await jobLedgerWorker.request<string[]>({
      op: "listJobs",
      dbPath: this.dbPath(caseId),
      scopeKey: this.scopeKey(caseId),
    });
    return payloads.map((payload) => jobSchema.parse(JSON.parse(payload) as unknown));
  }

  async listAll(): Promise<Job[]> {
    const cases = await this.cases.listCases();
    const lists = await Promise.all([this.list(null), ...cases.map((item) => this.list(item.caseId))]);
    return lists.flat();
  }

  async prune(caseId: string | null, max: number): Promise<number> {
    return jobLedgerWorker.request<number>({
      op: "pruneJobs",
      dbPath: this.dbPath(caseId),
      scopeKey: this.scopeKey(caseId),
      max: Math.max(1, Math.floor(max)),
    });
  }
}
