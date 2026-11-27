import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";
import { StateLock } from "../../analysis/stateLock.js";

// SO-CRATES jobs that startup recovery settled as failed while their row in socrates-jobs.json could
// not be written (#3038). The failure was already counted in its submission's message, so a later
// restart must treat the job as finished and never report it again. Persisted to its own side file
// (state/socrates-settled.json): the job file is the one that just refused the write. A mark is
// pruned once the job's row is final or gone.

export interface SocratesSettledMark {
  /** The failure reason the submission's message gave for this job. */
  error: string;
  settledAt: string; // ISO
}

export type SocratesSettledMarks = Readonly<Record<string, SocratesSettledMark>>;

const settledLock = new StateLock();

function isMark(value: unknown): value is SocratesSettledMark {
  const v = value as Partial<SocratesSettledMark> | null;
  return (
    typeof v === "object" && v !== null && typeof v.error === "string" && typeof v.settledAt === "string"
  );
}

export class SocratesSettledStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "socrates-settled.json");
  }

  /** Every mark of the case. A missing file is no marks; an unreadable one throws. */
  async list(caseId: string): Promise<SocratesSettledMarks> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    return Object.fromEntries(Object.entries(parsed).filter(([, v]) => isMark(v)));
  }

  /** Record that this job was settled as failed with `error`. Throws when it cannot be written. */
  mark(caseId: string, jobId: string, error: string): Promise<void> {
    return settledLock.runExclusive(caseId, async () => {
      const marks = await this.list(caseId);
      const next = { ...marks, [jobId]: { error, settledAt: new Date().toISOString() } };
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    });
  }

  /** Drop the marks of these jobs (their rows are final or gone). Nothing to drop writes nothing. */
  prune(caseId: string, jobIds: readonly string[]): Promise<void> {
    return settledLock.runExclusive(caseId, async () => {
      const marks = await this.list(caseId);
      const drop = new Set(jobIds.filter((id) => id in marks));
      if (!drop.size) return;
      const next = Object.fromEntries(Object.entries(marks).filter(([id]) => !drop.has(id)));
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    });
  }
}
