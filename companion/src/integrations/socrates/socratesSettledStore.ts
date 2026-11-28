import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";
import { StateLock } from "../../analysis/stateLock.js";

// SO-CRATES jobs whose final state was reported while their row in socrates-jobs.json could not be
// written: settled as failed by startup recovery (#3038), or finished by a poller whose final save
// failed (#3042). The outcome was already counted in its submission's message, so a later restart
// must treat the job as finished and never report it again. Persisted to its own side file
// (state/socrates-settled.json): the job file is the one that just refused the write. A mark is
// pruned once the job's row is final or gone. A mark written before #3042 has no status: failed.

export interface SocratesSettledMark {
  /** The outcome the submission's message gave for this job. Absent: "error". */
  status?: "error" | "imported";
  /** The failure reason the message gave ("" for an imported job). */
  error: string;
  /** What an imported job added, for its healed row. */
  addedEvents?: number;
  addedIocs?: number;
  settledAt: string; // ISO
}

/** What a mark records: a failure reason, or an imported job's counts. */
export type SocratesSettledOutcome =
  { status: "error"; error: string } | { status: "imported"; addedEvents?: number; addedIocs?: number };

export type SocratesSettledMarks = Readonly<Record<string, SocratesSettledMark>>;

const settledLock = new StateLock();

function isMark(value: unknown): value is SocratesSettledMark {
  const v = value as Partial<SocratesSettledMark> | null;
  return (
    typeof v === "object" &&
    v !== null &&
    typeof v.error === "string" &&
    typeof v.settledAt === "string" &&
    (v.status === undefined || v.status === "error" || v.status === "imported") &&
    (v.addedEvents === undefined || Number.isInteger(v.addedEvents)) &&
    (v.addedIocs === undefined || Number.isInteger(v.addedIocs))
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

  /** Record the outcome this job was reported with. Throws when it cannot be written. */
  mark(caseId: string, jobId: string, outcome: SocratesSettledOutcome): Promise<void> {
    return settledLock.runExclusive(caseId, async () => {
      const marks = await this.list(caseId);
      const mark: SocratesSettledMark =
        outcome.status === "error"
          ? { error: outcome.error, settledAt: new Date().toISOString() }
          : {
              status: "imported",
              error: "",
              ...(outcome.addedEvents !== undefined ? { addedEvents: outcome.addedEvents } : {}),
              ...(outcome.addedIocs !== undefined ? { addedIocs: outcome.addedIocs } : {}),
              settledAt: new Date().toISOString(),
            };
      const next = { ...marks, [jobId]: mark };
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
