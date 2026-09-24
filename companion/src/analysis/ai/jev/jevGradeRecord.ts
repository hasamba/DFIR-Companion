import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../../storage/caseStore.js";
import { atomicWrite } from "../../../storage/atomicWrite.js";
import { StateLock } from "../../stateLock.js";
import type { Severity } from "../../stateTypes.js";

/**
 * The server's own record of what a missed-evidence review graded (#1578).
 *
 * A promoted row carries a severity and a provenance tag that say "a model graded this, at this
 * confidence". Both used to come from the promote request, so any session could write a grade, a
 * confidence or a model name that no review ever produced — into the audit trail, displayed as
 * fact. The review now leaves this record behind, and the promote route reads every one of those
 * values from here. The browser sends row ids and nothing else the server has to trust.
 *
 * ONE ENTRY PER ROW, NEWEST REVIEW WINS. A later review that re-grades a row replaces that row's
 * entry; rows it did not read keep what an earlier review said, because the analyst may still be
 * looking at that earlier table and ticking from it.
 *
 * Stored beside the investigation state, so it travels with a whole-case export like every other
 * per-case sidecar.
 */

const SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"] as const;

export interface JevGradeEntry {
  readonly grade: Severity;
  readonly confidence: number;
  readonly score: number;
  readonly model: string;
  readonly reviewedAt: string;
}

/** One graded row, in the shape the grader returns it. */
export interface JevGradedRow {
  readonly id: string;
  readonly grade: Severity;
  readonly confidence: number;
  readonly score: number;
}

const entrySchema = z.object({
  grade: z.enum(SEVERITIES),
  confidence: z.number().finite(),
  score: z.number().finite(),
  model: z.string(),
  reviewedAt: z.string(),
});

const FILE = "jev-grades.json";
const VERSION = 1;

// MODULE-level, like synthMeta's: two routes build their own instance, and two reviews of the same
// case recording at once must not lose one another's rows in the load-merge-save.
const gradeLock = new StateLock();

export class JevGradeStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), FILE);
  }

  /**
   * Every recorded row, by id. An absent file is an empty record. An entry in a shape the schema
   * refuses is dropped on its own: one damaged entry must not stop the analyst promoting the rest,
   * and a dropped entry is reported to them as "not graded", which is the honest answer.
   */
  async load(caseId: string): Promise<Map<string, JevGradeEntry>> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return new Map();
      throw err;
    }
    const rows = (JSON.parse(raw) as { rows?: unknown })?.rows;
    const out = new Map<string, JevGradeEntry>();
    if (!rows || typeof rows !== "object") return out;
    for (const [id, value] of Object.entries(rows as Record<string, unknown>)) {
      const parsed = entrySchema.safeParse(value);
      if (parsed.success) out.set(id, parsed.data);
    }
    return out;
  }

  /** Merge one review's grades into the record. */
  record(
    caseId: string,
    model: string,
    rows: readonly JevGradedRow[],
    at: string = new Date().toISOString(),
  ): Promise<void> {
    return gradeLock.runExclusive(caseId, async () => {
      const merged = new Map(await this.load(caseId));
      for (const row of rows) {
        merged.set(row.id, {
          grade: row.grade,
          confidence: row.confidence,
          score: row.score,
          model,
          reviewedAt: at,
        });
      }
      const doc = { version: VERSION, rows: Object.fromEntries(merged) };
      await atomicWrite(this.path(caseId), JSON.stringify(doc));
    });
  }
}
