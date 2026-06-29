import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case record of the LAST drop-folder sweep that did anything: when it ran, the absolute drop
// path (so the dashboard can tell the analyst where to drop), and the imported / failed files. Kept
// in a side file (`state/drop-status.json`) so the live "📥 Drop: N imported, M failed" banner
// survives a page reload (it's backed by GET /cases/:id/drop-status). The drop analog of
// import-meta.json. NOT part of InvestigationState; NOT in SNAPSHOT_STATE_FILES (transient/machine).

const failureSchema = z.object({
  relpath: z.string().catch(""),
  reason: z.string().catch(""),
});

export const dropStatusSchema = z.object({
  lastSweepAt: z.string().catch(""),
  dropPath: z.string().catch(""),
  importedCount: z.number().catch(0),
  failedCount: z.number().catch(0),
  imported: z.array(z.string()).catch([]),
  failed: z.array(failureSchema).catch([]),
});

export type DropFailure = z.infer<typeof failureSchema>;
export type DropStatus = z.infer<typeof dropStatusSchema>;

const EMPTY: DropStatus = {
  lastSweepAt: "", dropPath: "", importedCount: 0, failedCount: 0, imported: [], failed: [],
};

// One sweep can drop hundreds of files; cap the detail lists (the counts stay exact).
const MAX_LISTED = 200;

export interface DropSweep {
  dropPath: string;
  imported: string[];           // relpaths imported OK this sweep
  failed: DropFailure[];        // relpaths that failed + the reason
}

export class DropStatusStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "drop-status.json");
  }

  async load(caseId: string): Promise<DropStatus> {
    try {
      return dropStatusSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  async record(caseId: string, sweep: DropSweep, at: string = new Date().toISOString()): Promise<DropStatus> {
    const status: DropStatus = {
      lastSweepAt: at,
      dropPath: sweep.dropPath,
      importedCount: sweep.imported.length,
      failedCount: sweep.failed.length,
      imported: sweep.imported.slice(0, MAX_LISTED),
      failed: sweep.failed.slice(0, MAX_LISTED),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(status, null, 2));
    return status;
  }

  async clear(caseId: string): Promise<DropStatus> {
    const status: DropStatus = { ...EMPTY };
    await atomicWrite(this.path(caseId), JSON.stringify(status, null, 2));
    return status;
  }
}
