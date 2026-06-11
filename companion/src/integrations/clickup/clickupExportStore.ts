import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";

// Per-case memory of the LAST ClickUp export: the target list and the map from each playbook task
// id → the ClickUp task id we created for it. On re-export this lets us UPDATE the existing ClickUp
// task instead of creating a duplicate (the spec's "store a reference id so re-export updates").
// Kept in `state/clickup-export.json` via atomicWrite (Dropbox-lock tolerant), like the other
// side-file stores.

export const clickupExportSchema = z.object({
  listId: z.string().catch(""),                         // the target ClickUp list id
  taskIds: z.record(z.string(), z.string()).catch({}),  // playbook task id → ClickUp task id
  lastTaskUrl: z.string().catch(""),                    // a sample task url for the "Open in ClickUp" link
  lastExportedAt: z.string().catch(""),
});

export type ClickUpExport = z.infer<typeof clickupExportSchema>;

const EMPTY: ClickUpExport = { listId: "", taskIds: {}, lastTaskUrl: "", lastExportedAt: "" };

export class ClickUpExportStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "clickup-export.json");
  }

  async load(caseId: string): Promise<ClickUpExport> {
    try {
      return clickupExportSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  // Persist the latest export pointer (merged over whatever was there before).
  async record(caseId: string, patch: Partial<ClickUpExport>): Promise<ClickUpExport> {
    const prev = await this.load(caseId);
    const next: ClickUpExport = { ...prev, ...patch, taskIds: { ...prev.taskIds, ...(patch.taskIds ?? {}) } };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
