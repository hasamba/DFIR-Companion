import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";

// Per-case memory of the LAST Notion export: which page we wrote to and the id of the single
// managed container block we own on it. Unlike IRIS/Timesketch (which we can find-by-name on
// the remote), Notion has no "find my page" lookup — so we MUST remember the target ourselves.
// On re-export this tells us which container's children to refresh (leaving everything the
// investigators wrote outside it untouched). Kept in `state/notion-export.json`, written via
// atomicWrite (Dropbox-lock tolerant) like the other side-file stores.

export const notionExportSchema = z.object({
  pageId: z.string().catch(""),              // the target Notion page (dashed UUID)
  pageUrl: z.string().catch(""),             // cached for the dashboard's "Open in Notion" link
  containerBlockId: z.string().catch(""),    // the managed toggle block we own on that page
  parentPageId: z.string().catch(""),        // remembered parent for a "new page" export (audit)
  databaseId: z.string().catch(""),          // set when the page was created as a database row
  lastExportedAt: z.string().catch(""),
  lastBlocksAppended: z.number().catch(0),
  lastMode: z.string().catch(""),            // "new" | "existing"
});

export type NotionExport = z.infer<typeof notionExportSchema>;

const EMPTY: NotionExport = {
  pageId: "", pageUrl: "", containerBlockId: "", parentPageId: "", databaseId: "",
  lastExportedAt: "", lastBlocksAppended: 0, lastMode: "",
};

export class NotionExportStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "notion-export.json");
  }

  async load(caseId: string): Promise<NotionExport> {
    try {
      return notionExportSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  // Persist the latest export pointer (merged over whatever was there before).
  async record(caseId: string, patch: Partial<NotionExport>): Promise<NotionExport> {
    const prev = await this.load(caseId);
    const next: NotionExport = { ...prev, ...patch };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
