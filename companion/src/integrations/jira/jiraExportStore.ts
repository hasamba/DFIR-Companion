import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";
import type { JiraIssueRef } from "./jiraClient.js";

// Per-case memory of the finding → Jira issue keys we created. On re-export this lets us update
// an existing issue instead of duplicating. Stored in `state/jira-export.json`.

const jiraExportSchema = z.object({
  issueRefs: z.record(z.string(), z.object({ id: z.string(), key: z.string(), url: z.string().optional() })).catch({}),
  lastExportedAt: z.string().catch(""),
});

export type JiraExport = z.infer<typeof jiraExportSchema>;

const EMPTY: JiraExport = { issueRefs: {}, lastExportedAt: "" };

export class JiraExportStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "jira-export.json");
  }

  async load(caseId: string): Promise<JiraExport> {
    try {
      return jiraExportSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  async record(caseId: string, refs: Record<string, JiraIssueRef>, now?: string): Promise<JiraExport> {
    const prev = await this.load(caseId);
    const next: JiraExport = {
      issueRefs: { ...prev.issueRefs, ...refs },
      lastExportedAt: now ?? new Date().toISOString(),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }

  // Alias matching the structural store interface used by jiraPush.ts.
  async save(caseId: string, refs: Record<string, JiraIssueRef>): Promise<void> {
    await this.record(caseId, refs);
  }
}
