import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// The analyst-saved Starred Events Report (the TimeSketch-style AI summary over starred events).
// A per-case side file (state/starred-report.json) — NOT in InvestigationState, so synthesis never
// wipes it. Single-slot: saving overwrites the previous saved report. null = nothing saved yet.
// Deliberately NOT in SNAPSHOT_STATE_FILES — nothing mutates this file during synthesis/import,
// so the rollback snapshot adds no protection.
export interface SavedStarredReport {
  markdown: string;     // the report as raw Markdown
  savedAt: string;      // ISO timestamp of the save
  eventCount: number;   // starred events the report was generated from (0 when unknown)
}

export class StarredReportStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "starred-report.json");
  }

  async load(caseId: string): Promise<SavedStarredReport | null> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<SavedStarredReport>;
      if (typeof raw?.markdown !== "string" || !raw.markdown) return null;
      return {
        markdown: raw.markdown,
        savedAt: typeof raw.savedAt === "string" ? raw.savedAt : "",
        eventCount: Number(raw.eventCount) || 0,
      };
    } catch {
      return null;   // absent or malformed: treat as nothing saved rather than break the case
    }
  }

  async save(caseId: string, report: SavedStarredReport): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(report, null, 2));
  }
}
