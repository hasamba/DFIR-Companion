import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import {
  EMPTY_PERSISTED_HUNTS,
  type PersistedPlaybookHunts,
  type PlaybookHuntSuggestion,
} from "./playbookHunt.js";

// Per-case store for the AI-suggested Velociraptor hunts (#70) so they SURVIVE a page refresh instead
// of living only in dashboard memory. Kept in `state/playbook-hunts.json` (a side file, like
// playbook.json / comments / tags) with the per-task fingerprints used to detect staleness — when a
// task is reworded the matching suggestion is dropped on read (selectFreshHunts). Writes go through
// atomicWrite (Dropbox-safe temp-rename). NOT part of InvestigationState, so synthesis never wipes it;
// NOT in the snapshot allowlist (suggestions are regenerable + reference machine-specific artifacts).

export class PlaybookHuntStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "playbook-hunts.json");
  }

  async load(caseId: string): Promise<PersistedPlaybookHunts> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<PersistedPlaybookHunts>;
      return {
        generatedAt: typeof parsed.generatedAt === "string" ? parsed.generatedAt : "",
        suggestions: Array.isArray(parsed.suggestions) ? (parsed.suggestions as PlaybookHuntSuggestion[]) : [],
        taskHashes: parsed.taskHashes && typeof parsed.taskHashes === "object" ? (parsed.taskHashes as Record<string, string>) : {},
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY_PERSISTED_HUNTS };
      throw err;
    }
  }

  async save(caseId: string, data: PersistedPlaybookHunts): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(data, null, 2));
  }
}
