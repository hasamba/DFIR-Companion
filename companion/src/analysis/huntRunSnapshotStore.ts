import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { HuntRunRecord } from "./huntRunDiff.js";

// Per-case persistence for run-to-run hunt diffing (#80): the latest result-row snapshot recorded per
// VQL fingerprint (state/hunt-run-snapshots.json), so a re-run of the same hunt can show what's new
// since the last one. A sibling to HuntOutcomeStore (which is keyed by huntId, not fingerprint, and
// carries the case-cumulative delta rather than a per-run snapshot). Writes go through atomicWrite
// (Dropbox/OneDrive-safe temp-rename), like every other side-file store.

export class HuntRunSnapshotStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "hunt-run-snapshots.json");
  }

  // Records for the case, newest-touched first. [] when the file is absent or malformed — a corrupt
  // side file must never sink a hunt collection.
  async load(caseId: string): Promise<HuntRunRecord[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      return Array.isArray(parsed) ? (parsed as HuntRunRecord[]) : [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      if (err instanceof SyntaxError) return [];
      throw err;
    }
  }

  async save(caseId: string, records: readonly HuntRunRecord[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(records, null, 2));
  }
}
