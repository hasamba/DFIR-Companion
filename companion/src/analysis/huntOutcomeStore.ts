import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { HuntOutcome } from "./huntOutcomes.js";

// Per-case persistence for the hunting feedback loop (#157). Holds the durable record of every hunt
// deployed in the case + its outcome (state/hunt-outcomes.json), so suggestions can exclude what
// already ran and pivot on what hit, and the dashboard can show a hunting profile. A side file like
// playbook.json / import-meta.json — NOT part of InvestigationState, so synthesis never wipes it.
// Writes go through atomicWrite (Dropbox/OneDrive-safe temp-rename). IN the snapshot allowlist
// (investigation data — see SNAPSHOT_STATE_FILES), so outcomes travel with an exported case.
//
// Unlike VeloHuntStore (which caps at 12 jobs, carries no VQL fingerprint, and is machine-specific so
// it's snapshot-excluded), this is the loop's portable, fingerprint-keyed ledger.

export class HuntOutcomeStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "hunt-outcomes.json");
  }

  // The case's recorded hunt outcomes, newest first. Returns [] when the file is absent. Tolerant of a
  // malformed file (returns []) so a corrupt side file never sinks a suggestion or dashboard request.
  async load(caseId: string): Promise<HuntOutcome[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      return Array.isArray(parsed) ? (parsed as HuntOutcome[]) : [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      if (err instanceof SyntaxError) return [];
      throw err;
    }
  }

  async save(caseId: string, outcomes: readonly HuntOutcome[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(outcomes, null, 2));
  }
}
