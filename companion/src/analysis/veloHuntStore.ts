import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { HuntTarget } from "../integrations/velociraptor/velociraptorApi.js";

// The per-case record of the current / last Velociraptor BUNDLE hunt: which bundle was launched, the
// returned hunt id, when results should be collected, and the outcome once they are. Persisted to a
// side file (`state/velo-hunt.json`) so a server restart (the project's #1 gotcha) doesn't strand a
// hunt — the dashboard still shows it and the analyst can "Collect now". NOT part of InvestigationState.
// One active job per case (a new run replaces the previous record).

export type VeloHuntStatus = "running" | "collecting" | "imported" | "error";

export interface VeloHuntJob {
  bundleId: string;
  bundleName: string;
  artifacts: string[];
  huntId: string;
  guiUrl?: string;
  launchedAt: string;     // ISO
  waitMinutes: number;
  collectAt: string;      // ISO — launchedAt + waitMinutes; when the auto-collect fires
  status: VeloHuntStatus;
  target?: HuntTarget;
  error?: string;
  importedAt?: string;    // ISO — when results were collected + imported
  importFile?: string;    // stored evidence filename
  addedEvents?: number;
  addedIocs?: number;
}

export class VeloHuntStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "velo-hunt.json");
  }

  // The current/last job for the case, or null when none has run.
  async load(caseId: string): Promise<VeloHuntJob | null> {
    try {
      return JSON.parse(await readFile(this.path(caseId), "utf8")) as VeloHuntJob;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async save(caseId: string, job: VeloHuntJob): Promise<VeloHuntJob> {
    await atomicWrite(this.path(caseId), JSON.stringify(job, null, 2));
    return job;
  }
}
