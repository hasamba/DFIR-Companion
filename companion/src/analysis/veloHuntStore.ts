import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { Severity } from "./stateTypes.js";
import type { HuntTarget } from "../integrations/velociraptor/velociraptorApi.js";

// The per-case record of Velociraptor BUNDLE hunts: which bundle was launched, the returned hunt id,
// when results should be collected, and the outcome once they are. Persisted to a side file
// (`state/velo-hunt.json`) so a server restart (the project's #1 gotcha) doesn't strand a hunt — the
// dashboard still shows it and the analyst can "Collect now". NOT part of InvestigationState.
// MULTIPLE concurrent jobs per case are supported (a list keyed by huntId) — starting a second hunt
// while a first is still running no longer drops the first.

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
  minSeverity?: Severity;     // optional import floor chosen at run time (keeps low-value items out)
  timeoutSeconds?: number;    // optional per-collection timeout used for this hunt (Velociraptor default 600s)
  error?: string;
  importedAt?: string;    // ISO — when results were collected + imported
  importFile?: string;    // stored evidence filename
  addedEvents?: number;
  addedIocs?: number;
}

// Cap retained jobs per case (newest first) so the side file stays small — old terminal jobs drop off.
const MAX_JOBS = 12;

export class VeloHuntStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "velo-hunt.json");
  }

  // All tracked bundle hunts for the case, newest first. Back-compat: an older single-object file
  // (one job per case) is read as a one-element list.
  async list(caseId: string): Promise<VeloHuntJob[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      if (Array.isArray(parsed)) return parsed as VeloHuntJob[];
      if (parsed && typeof parsed === "object" && typeof (parsed as VeloHuntJob).huntId === "string") return [parsed as VeloHuntJob];
      return [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(caseId: string, huntId: string): Promise<VeloHuntJob | null> {
    return (await this.list(caseId)).find((j) => j.huntId === huntId) ?? null;
  }

  // Add a new job (prepended) or update an existing one IN PLACE (matched by huntId), capping history.
  async upsert(caseId: string, job: VeloHuntJob): Promise<VeloHuntJob> {
    const jobs = await this.list(caseId);
    const idx = jobs.findIndex((j) => j.huntId === job.huntId);
    const next = idx >= 0 ? jobs.map((j, i) => (i === idx ? job : j)) : [job, ...jobs].slice(0, MAX_JOBS);
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return job;
  }
}
