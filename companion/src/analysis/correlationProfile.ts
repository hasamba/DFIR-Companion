import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

export type CorrelationProfileName = "strict" | "moderate" | "aggressive" | "custom";

export interface CorrelationProfile {
  profileName: CorrelationProfileName;
  windowSeconds: number;
}

// Preset window values for named profiles.
export const PROFILE_WINDOWS: Record<Exclude<CorrelationProfileName, "custom">, number> = {
  strict: 0,       // hash-only + exact timestamp — no fuzzy path+time merge
  moderate: 2,     // current default (±2 s)
  aggressive: 300, // ±5 min — catches tools with coarse timestamps
};

export const DEFAULT_PROFILE: CorrelationProfile = { profileName: "moderate", windowSeconds: 2 };

export class CorrelationProfileStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "correlation-profile.json");
  }

  async load(caseId: string): Promise<CorrelationProfile> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<CorrelationProfile>;
      const profileName = (["strict","moderate","aggressive","custom"] as CorrelationProfileName[]).includes(raw.profileName as CorrelationProfileName)
        ? (raw.profileName as CorrelationProfileName) : DEFAULT_PROFILE.profileName;
      const windowSeconds = typeof raw.windowSeconds === "number" && raw.windowSeconds >= 0
        ? raw.windowSeconds : DEFAULT_PROFILE.windowSeconds;
      return { profileName, windowSeconds };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...DEFAULT_PROFILE };
      throw err;
    }
  }

  async save(caseId: string, profile: CorrelationProfile): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(profile, null, 2));
  }
}
