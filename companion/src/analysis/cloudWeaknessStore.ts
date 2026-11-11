// The per-case AWS account-weakness file (#2560), state/cloud-weaknesses.json. Outside the
// investigation state like cloud-coverage.json: never a timeline row, never in a model delta,
// never wiped by a re-synthesis. Each import folds its draft in under a per-case lock; the file is
// bounded by the fold's caps, so one upload costs one small read and write however many came
// before it.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { StateLock } from "./stateLock.js";
import { weaknessFileSchema, type WeaknessFile } from "./awsAccountWeakness.js";
import { foldWeaknesses } from "./awsAccountWeaknessFold.js";

export const CLOUD_WEAKNESS_FILE = "cloud-weaknesses.json";

// Module-level, so every store instance over the same case serializes its folds.
const lock = new StateLock();

export class CloudWeaknessStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), CLOUD_WEAKNESS_FILE);
  }

  /** The case file, or null when no import has recorded weaknesses yet. */
  async load(caseId: string): Promise<WeaknessFile | null> {
    try {
      return weaknessFileSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  /** Fold one import's draft into the case file. */
  async fold(caseId: string, draft: WeaknessFile): Promise<WeaknessFile> {
    return lock.runExclusive(caseId, async () => {
      const next = foldWeaknesses(
        (await this.load(caseId)) ?? { accounts: [], accountsOverflow: false },
        draft,
      );
      await atomicWrite(this.path(caseId), JSON.stringify(next));
      return next;
    });
  }
}

/**
 * Best-effort, like persistCloudCoverage: the import has already committed, so a failure here never
 * fails it. An upload with no CloudTrail records (no draft) writes nothing; one whose records hold no
 * weakness still writes, so the surfaces can say the checks ran and found nothing.
 */
export async function persistWeaknesses(
  store: CloudWeaknessStore | undefined,
  caseId: string,
  draft: WeaknessFile | undefined,
): Promise<void> {
  if (!store || !draft) return;
  try {
    await store.fold(caseId, draft);
  } catch {
    /* best-effort */
  }
}
