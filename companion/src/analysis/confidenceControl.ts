import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case Findings-panel display preferences. `minConfidence` undefined = show all (0);
// each `hide…` undefined = show that origin. Machine/analyst display preferences, not
// investigation data — nothing here removes anything from case state.
// state/confidence-control.json via atomicWrite.
export interface ConfidenceControl {
  minConfidence?: number;
  hideAutoFindings?: boolean;
  hideGapFindings?: boolean;
}

const schema = z
  .object({
    minConfidence: z.number().min(0).max(100).optional().catch(undefined),
    hideAutoFindings: z.boolean().optional().catch(undefined),
    hideGapFindings: z.boolean().optional().catch(undefined),
  })
  .catch({});

export class ConfidenceControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "confidence-control.json");
  }

  async load(caseId: string): Promise<ConfidenceControl> {
    try {
      return schema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  async set(caseId: string, patch: ConfidenceControl): Promise<ConfidenceControl> {
    // Key by key, not a spread of `patch`: the dashboard saves the confidence floor and the two
    // origin lenses from separate code paths, so a patch naming one must leave the others alone.
    // An explicitly-undefined key still counts as present, which is how a value is cleared.
    const next: ConfidenceControl = {
      ...(await this.load(caseId)),
      ...("minConfidence" in patch ? { minConfidence: patch.minConfidence } : {}),
      ...("hideAutoFindings" in patch ? { hideAutoFindings: patch.hideAutoFindings } : {}),
      ...("hideGapFindings" in patch ? { hideGapFindings: patch.hideGapFindings } : {}),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
