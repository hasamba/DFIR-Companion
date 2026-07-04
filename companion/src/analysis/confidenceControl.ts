import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case minimum-confidence display preference (#226). `minConfidence` undefined = show all
// (0). A machine/analyst display preference, not investigation data — mirrors ForensicGateControl's
// shape. state/confidence-control.json via atomicWrite.
export interface ConfidenceControl {
  minConfidence?: number;
}

const schema = z
  .object({ minConfidence: z.number().min(0).max(100).optional().catch(undefined) })
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
    const next: ConfidenceControl = {
      ...(await this.load(caseId)),
      ...("minConfidence" in patch ? { minConfidence: patch.minConfidence } : {}),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
