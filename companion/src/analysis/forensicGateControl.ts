import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { Severity } from "./stateTypes.js";

// Per-case forensic-timeline severity cut (2026-07-03). `minSeverity` undefined = defer to the
// global DFIR_FORENSIC_MIN_SEVERITY (resolved by resolveForensicMinSeverity). A machine/analyst
// preference — deliberately NOT in SNAPSHOT_STATE_FILES. state/forensic-gate.json via atomicWrite.
export interface ForensicGateControl {
  minSeverity?: Severity;
}

const schema = z
  .object({ minSeverity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).optional().catch(undefined) })
  .catch({});

export class ForensicGateControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "forensic-gate.json");
  }

  async load(caseId: string): Promise<ForensicGateControl> {
    try {
      return schema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  async set(caseId: string, patch: ForensicGateControl): Promise<ForensicGateControl> {
    const next: ForensicGateControl = {
      ...(await this.load(caseId)),
      ...("minSeverity" in patch ? { minSeverity: patch.minSeverity } : {}),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
