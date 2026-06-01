import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";

// Per-case AI analysis control. `enabled` lets the user capture screenshots without
// running AI; `lastAnalyzedSeq` is the highest capture sequence the live pipeline has
// analyzed, so turning AI back on can catch up on everything captured while it was off.
export interface AiControl {
  enabled: boolean;
  lastAnalyzedSeq: number;
}

const DEFAULT: AiControl = { enabled: true, lastAnalyzedSeq: 0 };

export class AiControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "ai-control.json");
  }

  async load(caseId: string): Promise<AiControl> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<AiControl>;
      return { ...DEFAULT, ...raw };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...DEFAULT };
      throw err;
    }
  }

  async save(caseId: string, control: AiControl): Promise<void> {
    const target = this.path(caseId);
    const tmp = target + ".tmp";
    await writeFile(tmp, JSON.stringify(control, null, 2), "utf8");
    await rename(tmp, target); // atomic replace
  }
}
