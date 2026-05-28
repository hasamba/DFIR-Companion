import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { type InvestigationState, emptyState } from "./stateTypes.js";

export class StateStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "investigation.json");
  }

  async load(caseId: string): Promise<InvestigationState> {
    try {
      const raw = await readFile(this.path(caseId), "utf8");
      return JSON.parse(raw) as InvestigationState;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyState(caseId);
      throw err;
    }
  }

  async save(state: InvestigationState): Promise<void> {
    const target = this.path(state.caseId);
    const tmp = target + ".tmp";
    await writeFile(tmp, JSON.stringify(state, null, 2), "utf8");
    await rename(tmp, target); // atomic replace
  }
}
