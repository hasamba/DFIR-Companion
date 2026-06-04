import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";

// Per-case threat-intel enrichment control. Default OFF for OPSEC — enrichment sends
// indicators to third-party services, so nothing is queried until the analyst explicitly
// turns it on. When ON, the server enriches the current IOCs and auto-enriches any IOCs
// added afterward (imports/synthesis).
export interface EnrichControl {
  enabled: boolean;
}

const DEFAULT: EnrichControl = { enabled: false };

export class EnrichControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "enrich-control.json");
  }

  async load(caseId: string): Promise<EnrichControl> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<EnrichControl>;
      return { ...DEFAULT, ...raw };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...DEFAULT };
      throw err;
    }
  }

  async save(caseId: string, control: EnrichControl): Promise<void> {
    const target = this.path(caseId);
    const tmp = target + ".tmp";
    await writeFile(tmp, JSON.stringify(control, null, 2), "utf8");
    await rename(tmp, target); // atomic replace
  }
}
