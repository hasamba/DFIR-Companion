import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { parseMainSourceOverride, type MainSourceOverride } from "./caseMainSource.js";

// The analyst's per-case override of the main evidence source (#2559). Only the override is stored;
// the automatic choice is computed on read from the forensic timeline (caseMainSource.ts). Same
// pattern as CorrelationProfileStore: one small JSON file under the case's state/ directory.
// An unreadable or unknown stored value reads as "no override" rather than failing the case.

export interface StoredMainSource {
  override: MainSourceOverride;
}

export class CaseMainSourceStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "main-source.json");
  }

  async load(caseId: string): Promise<MainSourceOverride> {
    let text: string;
    try {
      text = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
    try {
      const parsed = parseMainSourceOverride((JSON.parse(text) as Partial<StoredMainSource>)?.override);
      return parsed.ok ? parsed.value : null;
    } catch {
      return null; // a corrupt file must not break hunts or synthesis
    }
  }

  async save(caseId: string, override: MainSourceOverride): Promise<void> {
    const body: StoredMainSource = { override };
    await atomicWrite(this.path(caseId), JSON.stringify(body, null, 2));
  }
}
