import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { sanitizeTrustOverrides, type SourceTrustMap } from "./sourceTrust.js";

// Per-case source-trust OVERRIDES (issue #66), in state/source-trust.json. Only the analyst's deltas from
// the built-in DEFAULT_SOURCE_TRUST are stored here (e.g. "velociraptor: 0.4 on THIS engagement, the hunt
// was noisy"); the effective map is default ⊕ overrides, computed by effectiveTrustMap at read time. A
// stateless wrapper over CaseStore (mirrors ScopeStore / CorrelationProfileStore). Values are sanitized to
// [0,1] on save so a bad value can never skew every downstream weight.
export class SourceTrustStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "source-trust.json");
  }

  async load(caseId: string): Promise<SourceTrustMap> {
    try {
      return sanitizeTrustOverrides(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  // Replace the override map (validated/clamped). Returns the persisted sanitized map.
  async save(caseId: string, overrides: unknown): Promise<SourceTrustMap> {
    const clean = sanitizeTrustOverrides(overrides);
    await atomicWrite(this.path(caseId), JSON.stringify(clean, null, 2));
    return clean;
  }
}
