import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case threat-intel enrichment control. Instead of a single on/off, the case stores the
// explicit set of ENABLED provider names. OPSEC default = local providers only (your own
// MISP / YETI instances), which don't leak indicators off-box; external SaaS (VirusTotal,
// AbuseIPDB, MalwareBazaar, RockyRaccoon) are opt-in per case. Enabling a provider triggers a
// re-check of all IOCs on it (see enrichService's per-provider caching).
export interface EnrichControl {
  providers: string[];   // enabled provider names
}

// The raw persisted shape, tolerant of the legacy `{ enabled: boolean }` files.
interface RawControl {
  providers?: string[];
  enabled?: boolean;
}

// Resolve the enabled provider names from the stored control, the providers actually
// CONFIGURED on this server (have keys), and the LOCAL subset of those:
//   - explicit list  → keep only names that are still configured
//   - legacy enabled → on = all configured (preserve old behavior), off = none
//   - nothing stored → default to local-only configured providers (the OPSEC-safe default)
export function resolveEnabledProviders(
  raw: RawControl | null,
  configured: string[],
  localConfigured: string[],
): string[] {
  if (raw && Array.isArray(raw.providers)) return raw.providers.filter((n) => configured.includes(n));
  if (raw && typeof raw.enabled === "boolean") return raw.enabled ? [...configured] : [];
  return [...localConfigured];
}

export class EnrichControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "enrich-control.json");
  }

  // Returns the raw stored control (possibly legacy-shaped), or null when never set.
  async load(caseId: string): Promise<RawControl | null> {
    try {
      return JSON.parse(await readFile(this.path(caseId), "utf8")) as RawControl;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async save(caseId: string, control: EnrichControl): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(control, null, 2));
  }
}
