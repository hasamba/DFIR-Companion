import { readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { ClockSkewResult } from "../analysis/clockSkew.js";

// Per-case clock-skew alignment toggle (#228), in state/clock-skew.json. A stateless wrapper over
// CaseStore (mirrors SourceTrustStore). Persists whether the analyst has enabled cross-host
// alignment for this case + the last computed skew results. Returns sensible defaults when
// absent / unreadable.
export interface ClockSkewRecord {
  alignEnabled: boolean;
  results: ClockSkewResult[];
  updatedAt: string;
}

export class ClockSkewStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "clock-skew.json");
  }

  async load(caseId: string): Promise<ClockSkewRecord> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8"));
      return {
        alignEnabled: parsed.alignEnabled === true,
        results: Array.isArray(parsed.results) ? parsed.results : [],
        updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : "",
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return { alignEnabled: false, results: [], updatedAt: "" };
      }
      throw err;
    }
  }

  async save(caseId: string, record: ClockSkewRecord): Promise<ClockSkewRecord> {
    await mkdir(this.cases.stateDir(caseId), { recursive: true });
    const clean: ClockSkewRecord = {
      alignEnabled: record.alignEnabled === true,
      results: Array.isArray(record.results) ? record.results : [],
      updatedAt: new Date().toISOString(),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(clean, null, 2));
    return clean;
  }

  async setAlign(caseId: string, alignEnabled: boolean): Promise<ClockSkewRecord> {
    const current = await this.load(caseId);
    return this.save(caseId, { ...current, alignEnabled });
  }
}
