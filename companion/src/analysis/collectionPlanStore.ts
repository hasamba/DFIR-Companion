import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { CollectionOverride } from "./collectionPlan.js";

// Per-case collection-plan overrides (#347), in state/collection-plan.json. A stateless wrapper
// over CaseStore (mirrors IncidentTypeStore / ClockSkewStore). Only the analyst's assertions live
// here — every derived state is recomputed from the timeline on read, so there is nothing to stale.

const overrideSchema = z.object({
  state: z.enum(["collected", "na"]),
  reason: z.string().catch(""),
});

// A malformed entry is dropped, not defaulted: an override is an analyst assertion, and inventing
// one would silently mark evidence collected that nobody vouched for.
const recordSchema = z.object({
  overrides: z.record(z.string(), overrideSchema.nullable().catch(null)).catch({}),
});

export type CollectionOverrides = Record<string, CollectionOverride>;

export class CollectionPlanStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "collection-plan.json");
  }

  async load(caseId: string): Promise<CollectionOverrides> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
    try {
      const parsed = recordSchema.parse(JSON.parse(raw));
      const out: CollectionOverrides = {};
      for (const [stepId, override] of Object.entries(parsed.overrides)) {
        if (override) out[stepId] = override;
      }
      return out;
    } catch {
      // Corrupt file — the panel still renders from derived state.
      return {};
    }
  }

  private async save(caseId: string, overrides: CollectionOverrides): Promise<CollectionOverrides> {
    await atomicWrite(this.path(caseId), JSON.stringify({ overrides }, null, 2));
    return overrides;
  }

  async set(caseId: string, stepId: string, override: CollectionOverride): Promise<CollectionOverrides> {
    const current = await this.load(caseId);
    return this.save(caseId, { ...current, [stepId]: override });
  }

  async clear(caseId: string, stepId: string): Promise<CollectionOverrides> {
    const current = await this.load(caseId);
    if (!(stepId in current)) return current;
    const { [stepId]: _removed, ...rest } = current;
    return this.save(caseId, rest);
  }
}
