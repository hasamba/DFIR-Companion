import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case IOC alias map (#82): duplicate IOC value (lowercased) -> canonical IOC id it was
// merged into. Kept in `state/ioc-aliases.json`, NOT in InvestigationState, so re-synthesis never
// wipes it (same pattern as asset-overrides.json). stateMerge.ts's mergeDelta consults this map
// BEFORE its own exact-value dedup so that if the AI re-extracts the same near-duplicate value
// from new source text later, it's routed straight onto the canonical IOC instead of recreating
// the duplicate — "synthesis re-merge preserves the alias".

export const iocAliasSchema = z.object({
  aliases: z.record(z.string(), z.string()).default({}),
}).catch({ aliases: {} });

export type IocAliasMap = z.infer<typeof iocAliasSchema>;

export function emptyIocAliasMap(): IocAliasMap {
  return { aliases: {} };
}

// Canonical IOC id for a value the analyst previously merged away, or undefined if none.
export function resolveIocAlias(value: string, map: IocAliasMap): string | undefined {
  return map.aliases[value.trim().toLowerCase()];
}

export class IocAliasStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "ioc-aliases.json");
  }

  async load(caseId: string): Promise<IocAliasMap> {
    try {
      return iocAliasSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyIocAliasMap();
      throw err;
    }
  }

  private async save(caseId: string, map: IocAliasMap): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(map, null, 2));
  }

  // Record that `value` (the merged-away duplicate's value) should route onto `intoId` going
  // forward. Idempotent.
  async add(caseId: string, value: string, intoId: string): Promise<IocAliasMap> {
    const map = await this.load(caseId);
    const next = { aliases: { ...map.aliases, [value.trim().toLowerCase()]: intoId } };
    await this.save(caseId, next);
    return next;
  }

  // Un-merge: stop auto-routing this value onto its former canonical IOC.
  async remove(caseId: string, value: string): Promise<IocAliasMap> {
    const map = await this.load(caseId);
    const aliases = { ...map.aliases };
    delete aliases[value.trim().toLowerCase()];
    const next = { aliases };
    await this.save(caseId, next);
    return next;
  }
}
