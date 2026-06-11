import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { sanitizeCustomEntities } from "./anonEntities.js";
import type { CustomEntity } from "./anonymize.js";

// Entities the companion DISCOVERED while anonymizing screenshots (the OCR pass reports which
// values it tokenized), plus the values the analyst REMOVED from that list. Persisted per case so
// the auto-discovery list survives restarts and a removed false positive stays removed.
//
// `discovered` feeds the anonymizer as exact-match entities (so the same value is tokenized
// consistently on later runs); `suppressed` is the analyst's "this isn't a real entity" veto —
// those values are never tokenized again (the anonymizer skips them) and are hidden from the list.
export interface AnonDiscovered {
  discovered: CustomEntity[];
  suppressed: string[]; // lowercased values
}

const MAX_DISCOVERED = 2000;

export function emptyDiscovered(): AnonDiscovered {
  return { discovered: [], suppressed: [] };
}

// Normalize a stored/loaded blob into a valid AnonDiscovered (defensive against hand-edits).
export function sanitizeDiscovered(raw: unknown): AnonDiscovered {
  const obj = (raw ?? {}) as { discovered?: unknown; suppressed?: unknown };
  const suppressed = Array.isArray(obj.suppressed)
    ? [...new Set(obj.suppressed.filter((s): s is string => typeof s === "string" && s.trim().length > 0).map((s) => s.trim().toLowerCase()))]
    : [];
  const suppressedSet = new Set(suppressed);
  const discovered = sanitizeCustomEntities(obj.discovered).filter((e) => !suppressedSet.has(e.value.toLowerCase()));
  return { discovered: discovered.slice(0, MAX_DISCOVERED), suppressed };
}

// Merge newly-discovered entities into the existing set: dedupe by value (case-insensitive),
// drop anything currently suppressed, and cap the total. Pure — returns a new object.
export function mergeDiscovered(prev: AnonDiscovered, add: CustomEntity[]): AnonDiscovered {
  const suppressedSet = new Set(prev.suppressed);
  const seen = new Set(prev.discovered.map((e) => e.value.toLowerCase()));
  const discovered = [...prev.discovered];
  for (const e of sanitizeCustomEntities(add)) {
    const key = e.value.toLowerCase();
    if (suppressedSet.has(key) || seen.has(key)) continue;
    seen.add(key);
    discovered.push(e);
    if (discovered.length >= MAX_DISCOVERED) break;
  }
  return { discovered, suppressed: prev.suppressed };
}

// Remove a value: add it to the suppression veto and drop it from the discovered list. Pure.
export function suppressValue(prev: AnonDiscovered, value: string): AnonDiscovered {
  const v = value.trim().toLowerCase();
  if (!v) return prev;
  const suppressed = prev.suppressed.includes(v) ? prev.suppressed : [...prev.suppressed, v];
  return { discovered: prev.discovered.filter((e) => e.value.toLowerCase() !== v), suppressed };
}

// Un-remove a value: lift the veto so it can be auto-discovered / tokenized again. Pure.
export function unsuppressValue(prev: AnonDiscovered, value: string): AnonDiscovered {
  const v = value.trim().toLowerCase();
  return { discovered: prev.discovered, suppressed: prev.suppressed.filter((s) => s !== v) };
}

export class DiscoveredEntitiesStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "anon-discovered.json");
  }

  async load(caseId: string): Promise<AnonDiscovered> {
    try {
      return sanitizeDiscovered(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyDiscovered();
      throw err;
    }
  }

  async save(caseId: string, data: AnonDiscovered): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(sanitizeDiscovered(data), null, 2));
  }

  async addDiscovered(caseId: string, entities: CustomEntity[]): Promise<AnonDiscovered> {
    if (entities.length === 0) return this.load(caseId);
    const next = mergeDiscovered(await this.load(caseId), entities);
    await this.save(caseId, next);
    return next;
  }

  async suppress(caseId: string, value: string): Promise<AnonDiscovered> {
    const next = suppressValue(await this.load(caseId), value);
    await this.save(caseId, next);
    return next;
  }

  async unsuppress(caseId: string, value: string): Promise<AnonDiscovered> {
    const next = unsuppressValue(await this.load(caseId), value);
    await this.save(caseId, next);
    return next;
  }
}
