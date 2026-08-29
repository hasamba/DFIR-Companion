import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
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

// Serializes a case's load->modify->save section on anon-discovered.json. atomicWrite stops a TORN
// file, not a LOST one, and losing a write here is not a lost click — it is an unredacted value in
// an exported screenshot.
//
// MODULE-level, and that is the whole point. This file has two writers that are not the same
// object: the OCR pass writes through the store built in composition/aiProviders.ts, and the
// analyst's suppress/unsuppress clicks write through the one built in routes/anonymization.ts. A
// per-instance lock would leave the actual race completely unguarded.
//
// It is also the one store of its class a SOLO analyst can trip. Everywhere else this bug needs two
// people or two tabs; here a background pass is the second writer, so one investigator on one
// laptop is enough. The dangerous direction is losing the OCR write: the entity never enters
// `discovered`, so it is never tokenized, and the real value ships in the redacted export.
//
// Keyed by case id, so a busy case never blocks another, and private to this file, so it can never
// deadlock against the pipeline's investigation-state lock.
const discoveredLock = new StateLock();

export function emptyDiscovered(): AnonDiscovered {
  return { discovered: [], suppressed: [] };
}

// Normalize a stored/loaded blob into a valid AnonDiscovered (defensive against hand-edits).
export function sanitizeDiscovered(raw: unknown): AnonDiscovered {
  const obj = (raw ?? {}) as { discovered?: unknown; suppressed?: unknown };
  const suppressed = Array.isArray(obj.suppressed)
    ? [
        ...new Set(
          obj.suppressed
            .filter((s): s is string => typeof s === "string" && s.trim().length > 0)
            .map((s) => s.trim().toLowerCase()),
        ),
      ]
    : [];
  const suppressedSet = new Set(suppressed);
  const discovered = sanitizeCustomEntities(obj.discovered).filter(
    (e) => !suppressedSet.has(e.value.toLowerCase()),
  );
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

  // PRIVATE, so the lock above cannot be walked around: a caller holding this store could otherwise
  // load, mutate and save outside the critical section and reintroduce the exact race.
  private async save(caseId: string, data: AnonDiscovered): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(sanitizeDiscovered(data), null, 2));
  }

  addDiscovered(caseId: string, entities: CustomEntity[]): Promise<AnonDiscovered> {
    if (entities.length === 0) return this.load(caseId);
    return discoveredLock.runExclusive(caseId, async () => {
      const next = mergeDiscovered(await this.load(caseId), entities);
      await this.save(caseId, next);
      return next;
    });
  }

  suppress(caseId: string, value: string): Promise<AnonDiscovered> {
    return discoveredLock.runExclusive(caseId, async () => {
      const next = suppressValue(await this.load(caseId), value);
      await this.save(caseId, next);
      return next;
    });
  }

  unsuppress(caseId: string, value: string): Promise<AnonDiscovered> {
    return discoveredLock.runExclusive(caseId, async () => {
      const next = unsuppressValue(await this.load(caseId), value);
      await this.save(caseId, next);
      return next;
    });
  }
}
