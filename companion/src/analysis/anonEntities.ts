import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { AnonTokenCategory, CustomEntity } from "./anonymize.js";

const VALID: readonly AnonTokenCategory[] = ["IP", "EMAIL", "USER", "HOST", "DOMAIN", "PATH", "CMD", "REG", "OTHER"];

// Sanitize a raw entity list: trim, drop blanks, coerce unknown categories to OTHER, dedupe by
// value (case-insensitive, first wins), cap the count. Pure — safe to run on stored OR posted data.
export function sanitizeCustomEntities(raw: unknown): CustomEntity[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: CustomEntity[] = [];
  for (const item of raw) {
    const rawValue = (item as { value?: unknown })?.value;
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const rawCat = (item as { category?: unknown })?.category;
    const category: AnonTokenCategory = VALID.includes(rawCat as AnonTokenCategory) ? (rawCat as AnonTokenCategory) : "OTHER";
    out.push({ value, category });
    if (out.length >= 500) break;
  }
  return out;
}

// Per-case list of analyst-added entities to anonymize, persisted to state/anon-entities.json.
export class CustomEntitiesStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "anon-entities.json");
  }

  async load(caseId: string): Promise<CustomEntity[]> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as { entities?: unknown };
      return sanitizeCustomEntities(raw?.entities ?? raw);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async save(caseId: string, entities: CustomEntity[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify({ entities: sanitizeCustomEntities(entities) }, null, 2));
  }
}
