import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { AnonTokenCategory, CustomEntity } from "./anonymize.js";
import { bumpAnonRevision } from "./anonRevision.js";

const VALID: readonly AnonTokenCategory[] = [
  "IP",
  "EXTIP",
  "EMAIL",
  "USER",
  "HOST",
  "DOMAIN",
  "PATH",
  "CMD",
  "REG",
  "CARD",
  "PHONE",
  "NATID",
  "PERSON",
  "OTHER",
];

// The most custom entities a case keeps. sanitizeCustomEntities drops everything past it.
export const MAX_CUSTOM_ENTITIES = 500;

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
    const category: AnonTokenCategory = VALID.includes(rawCat as AnonTokenCategory)
      ? (rawCat as AnonTokenCategory)
      : "OTHER";
    out.push({ value, category });
    if (out.length >= MAX_CUSTOM_ENTITIES) break;
  }
  return out;
}

// Per-case list of analyst-added entities to anonymize, persisted to state/anon-entities.json.
//
// The file carries a `version` (#1839): a counter bumped by EVERY save, including a save that
// leaves the list unchanged (a "Hide from AI" on a value already listed). The custom-entity editor
// sends the version it loaded, and a save from a stale base is refused — so a second window can
// never erase a value the analyst just hid. A counter, not a content hash, for exactly that
// re-hide: the contents do not change, but the editor's pending removal of the value is now stale.
// Every writer runs under presidioDecisions.ts's per-case lock, which makes the read-increment-write
// here safe.
export interface VersionedCustomEntities {
  entities: CustomEntity[];
  version: number;
}

export class CustomEntitiesStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "anon-entities.json");
  }

  async load(caseId: string): Promise<CustomEntity[]> {
    return (await this.loadVersioned(caseId)).entities;
  }

  async loadVersioned(caseId: string): Promise<VersionedCustomEntities> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as {
        entities?: unknown;
        version?: unknown;
      };
      const version =
        Number.isSafeInteger(raw?.version) && (raw.version as number) >= 0 ? (raw.version as number) : 0;
      return { entities: sanitizeCustomEntities(raw?.entities ?? raw), version };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { entities: [], version: 0 };
      throw err;
    }
  }

  /** Replace the list and bump its version. Returns the new version. */
  async save(caseId: string, entities: CustomEntity[]): Promise<number> {
    try {
      const version = (await this.loadVersioned(caseId)).version + 1;
      await atomicWrite(
        this.path(caseId),
        JSON.stringify({ entities: sanitizeCustomEntities(entities), version }, null, 2),
      );
      return version;
    } finally {
      bumpAnonRevision(caseId); // #1840: an AI call being prepared masks again before it sends
    }
  }
}
