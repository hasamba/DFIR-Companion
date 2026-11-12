import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { sanitizeCustomEntities } from "./anonEntities.js";
import type { CustomEntity } from "./anonymize.js";

// Presidio findings this case has not seen before, held until the analyst approves or suppresses
// them. Persisted (rather than kept in memory) because the approval round trip crosses a request
// boundary: the AI call fails with a 409, the analyst resolves the list, then re-runs the action.
//
// The file also records WHICH features the gate held this round (the AI call's label, e.g.
// "synthesis" or "suggest-language-hunts"). Clearing the gate reads it to decide whether the case is
// "ready — press Re-synthesize" or simply back where it was: a held hunt suggestion is re-run from
// its own button, and the conclusions it never touched are not out of date.
//
// The record is sticky for the whole round: a hold adds its feature, an approval keeps it, and only
// the first hold after the list emptied starts a new round. A file written before this field existed
// reports `null` ("unknown") — the caller then assumes a synthesis was held, the old behaviour.

interface PendingFile {
  pending: CustomEntity[];
  heldFeatures: string[] | null;
}

const MAX_FEATURES = 32;
const MAX_FEATURE_CHARS = 64;

function sanitizeFeatures(raw: unknown): string[] | null {
  if (!Array.isArray(raw)) return null;
  const clean = raw
    .filter((f): f is string => typeof f === "string" && f.trim() !== "")
    .map((f) => f.trim().slice(0, MAX_FEATURE_CHARS));
  return [...new Set(clean)].slice(0, MAX_FEATURES);
}

export class PresidioPendingStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "presidio-pending.json");
  }

  private async read(caseId: string): Promise<PendingFile> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as {
        pending?: unknown;
        heldFeatures?: unknown;
      };
      return {
        pending: sanitizeCustomEntities(raw?.pending ?? []),
        heldFeatures: sanitizeFeatures(raw?.heldFeatures),
      };
    } catch (err) {
      // No file: nothing recorded. Only hold() names a feature, so a list saved any other way stays
      // "unknown" and keeps the safe default.
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { pending: [], heldFeatures: null };
      throw err;
    }
  }

  private async write(caseId: string, file: PendingFile): Promise<void> {
    const body = {
      pending: sanitizeCustomEntities(file.pending),
      ...(file.heldFeatures ? { heldFeatures: file.heldFeatures } : {}),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(body, null, 2));
  }

  async load(caseId: string): Promise<CustomEntity[]> {
    return (await this.read(caseId)).pending;
  }

  /** The features the gate held this round; `null` for a file written before they were recorded. */
  async heldFeatures(caseId: string): Promise<string[] | null> {
    return (await this.read(caseId)).heldFeatures;
  }

  /**
   * Replace the pending list and keep the round's held features. The approve and suppress paths use
   * this, so a partial approval never forgets which feature the gate held.
   */
  async save(caseId: string, entities: CustomEntity[]): Promise<void> {
    const current = await this.read(caseId);
    await this.write(caseId, { pending: entities, heldFeatures: current.heldFeatures });
  }

  /**
   * The gate held `feature` on `entities`. Adds the feature to this round's record, or starts a new
   * round when nothing was pending. An unknown (legacy) round stays unknown.
   */
  async hold(caseId: string, entities: CustomEntity[], feature: string): Promise<void> {
    const current = await this.read(caseId);
    const sameRound = current.pending.length > 0;
    const heldFeatures =
      sameRound && current.heldFeatures === null
        ? null
        : sanitizeFeatures([...(sameRound ? (current.heldFeatures ?? []) : []), feature]);
    await this.write(caseId, { pending: entities, heldFeatures });
  }

  async clear(caseId: string): Promise<void> {
    await this.save(caseId, []);
  }
}
