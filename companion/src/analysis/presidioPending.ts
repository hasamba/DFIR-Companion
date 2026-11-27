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

// #2985: the list keeps at most MAX_CUSTOM_ENTITIES values (the sanitizer's cap, shared with the
// custom-entity list "Hide from AI" writes to — kept on purpose). A hold with more records how many
// it could not keep, so the panel can say so instead of looking complete. The count lasts while the
// list is non-empty; the re-run's own hold sets it again.

interface PendingFile {
  pending: CustomEntity[];
  heldFeatures: string[] | null;
  notShown: number;
}

/** The pending list and its overflow count, from ONE read — never combine two reads. */
export interface PendingRound {
  pending: CustomEntity[];
  notShown: number;
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

function sanitizeNotShown(raw: unknown): number {
  return typeof raw === "number" && Number.isInteger(raw) && raw > 0 ? raw : 0;
}

/** How many of `entities` the sanitizer would drop for the cap; repeats of a kept value are not counted. */
function countNotKept(entities: readonly CustomEntity[]): number {
  const distinct = new Set(
    entities.map((e) => (typeof e?.value === "string" ? e.value.trim().toLowerCase() : "")).filter(Boolean),
  );
  return Math.max(0, distinct.size - sanitizeCustomEntities(entities).length);
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
        notShown?: unknown;
      };
      return {
        pending: sanitizeCustomEntities(raw?.pending ?? []),
        heldFeatures: sanitizeFeatures(raw?.heldFeatures),
        notShown: sanitizeNotShown(raw?.notShown),
      };
    } catch (err) {
      // No file: nothing recorded. Only hold() names a feature, so a list saved any other way stays
      // "unknown" and keeps the safe default.
      if ((err as NodeJS.ErrnoException).code === "ENOENT")
        return { pending: [], heldFeatures: null, notShown: 0 };
      throw err;
    }
  }

  private async write(caseId: string, file: PendingFile): Promise<void> {
    const pending = sanitizeCustomEntities(file.pending);
    const notShown = pending.length > 0 ? sanitizeNotShown(file.notShown) : 0;
    const body = {
      pending,
      ...(file.heldFeatures ? { heldFeatures: file.heldFeatures } : {}),
      ...(notShown > 0 ? { notShown } : {}),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(body, null, 2));
  }

  async load(caseId: string): Promise<CustomEntity[]> {
    return (await this.read(caseId)).pending;
  }

  /** The list and how many values the hold could not keep (#2985), from one read. */
  async round(caseId: string): Promise<PendingRound> {
    const { pending, notShown } = await this.read(caseId);
    return { pending, notShown };
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
    await this.write(caseId, {
      pending: entities,
      heldFeatures: current.heldFeatures,
      notShown: current.notShown,
    });
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
    await this.write(caseId, { pending: entities, heldFeatures, notShown: countNotKept(entities) });
  }

  async clear(caseId: string): Promise<void> {
    await this.save(caseId, []);
  }
}
