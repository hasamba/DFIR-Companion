import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { sanitizeCustomEntities } from "./anonEntities.js";
import type { CustomEntity } from "./anonymize.js";

// Presidio findings this case has not seen before, held until the analyst approves or suppresses
// them. Persisted (rather than kept in memory) because the approval round trip crosses a request
// boundary: the AI call fails with a 409, the analyst resolves the list, then re-runs the action.
export class PresidioPendingStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "presidio-pending.json");
  }

  async load(caseId: string): Promise<CustomEntity[]> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as { pending?: unknown };
      return sanitizeCustomEntities(raw?.pending ?? []);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async save(caseId: string, entities: CustomEntity[]): Promise<void> {
    await atomicWrite(
      this.path(caseId),
      JSON.stringify({ pending: sanitizeCustomEntities(entities) }, null, 2),
    );
  }

  async clear(caseId: string): Promise<void> {
    await this.save(caseId, []);
  }
}
