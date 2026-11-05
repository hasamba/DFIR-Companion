// The per-case memory of configuration-snapshot observations (#2305): for every object a snapshot
// named (an inbox rule, a transport rule, an OAuth grant, a user's MFA methods), when it was observed
// and the hash of the state it held. ingest/cloudSnapshotImports.ts reads it to decide whether a
// newly imported snapshot adds anything (cloudSnapshotModel.decide) and appends to it after the
// import's events are merged.
//
// A sibling of authObservationStore.ts over the SAME case SQLite database, reusing the generic
// kind-based entities table (kind "cloudStateObservation") — no new table, no schema migration.
// Append-only: one row per (object, observation time, state); every row of one object shares its
// entity id (the identity hash), so `entityRows` by id returns the object's whole history.
//
// The observation time is stored as `observedAt`, NOT `timestamp`: the entity projection indexes a
// `timestamp` field, and this row is bookkeeping, not a timeline event.
//
// Internal bookkeeping only — never read by the AI, the dashboard or a report. The events the import
// derives from it take the ordinary import → merge → tagger → demote path (CLAUDE.md §7).

import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";
import type { StoredSnapshotObservation } from "./cloudSnapshotModel.js";

const KIND = "cloudStateObservation";
// One json_each list per request, bounded like authObservationStore's append chunks.
const CHUNK = 5_000;

interface EntityRow {
  rowId: number;
  version: number;
  entity: StoredSnapshotObservation;
}

export class CloudStateStore {
  constructor(private readonly cases: CaseStore) {}

  private databasePath(caseId: string): string {
    return join(this.cases.stateDir(caseId), INVESTIGATION_DB_FILENAME);
  }

  /** Every stored observation of each identity id, grouped by id. Ids never observed are absent. */
  async history(caseId: string, ids: readonly string[]): Promise<Map<string, StoredSnapshotObservation[]>> {
    const out = new Map<string, StoredSnapshotObservation[]>();
    const unique = [...new Set(ids)];
    for (let i = 0; i < unique.length; i += CHUNK) {
      const rows = await caseSqliteWorker.request<EntityRow[]>({
        op: "entityRows",
        dbPath: this.databasePath(caseId),
        kind: KIND,
        ids: unique.slice(i, i + CHUNK),
      });
      for (const { entity } of rows) out.set(entity.id, [...(out.get(entity.id) ?? []), entity]);
    }
    return out;
  }

  /** Appends observations. The caller passes only observations decide() did not call duplicates. */
  async append(caseId: string, observations: readonly StoredSnapshotObservation[]): Promise<number> {
    let added = 0;
    for (let i = 0; i < observations.length; i += CHUNK) {
      added += await caseSqliteWorker.request<number>({
        op: "appendEntities",
        dbPath: this.databasePath(caseId),
        kind: KIND,
        entities: observations.slice(i, i + CHUNK),
      });
    }
    return added;
  }
}
