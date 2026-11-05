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
  entity: StoredSnapshotObservation & { importBatch?: string; active?: boolean };
}

// Undo (#2305, mirroring #2301's cloud-record ledger). Every observation row carries the import
// batch that wrote it — the import's stored file name — and the same appendEntities call (one SQLite
// transaction) writes a `batch:<name>` marker row, so an undo checkpoint can always claim a batch
// whose rows exist. Undo appends a `batch-state:<name>` row {active:false}, Redo one {active:true};
// the latest such row wins. history() ignores the rows of a batch an Undo forgot.
const batchMarker = (batch: string): string => `batch:${batch}`;
const batchState = (batch: string): string => `batch-state:${batch}`;

// The stored file name inside an undo checkpoint label ("cloudsnapshot (0003_x.csv)" → "0003_x.csv").
function storedNameOf(checkpointLabel: string): string {
  return /\(([^()]+)\)$/.exec(checkpointLabel)?.[1] ?? checkpointLabel;
}

export class CloudStateStore {
  constructor(private readonly cases: CaseStore) {}

  private databasePath(caseId: string): string {
    return join(this.cases.stateDir(caseId), INVESTIGATION_DB_FILENAME);
  }

  private rows(caseId: string, ids: string[]): Promise<EntityRow[]> {
    return caseSqliteWorker.request<EntityRow[]>({
      op: "entityRows",
      dbPath: this.databasePath(caseId),
      kind: KIND,
      ids,
    });
  }

  /** The batches among `batches` an Undo forgot (latest state row wins; rows come in write order). */
  private async inactive(caseId: string, batches: readonly string[]): Promise<Set<string>> {
    const latest = new Map<string, boolean>();
    for (let i = 0; i < batches.length; i += CHUNK) {
      const rows = await this.rows(caseId, batches.slice(i, i + CHUNK).map(batchState));
      for (const { entity } of rows) latest.set(entity.id, entity.active !== false);
    }
    return new Set(batches.filter((b) => latest.get(batchState(b)) === false));
  }

  /** Every stored observation of each identity id, grouped by id; rows of forgotten batches left out. */
  async history(caseId: string, ids: readonly string[]): Promise<Map<string, StoredSnapshotObservation[]>> {
    const unique = [...new Set(ids)];
    const found: EntityRow["entity"][] = [];
    for (let i = 0; i < unique.length; i += CHUNK) {
      for (const { entity } of await this.rows(caseId, unique.slice(i, i + CHUNK))) found.push(entity);
    }
    const batches = [...new Set(found.map((e) => e.importBatch).filter((b): b is string => !!b))];
    const forgotten = await this.inactive(caseId, batches);
    const out = new Map<string, StoredSnapshotObservation[]>();
    for (const e of found) {
      if (e.importBatch && forgotten.has(e.importBatch)) continue;
      const { id, observedAt, stateHash, state } = e;
      out.set(id, [...(out.get(id) ?? []), { id, observedAt, stateHash, state }]);
    }
    return out;
  }

  /**
   * Appends observations stamped with `batch` (the import's stored file name), each chunk together
   * with the batch's marker row in one transaction. The caller passes only non-duplicates.
   */
  async append(
    caseId: string,
    observations: readonly StoredSnapshotObservation[],
    batch: string,
  ): Promise<number> {
    let added = 0;
    for (let i = 0; i < observations.length; i += CHUNK) {
      const rows = observations.slice(i, i + CHUNK).map((o) => ({ ...o, importBatch: batch }));
      added += await caseSqliteWorker.request<number>({
        op: "appendEntities",
        dbPath: this.databasePath(caseId),
        kind: KIND,
        entities: [...rows, { id: batchMarker(batch), batch }],
      });
    }
    return Math.max(0, added - Math.ceil(observations.length / CHUNK));
  }

  /** The observation batch the import an undo checkpoint label names wrote, if it wrote any rows. */
  async claimBatches(caseId: string, checkpointLabel: string): Promise<string[]> {
    const candidates = [...new Set([checkpointLabel, storedNameOf(checkpointLabel)])];
    const held = await caseSqliteWorker.request<string[]>({
      op: "hasEntityIds",
      dbPath: this.databasePath(caseId),
      kind: KIND,
      ids: candidates.map(batchMarker),
    });
    return candidates.filter((c) => held.includes(batchMarker(c)));
  }

  /** Undo forgets a checkpoint's batches (false); Redo remembers them again (true). */
  async setBatchesActive(caseId: string, batches: string[], active: boolean): Promise<void> {
    if (!batches.length) return;
    await caseSqliteWorker.request<number>({
      op: "appendEntities",
      dbPath: this.databasePath(caseId),
      kind: KIND,
      entities: batches.map((b) => ({ id: batchState(b), active })),
    });
  }
}
