// Per-case, disk-backed cloud-record ledger and provenance relation (#2301).
//
// Two jobs, one store, both in the case SQLite database (INVESTIGATION_DB_FILENAME) through
// caseSqliteWorker's generic kind-based entities table — the same approach authObservationStore.ts
// and superTimelineStore.ts take, so no new table, migration or storage dependency:
//
//  1. Dedup ledger (kind "cloudRecord"): every record identity (cloudRecordIdentity.ts) a cloud
//     import kept, with its payload hash. `classify()` answers, BEFORE aggregation, whether each
//     record of a batch is new, a duplicate (same id, same payload — skipped), or a conflict (same
//     id, different payload — kept and flagged). `commit()` records the kept ones only after the
//     import's merge saved, so a failed import never marks its records as seen.
//  2. Provenance relation (kind "cloudRecordMember"): aggregated event group → member records, so
//     an event that stands for a million source records carries a bounded list of references plus
//     a count, and the analyst pages through the rest (`pageMembers`).
//
// The API is batch-shaped on purpose (#2303's streaming import calls it once per batch). Internal
// bookkeeping: never read by AI. Domain analysis/ingest, the tier of its sibling authObservationStore.

import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";
import type { CloudRecordIdentity } from "./cloudRecordIdentity.js";
import { CloudRecordBatches } from "./cloudRecordBatches.js";

export type RecordVerdict = "new" | "duplicate" | "conflict";

export interface RecordVerdicts {
  verdicts: RecordVerdict[]; // one per identity, same order
  duplicates: number;
  conflicts: number;
}

export interface SourceRecordMember {
  group: string; // the aggregated event's sourceRecords.group
  ref: string; // the member record's identity key
  payloadHash?: string; // which payload under that key (two differ on a conflict)
  locator?: string; // where the record sits in its upload, e.g. "record:12"
}

export interface SourceRecordPage {
  members: Array<{ ref: string; locator?: string }>;
  next: number | null; // pass as `after` for the next page; null on the last page
  total: number;
}

const LEDGER_KIND = "cloudRecord";
const MEMBER_KIND = "cloudRecordMember";
// entityRows/appendEntities each build one JSON array per call — chunked like authObservationStore.
const CHUNK_SIZE = 5_000;

interface LedgerRow {
  id: string;
  payloadHash: string;
  importBatch?: string;
}

function chunks<T>(items: readonly T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += CHUNK_SIZE) out.push(items.slice(i, i + CHUNK_SIZE));
  return out;
}

/** The verdict for each identity given the payload hashes already known per key. Pure. */
export function verdictsFor(
  identities: readonly CloudRecordIdentity[],
  known: ReadonlyMap<string, ReadonlySet<string>>,
): RecordVerdicts {
  const seen = new Map<string, Set<string>>();
  let duplicates = 0;
  let conflicts = 0;
  const verdicts = identities.map((id): RecordVerdict => {
    const hashes = new Set([...(known.get(id.key) ?? []), ...(seen.get(id.key) ?? [])]);
    seen.set(id.key, new Set([...(seen.get(id.key) ?? []), id.payloadHash]));
    if (hashes.has(id.payloadHash)) {
      duplicates++;
      return "duplicate";
    }
    if (hashes.size) {
      conflicts++;
      return "conflict";
    }
    return "new";
  });
  return { verdicts, duplicates, conflicts };
}

export class CloudRecordStore {
  private readonly batches: CloudRecordBatches;

  constructor(private readonly cases: CaseStore) {
    this.batches = new CloudRecordBatches(cases);
  }

  /** Notes the batch an import committed, for its undo checkpoint to claim (cloudRecordBatches.ts). */
  notePending(caseId: string, batch: string, storedName: string): Promise<void> {
    return this.batches.notePending(caseId, batch, storedName);
  }

  /** The batches the import an undo checkpoint label names committed; they leave the pending list. */
  claimPending(caseId: string, checkpointLabel: string): Promise<string[]> {
    return this.batches.claimPending(caseId, checkpointLabel);
  }

  /** Undo forgets a checkpoint's batches (false); Redo remembers them again (true). */
  setBatchesActive(caseId: string, batches: string[], active: boolean): Promise<void> {
    return this.batches.setActive(caseId, batches, active);
  }

  private databasePath(caseId: string): string {
    return join(this.cases.stateDir(caseId), INVESTIGATION_DB_FILENAME);
  }

  private async knownHashes(caseId: string, keys: readonly string[]): Promise<Map<string, Set<string>>> {
    const known = new Map<string, Set<string>>();
    const dbPath = this.databasePath(caseId);
    // A batch an Undo forgot holds no records the case still has (#2301).
    const inactive = await this.batches.inactive(caseId);
    for (const ids of chunks([...new Set(keys)])) {
      const rows = await caseSqliteWorker.request<Array<{ entity: LedgerRow }>>({
        op: "entityRows",
        dbPath,
        kind: LEDGER_KIND,
        ids,
      });
      for (const { entity } of rows)
        if (!entity.importBatch || !inactive.has(entity.importBatch))
          known.set(entity.id, new Set([...(known.get(entity.id) ?? []), entity.payloadHash]));
    }
    return known;
  }

  /** Classifies a batch against the ledger AND against itself (a record twice in one file). Read-only. */
  async classify(caseId: string, identities: readonly CloudRecordIdentity[]): Promise<RecordVerdicts> {
    if (!identities.length) return { verdicts: [], duplicates: 0, conflicts: 0 };
    return verdictsFor(
      identities,
      await this.knownHashes(
        caseId,
        identities.map((i) => i.key),
      ),
    );
  }

  /**
   * Records every identity the import kept (verdict new or conflict) that the ledger does not hold
   * yet, stamped with the import batch. Call after the import's merge saved. Returns rows written.
   */
  async commit(
    caseId: string,
    identities: readonly CloudRecordIdentity[],
    verdicts: readonly RecordVerdict[],
    importBatch: string,
  ): Promise<number> {
    const kept = identities.filter((_, i) => verdicts[i] !== "duplicate");
    if (!kept.length) return 0;
    const known = await this.knownHashes(
      caseId,
      kept.map((k) => k.key),
    );
    const unique = new Map<string, CloudRecordIdentity>();
    for (const id of kept) {
      if (!known.get(id.key)?.has(id.payloadHash)) unique.set(`${id.key}\n${id.payloadHash}`, id);
    }
    const dbPath = this.databasePath(caseId);
    let added = 0;
    for (const batch of chunks([...unique.values()])) {
      const entities = batch.map((id) => ({
        id: id.key,
        payloadHash: id.payloadHash,
        ...(id.hashIdentified ? { hashIdentified: true } : {}),
        importBatch,
      }));
      added += await caseSqliteWorker.request<number>({
        op: "appendEntities",
        dbPath,
        kind: LEDGER_KIND,
        entities,
      });
    }
    return added;
  }

  /** Appends group → member rows. The group key is stored in the indexed host column (`asset`). */
  async recordMembers(caseId: string, members: readonly SourceRecordMember[]): Promise<number> {
    const dbPath = this.databasePath(caseId);
    let added = 0;
    for (const batch of chunks(members)) {
      const entities = batch.map((m) => ({
        asset: m.group,
        ref: m.ref,
        ...(m.payloadHash ? { payloadHash: m.payloadHash } : {}),
        ...(m.locator ? { locator: m.locator } : {}),
      }));
      added += await caseSqliteWorker.request<number>({
        op: "appendEntities",
        dbPath,
        kind: MEMBER_KIND,
        entities,
      });
    }
    return added;
  }

  /** One page of a group's member records, in the order they were recorded. */
  async pageMembers(
    caseId: string,
    group: string,
    page: { after?: number; limit?: number } = {},
  ): Promise<SourceRecordPage> {
    return caseSqliteWorker.request<SourceRecordPage>({
      op: "cloudMembersPage",
      dbPath: this.databasePath(caseId),
      group,
      afterRowId: page.after ?? 0,
      limit: page.limit,
    });
  }
}
