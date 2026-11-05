// The parse-loop half of cloud-record dedup (#2301): what an importer's per-record loop does with
// the ledger's verdict for record `index`, BEFORE aggregation. Pure.
//
//  - duplicate → the record maps to no row at all (it is already in the case);
//  - new       → its rows carry the record's identity (`recordRefs`), which the aggregator folds into
//                the group's provenance;
//  - conflict  → its rows are kept, flagged, and keyed apart from the rows they would otherwise fold
//                into, so the flag stays on a row of its own the analyst can see.
//
// Skipping by index inside the importer's own loop keeps every `record:<index>` locator pointing at
// the original upload. Summaries built over the whole record array take `gateRecords()`, which blanks
// a duplicate in place instead of removing it, for the same reason.

import type { MappedEvent } from "./siemImport.js";
import type { CloudRecordIdentity } from "./cloudRecordIdentity.js";
import type { RecordVerdict } from "./cloudRecordStore.js";
import type { AggregateProvenance } from "./eventAggregate.js";
import type { JsonRepairs } from "./tolerantJson.js";

export interface RecordGate {
  identities: readonly CloudRecordIdentity[]; // by record index
  verdicts: readonly RecordVerdict[]; // by record index
}

/** What a gated cloud parser accepts from the ingest layer (cloudRecordIngest.ts). */
export interface CloudRecordParseOptions {
  records?: Array<Record<string, unknown>>; // pre-extracted, so the upload is read once
  repairs?: JsonRepairs; // what the tolerant reader repaired while pre-reading them (#2302)
  recordGate?: RecordGate; // the case ledger's verdict per record
  provenance?: AggregateProvenance; // aggregate → source-record membership sink
  // Streaming import (#2303): the records are one batch of a larger file. `recordIndexBase` is the
  // batch's offset, so `record:<index>` locators still point into the upload; `rowsOnly` returns
  // the mapped rows unaggregated (the streaming importer budgets them) and skips the summaries.
  recordIndexBase?: number;
  rowsOnly?: boolean;
}

// Appended to a conflicting row's description: the conflict must be visible on the row itself.
export const RECORD_CONFLICT_NOTE =
  " [record id conflict: an earlier import holds a different record under the same id — both kept]";

/** True when record `index` is a duplicate the importer must not map. */
export function isDuplicateRecord(gate: RecordGate | undefined, index: number): boolean {
  return gate?.verdicts[index] === "duplicate";
}

/** The rows of record `index`, stamped with its identity — or none when it is a duplicate. */
export function gateRows(gate: RecordGate | undefined, index: number, rows: MappedEvent[]): MappedEvent[] {
  if (!gate) return rows;
  const verdict = gate.verdicts[index];
  const identity = gate.identities[index];
  if (verdict === "duplicate") return [];
  if (!identity) return rows;
  const conflict = verdict === "conflict";
  return rows.map((row) => ({
    ...row,
    recordRefs: [identity.key],
    recordHashes: [identity.payloadHash],
    ...(identity.hashIdentified ? { recordHashIdentified: true } : {}),
    ...(conflict
      ? {
          recordConflict: true,
          aggKey: `${row.aggKey}|record-conflict`,
          description: row.description + RECORD_CONFLICT_NOTE,
        }
      : {}),
  }));
}

/** `records` with every duplicate blanked in place (indices kept), for whole-upload summaries. */
export function gateRecords<T extends Record<string, unknown>>(
  gate: RecordGate | undefined,
  records: T[],
): T[] {
  if (!gate) return records;
  return records.map((rec, i) => (isDuplicateRecord(gate, i) ? ({} as T) : rec));
}
