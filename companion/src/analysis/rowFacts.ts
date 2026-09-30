import { createHash } from "node:crypto";
import { getAppVersion } from "../version.js";
import { canonicalize } from "./analysisRunHash.js";
import { CANONICAL_EVENT_SCHEMA_VERSION, upgradeForensicEvent } from "./canonicalEvent.js";
import { wouldDeobfuscate } from "./applyDeobfuscation.js";
import { DECODER_VERSION } from "./deobfuscateLayers.js";
import { normalizeHash } from "./nsrl.js";
import { keyOf } from "./timelineDiff.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { StateStore } from "./stateStore.js";
import type { PendingFactRow, RowFactRecord } from "./caseSqliteWorkerFacts.js";

/**
 * Per-row facts (#1874): what the per-import passes need to know about each forensic and IOC row,
 * computed once from the stored row and kept in the case database (caseSqliteWorkerFacts.ts) until
 * the row is written again. The run record's digest, the deobfuscation sweep's candidates, the NSRL
 * sweep's hashes and the import diff's keys used to be recomputed by reading every row of the case
 * after every import.
 *
 * Every fact is a function of the row as the loaders return it — upgradeForensicEvent applied to a
 * forensic row, an IOC as stored — plus, for the diff key, the three raw fields the keyed outline
 * reads. Bump ROW_FACTS_VERSION whenever what a fact means changes; the stamp also carries the build
 * and the versions of the two pieces of code the facts lean on, so an upgrade recomputes them.
 */
export const ROW_FACTS_VERSION = 1;
const FACTS_PAGE = 2000;
const MAX_REFRESH_ROUNDS = 5000;

export function rowFactsStamp(): string {
  return `${ROW_FACTS_VERSION}:${getAppVersion()}:${DECODER_VERSION}:${CANONICAL_EVENT_SCHEMA_VERSION}`;
}

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

/** One item's digest in the run record's state hash: SHA-256 of its canonical JSON, lowercase hex. */
export function itemDigest(value: unknown): string {
  return sha256(JSON.stringify(canonicalize(value)) ?? "null");
}

/** What the index stores for a timeline diff key (the key itself can be as long as a description). */
export function diffKeyDigest(key: string): string {
  return sha256(key);
}

/** The timeline diff key of a row's three raw fields, exactly as diffTimeline keys an outline row. */
export function diffKeyOfFields(timestamp: unknown, description: unknown): string {
  return keyOf({ timestamp: timestamp as string, description: description as string });
}

const idOf = (value: unknown): string | null => {
  const id = (value as { id?: unknown } | null)?.id;
  return typeof id === "string" ? id : null;
};

/** A forensic row's facts, from its stored payload. */
export function forensicFacts(payload: unknown): Omit<RowFactRecord, "rowId" | "seq"> {
  const raw = payload as ForensicEvent;
  const event = upgradeForensicEvent(raw);
  return {
    id: idOf(event),
    digest: itemDigest(event),
    diffKey: diffKeyDigest(diffKeyOfFields(raw?.timestamp, raw?.description)),
    deob: wouldDeobfuscate(event),
    sha: normalizeHash(event.sha256 ?? ""),
    md5: normalizeHash(event.md5 ?? ""),
  };
}

/** An IOC row's facts, from its stored payload (the loaders return IOCs as stored). */
export function iocFacts(payload: unknown): Omit<RowFactRecord, "rowId" | "seq"> {
  return { id: idOf(payload), digest: itemDigest(payload) };
}

function factsOf(row: PendingFactRow): RowFactRecord {
  const facts = row.kind === "iocs" ? iocFacts(row.payload) : forensicFacts(row.payload);
  return { rowId: row.rowId, seq: row.seq, ...facts };
}

/** The part of StateStore the facts need; a store without it (a test fake) takes the full paths. */
export type FactsStore = Pick<
  StateStore,
  | "factsPending"
  | "factsWrite"
  | "factsFingerprint"
  | "factsCandidates"
  | "forensicKeyFields"
  | "factsKeyHolders"
>;

export function hasRowFacts(store: unknown): store is FactsStore {
  return typeof (store as Partial<FactsStore> | null)?.factsPending === "function";
}

/**
 * Compute and store the facts of every queued row (the rows written since the last refresh). Call it
 * inside the case's state lock, like the passes that read the facts. A row written while its facts
 * were being computed stays queued, and every reader treats it as unknown.
 */
export async function refreshRowFacts(store: FactsStore, caseId: string): Promise<number> {
  const stamp = rowFactsStamp();
  let computed = 0;
  for (let round = 0; round < MAX_REFRESH_ROUNDS; round++) {
    const pending = await store.factsPending(caseId, stamp, FACTS_PAGE);
    if (!pending.length) break;
    const written = await store.factsWrite(caseId, stamp, pending.map(factsOf));
    computed += pending.length;
    // Nothing stored this round (every row raced a writer): leave the rest queued, never spin.
    if (pending.length < FACTS_PAGE || written === 0) break;
  }
  return computed;
}
