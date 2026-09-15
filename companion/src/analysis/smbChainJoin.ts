// The join inside one upload for SMB operations (importer half of #933 item 4, #1085 / #1010).
//
// The join key is FILE IDENTITY (`flowId + fuid`), never session + tree. A session+tree pair
// identifies a share CONTEXT (which user, which share) — it does not identify which of possibly
// several concurrently-open files on that share a READ/WRITE/CLOSE belongs to. Grouping by
// session+tree alone would attach a READ on file B to file A's CREATE whenever two files are open
// at once, which is exactly the kind of evidence-integrity mistake this module exists to prevent.
// `sessionId`/`treeId` ride along on every observation as CONTEXT fields; they are never the
// grouping key.
//
// A record carrying no `fuid` (TREE_CONNECT, session setup, negotiate — anything that isn't a
// file operation) becomes its own single-operation chain, keyed by its own locator so it is never
// merged with an unrelated chain and never silently attached to "the latest" CREATE.
//
// Every bucket is bounded (SMB_BUCKET_MAX): a file with more operations than that keeps its CREATE
// (needed for the open-vs-create fact) plus the most recent operations, and the row states the
// true total — never "first N seen, denial or not."

import type { SmbObservation } from "./smbChainRead.js";

/** Observations retained; records past it are counted, never read or joined. */
export const SMB_OBSERVATIONS_MAX = 65_536;
/** Operations kept per file (`flowId + fuid`); the rest are counted, never silently dropped. */
export const SMB_BUCKET_MAX = 64;

export interface SmbOperations {
  observations: SmbObservation[];
  /** Records past SMB_OBSERVATIONS_MAX — never read, never joined. */
  overflow: number;
}

export function emptySmbOperations(): SmbOperations {
  return { observations: [], overflow: 0 };
}

export function addSmb(sink: SmbOperations, o: SmbObservation): void {
  if (sink.observations.length >= SMB_OBSERVATIONS_MAX) {
    sink.overflow++;
    return;
  }
  sink.observations.push(o);
}

export type SmbJoinState =
  /** Matched to a CREATE sharing this record's `flowId + fuid`. */
  | "joined"
  /** No `fuid` on this record at all — a TREE_CONNECT, negotiate, or session-setup row. */
  | "no fuid on this record"
  /** A `fuid` is present but no CREATE for it was read in this upload. */
  | "no matching file record in this upload";

export interface SmbChain {
  /** `${flowId}|${fuid}` when both are present; otherwise this record's own locator. */
  key: string;
  /** The CREATE sharing this file identity, if one was read. */
  create?: SmbObservation;
  /** READ/WRITE/CLOSE/etc. sharing this file identity, in the order they were read. */
  operations: SmbObservation[];
  /** Count of operations before SMB_BUCKET_MAX truncation. */
  operationsTotal: number;
  joinState: SmbJoinState;
}

function fileKey(o: SmbObservation): string | undefined {
  return o.fuid ? `${o.flowId ?? ""}|${o.fuid}` : undefined;
}

interface ChainBuild {
  key: string;
  create?: SmbObservation;
  operations: SmbObservation[]; // every non-CREATE operation for this key, read order, uncapped
}

/**
 * Group observations by file identity. A CREATE for a key is recorded once (the first one read —
 * a second CREATE for the same fuid is unusual and is kept as an ordinary operation, a fact the
 * row layer can show, never silently dropped). Every other observation sharing the key is
 * collected in read order; the bucket is capped to the MOST RECENT SMB_BUCKET_MAX only after every
 * observation is seen, so a late denial is never hidden behind an early run of successes.
 */
export function joinSmbChains(ops: SmbOperations): SmbChain[] {
  const byKey = new Map<string, ChainBuild>();
  const unkeyed: SmbChain[] = [];

  for (const o of ops.observations) {
    const key = fileKey(o);
    if (!key) {
      unkeyed.push({
        key: o.locator,
        operations: [o],
        operationsTotal: 1,
        joinState: "no fuid on this record",
      });
      continue;
    }
    let build = byKey.get(key);
    if (!build) {
      build = { key, operations: [] };
      byKey.set(key, build);
    }
    const isCreate = o.command === "SMB2_COMMAND_CREATE" || o.command === "CREATE";
    if (isCreate && !build.create) {
      build.create = o;
      continue;
    }
    build.operations.push(o);
  }

  const chains: SmbChain[] = [];
  for (const build of byKey.values()) {
    const operationsTotal = build.operations.length;
    const kept =
      operationsTotal > SMB_BUCKET_MAX ? build.operations.slice(-SMB_BUCKET_MAX) : build.operations;
    const joinState: SmbJoinState = build.create
      ? "joined"
      : operationsTotal > 0
        ? "no matching file record in this upload"
        : "joined"; // a CREATE with no operations at all is still a joined (single-record) chain
    chains.push({ key: build.key, create: build.create, operations: kept, operationsTotal, joinState });
  }

  return [...chains, ...unkeyed];
}
