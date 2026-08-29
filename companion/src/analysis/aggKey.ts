// The length bound on an importer's aggregation key.
//
// A key is a DISCRIMINATOR, and a collision does not merely miscount: the aggregator keeps ONE row
// and applyEventIdentity overwrites its path, hash and description with whichever row landed last,
// so two rows sharing a key DELETE one row's evidence. Keys are length-capped so one pathological
// row cannot blow up the key set, and that cap must never be paid for by a discriminator.
//
// Build the key with the short fields (host, rule, action) FIRST and the unbounded one (a path, a
// URL, a command line) LAST, then bound it here. A key that already fits comes back untouched, so
// nothing that aggregates correctly today starts aggregating differently. An over-long key keeps a
// digest of the FULL key in its tail, so two values sharing a 400-character prefix stay two rows.
//
// Both halves were learned from real collections. A deep path pushed the trailing host out of a
// BinaryRename key, and one renamed binary found on two machines came back as one finding on one
// machine (#670 — the cross-host merge #659 fixed for Windows events, arriving by another route).
// The same deep path collapsed two distinct binaries under one directory into a single row. The
// Velociraptor and CLI YARA mappers reached the bound the same way.

import { createHash } from "node:crypto";

const AGG_KEY_MAX = 400;
const AGG_KEY_DIGEST = 16; // 64 bits of hex — collision-free at any case's row count

export function boundedAggKey(key: string): string {
  if (key.length <= AGG_KEY_MAX) return key;
  const digest = createHash("sha256").update(key).digest("hex").slice(0, AGG_KEY_DIGEST);
  return `${key.slice(0, AGG_KEY_MAX - AGG_KEY_DIGEST - 1)}#${digest}`;
}
