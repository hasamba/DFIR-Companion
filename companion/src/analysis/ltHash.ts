import { createHash } from "node:crypto";

/**
 * LtHash (Lewi, Kim, Maykov, Weis 2019), the homomorphic multiset hash under the run record's case
 * fingerprint `investigation-state/v3` (#1887, analysis/analysisRunSnapshot.ts).
 *
 * An item's element is SHAKE128(LT_DOMAIN + its digest) read as LT_LANES little-endian 32-bit lanes.
 * A multiset's sum is the lane-wise sum of its items' elements mod 2^32 (32-bit lanes, so a multiplicity wraps only past 2^32 copies of one item, far
 * above any case; 16-bit lanes wrapped at 65,536 copies): adding an item adds its
 * element, removing one subtracts it, and a duplicate adds twice. The sum does not depend on the
 * order the items are added in, so the case database keeps it and folds in only the rows a write
 * changed (factsFingerprintV3, caseSqliteWorkerFacts.ts).
 *
 * The worker cannot import this module, so LT_HASH_WORKER_SOURCE is the same arithmetic as plain
 * JS; tests/analysis/fingerprintV3.test.ts holds the two, and a reference written from the
 * definition, equal.
 */
export const LT_LANES = 1024;
export const LT_DOMAIN = "dfir-companion/v3\n";

export type LtSum = Uint32Array;

function element(digest: string): Buffer {
  return createHash("shake128", { outputLength: 4 * LT_LANES })
    .update(LT_DOMAIN + digest)
    .digest();
}

/** The sum of a multiset of item digests. */
export function ltSum(digests: readonly string[]): LtSum {
  const sum = new Uint32Array(LT_LANES);
  for (const digest of digests) {
    const el = element(digest);
    for (let i = 0; i < LT_LANES; i++) sum[i] += el.readUInt32LE(4 * i);
  }
  return sum;
}

/** A sum as lowercase hex of its lanes, each little-endian. */
export function ltHex(sum: LtSum): string {
  const bytes = Buffer.alloc(4 * LT_LANES);
  for (let i = 0; i < LT_LANES; i++) bytes.writeUInt32LE(sum[i], 4 * i);
  return bytes.toString("hex");
}

// The worker's copy (backtick-free, no dollar-brace: it is spliced into a String.raw template).
// Sums travel as Uint32Array; ltWorkerEncode/Decode read and write the little-endian bytes as base64
// (storage) or hex (what the fingerprint hashes).
export const LT_HASH_WORKER_SOURCE =
  "const LT_LANES = " +
  LT_LANES +
  ";\n" +
  "const LT_DOMAIN = " +
  JSON.stringify(LT_DOMAIN) +
  ";\n" +
  String.raw`
const { createHash } = require("node:crypto");

function ltElement(digest) {
  return createHash("shake128", { outputLength: 4 * LT_LANES }).update(LT_DOMAIN + digest).digest();
}

// Add (sign 1) or subtract (sign -1) one item's element; a Uint32Array store wraps mod 2^32.
function ltApply(sum, digest, sign) {
  const el = ltElement(digest);
  for (let i = 0; i < LT_LANES; i++) sum[i] = sum[i] + sign * el.readUInt32LE(4 * i);
}

function ltWorkerEncode(sum, encoding) {
  const bytes = Buffer.alloc(4 * LT_LANES);
  for (let i = 0; i < LT_LANES; i++) bytes.writeUInt32LE(sum[i], 4 * i);
  return bytes.toString(encoding);
}

// Null when the text is not a sum (a damaged or foreign value): the caller rebuilds.
function ltWorkerDecode(text, encoding) {
  if (typeof text !== "string") return null;
  const bytes = Buffer.from(text, encoding);
  if (bytes.length !== 4 * LT_LANES) return null;
  const sum = new Uint32Array(LT_LANES);
  for (let i = 0; i < LT_LANES; i++) sum[i] = bytes.readUInt32LE(4 * i);
  return sum;
}
`;
