import { createHash } from "node:crypto";

// Exact content hash of a screenshot's bytes (SHA-256, hex). Deduplication uses STRICT equality:
// a capture is a duplicate of the one before it only when their bytes are identical — i.e. the
// screen did not change at all between the two captures. Any difference whatsoever (a single
// pixel, a blinking cursor, one new log row) yields a different hash, so the capture is treated
// as new and analyzed.
//
// This deliberately replaces perceptual / fuzzy hashing. A perceptual hash judges what a frame
// *looks like*, not what its text *says*, so it wrongly collapses two log-table pages that look
// near-identical but contain different events. For forensic evidence the only safe "duplicate"
// is a byte-for-byte identical frame; everything else must be analyzed.
export function computeContentHash(image: Buffer): string {
  return createHash("sha256").update(image).digest("hex");
}
