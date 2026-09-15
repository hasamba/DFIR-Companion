// The envelope block one host-acquisition provenance row carries (#932 item 1): what a
// collection tool's OWN copy/skip log states about itself — never a claim of "examined," never
// wired into refutation reasoning. See #1101 for the scoped, refutation-gate-safe follow-on this
// PR deliberately does not attempt. Kept beside canonicalEvent.ts so the envelope schema stays
// within its size bound (mirrors canonicalLogging.ts's own sibling-file pattern).

import { z } from "zod";

export const acquisitionTools = ["kape"] as const;
export type AcquisitionTool = (typeof acquisitionTools)[number];

export const acquisitionLogKinds = ["copied", "skipped"] as const;
export type AcquisitionLogKind = (typeof acquisitionLogKinds)[number];

/** KAPE's own documented, closed vocabulary for why it did not copy a file — a row whose own
 * `Reason` value is anything else is counted as malformed, never trusted (#932 item 1, Codex code
 * review finding #6). */
export const acquisitionSkipReasons = ["Excluded", "Deduped"] as const;
export type AcquisitionSkipReason = (typeof acquisitionSkipReasons)[number];

export const acquisitionFactSchema = z.object({
  /** The source path this log named — never the destination, which is this case's own storage.
   * Kept in FULL, never clipped: this is stored evidence, not display text (#932 item 1, Codex
   * code review finding #4). */
  sourceFile: z.string(),
  /** The source file's own hash, as the tool recorded it — never verified against a destination
   * re-hash by this block (the tool's own log does not record one). */
  sha1: z.string().optional(),
  fileSize: z.number().int().nonnegative().optional(),
  /** copylog only: the tool fell back to a raw-disk read because the source was locked. */
  deferredCopy: z.boolean().optional(),
  /** skiplog only: why the tool did not copy this file, in the tool's own closed vocabulary. */
  reason: z.enum(acquisitionSkipReasons).optional(),
});
export type AcquisitionFact = z.infer<typeof acquisitionFactSchema>;

export const acquisitionCoverageBlockSchema = z.object({
  tool: z.enum(acquisitionTools),
  logKind: z.enum(acquisitionLogKinds),
  /** Files copylog/skiplog named, in the tool's own log — bounded; `notCited` names the rest. */
  facts: z.array(acquisitionFactSchema),
  notCited: z.number().int().nonnegative(),
  /** Rows the CSV itself could not be read as an acquisition fact (no source path) — counted,
   * never silently dropped from the total. */
  malformedRows: z.number().int().nonnegative(),
  /** copylog only: the earliest/latest CopiedTimestamp across this log's own rows. */
  coverage: z.object({ first: z.string(), last: z.string() }).optional(),
  /** Always this exact sentence: the hash this block carries, when recorded, is the SOURCE
   * file's own hash — never a container/disk-image hash, and this log does not verify a
   * destination copy against it. */
  basis: z.literal(
    "each file's own SHA-1, when recorded at the source by the acquisition tool; not a container or disk-image hash, and this log does not verify the destination copy against it",
  ),
});
export type AcquisitionCoverageBlock = z.infer<typeof acquisitionCoverageBlockSchema>;
