// The envelope block one recovered-fragment row carries (#932 item 4): what an external carving/
// recovery tool's OWN report states about a string it found — a URL, in this scope — never a
// claim that the string was visited, executed, or belongs to a reconstructed file. Kept beside
// canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalAcquisition.ts's own sibling-file pattern).
//
// Bounds here are the authoritative contract — bulkExtractorUrlImport.ts imports these constants
// rather than restating them, so the parser's enforcement and the schema's cannot drift apart
// (Codex code review finding: the schema originally declared none of the documented maximums).

import { z } from "zod";

export const recoveredFragmentTools = ["bulk_extractor"] as const;
export type RecoveredFragmentTool = (typeof recoveredFragmentTools)[number];

/** Extensible: email/domain/ip feature files share this row shape but are not built yet (#1100 item 4). */
export const recoveredFragmentKinds = ["url"] as const;
export type RecoveredFragmentKind = (typeof recoveredFragmentKinds)[number];

export const MAX_VALUE_LEN = 2000;
export const MAX_CONTEXT_LEN = 600;
/** Not a storage bound (rawOffset itself is unbounded, see below) — the ceiling past which the
 * parser does not attempt a structured forensic-path breakdown, purely to bound parse work. */
export const MAX_RAW_OFFSET_PARSE_LEN = 400;
export const RECOVERY_CITATIONS_MAX = 64;
export const MAX_HOPS = 8;

export const recoveryPathHopSchema = z.object({
  method: z.string().regex(/^[A-Za-z0-9]+$/),
  offset: z.number().int().nonnegative().safe(),
});
export type RecoveryPathHop = z.infer<typeof recoveryPathHopSchema>;

const citationBaseSchema = {
  /** The tool's own offset field, verbatim and UNBOUNDED — always kept even when the structured
   * parse below does not apply, so a row is never silently reduced to less than the tool itself
   * stated (mirrors canonicalAcquisition.ts's own `sourceFile`: "kept in FULL, never clipped").
   * `bulkExtractorUrlImport.ts` rejects a row outright (counted malformed, never stored at all)
   * if this field is pathologically long — full rejection is honest; a silent truncation of an
   * evidence field is not. */
  rawOffset: z.string().min(1),
  context: z.string().max(MAX_CONTEXT_LEN),
};

/** `parsed` is a discriminant: a `true` citation always carries its structured breakdown, a
 * `false` one never does — the two states can no longer be constructed in a contradictory shape
 * (Codex code review finding: the prior single-object schema allowed `parsed: false` with a
 * populated `path`). */
export const recoveryCitationSchema = z.discriminatedUnion("parsed", [
  z.object({
    ...citationBaseSchema,
    parsed: z.literal(true),
    rootOffset: z.number().int().nonnegative().safe(),
    path: z.array(recoveryPathHopSchema).max(MAX_HOPS),
  }),
  z.object({ ...citationBaseSchema, parsed: z.literal(false) }),
]);
export type RecoveryCitation = z.infer<typeof recoveryCitationSchema>;

export const recoveredFragmentBlockSchema = z.object({
  tool: z.enum(recoveredFragmentTools),
  kind: z.enum(recoveredFragmentKinds),
  /** The recovered string itself. Plain-truncated (never digest-spliced — `boundedTextTo` is for
   * discriminator keys, and splicing a hex digest into a URL can read as a fabricated fragment
   * identifier) when it exceeds MAX_VALUE_LEN; `valueTruncated` discloses that truthfully. */
  value: z.string().min(1).max(MAX_VALUE_LEN),
  valueTruncated: z.boolean(),
  /** Never "file" — this importer only ever produces string fragments (#932 item 4's own
   * "keep a complete recovered file distinct from a fragment" guardrail). */
  artifactClass: z.literal("string-fragment"),
  completeness: z.literal(
    "not applicable — a recovered string fragment, not a reconstructed file; no completeness state exists for it",
  ),
  structuralValidation: z.literal(
    "not reported — bulk_extractor's url scanner does not validate the recovered string's container structure",
  ),
  /** The tool's own `# Filename:` header, when present — the source image's name as the TOOL
   * recorded it, never independently verified, never fabricated when the header is absent, and
   * read only from the validated leading header block (never from a data row). */
  sourceMedia: z.string().optional(),
  /** sha256 of the uploaded report TEXT (this url.txt) — never a disk-image hash; this importer
   * never has image bytes, only the tool's own text report. */
  reportFingerprint: z.string().length(64),
  /** Bounded, DISTINCT (rawOffset, context) citations; `notCited` counts distinct citations
   * beyond the bound, never raw duplicate rows. */
  citations: z.array(recoveryCitationSchema).max(RECOVERY_CITATIONS_MAX),
  notCited: z.number().int().nonnegative(),
  /** Total row count for this value in this upload, including exact duplicates. */
  occurrences: z.number().int().positive(),
  basis: z.literal(
    "a string bulk_extractor's scanner found in the image's raw or decoded byte stream; not a " +
      "browser-history entry, not proof of a completed transfer, and not evidence anyone acted on " +
      "it — corroborate independently before treating it as an event",
  ),
});
export type RecoveredFragmentBlock = z.infer<typeof recoveredFragmentBlockSchema>;
