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

/** `url`: a string feature (#1115). `carved-file`: a carved object (#1116). email/domain/ip feature
 * files share the string-feature row shape but are not built yet. */
export const recoveredFragmentKinds = ["url", "carved-file"] as const;
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

export const MAX_RECORDER_LEN = 64;
export const MAX_HASH_ALGO_LEN = 32;
export const MAX_HASH_HEX_LEN = 128;

/** The string-fragment member — unchanged from #1115 byte-for-byte except for becoming one arm
 * of the `artifactClass` union (#1116 adds the carved-file arm below). */
const stringFragmentBlockSchema = z.object({
  tool: z.enum(recoveredFragmentTools),
  kind: z.literal("url"),
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

// ---- carved-file arm (#1116) — every literal below states only what bulk_extractor 2.x's own
// be20_api `feature_recorder::carve()` was read to do; see RECOMMENDATION-1116.md for file:line.

/** Which bytes the tool's digest covers — per recorder, verified against every `.carve(` caller:
 * the 3-arg overload forwards an EMPTY header (hash == whole written file); only evtx's
 * reconstructed-header path and rtti's ppm-header path prepend bytes the hash excludes. */
export const CARVED_HASH_SCOPES = [
  "whole file — this recorder passes no separate header, so the digest covers every byte written",
  "data buffer only — this recorder prepends a synthesized header to the written file, which the digest excludes",
  "the carver's data buffer; whether this recorder prepends a header to the written file is not stated in the feature line",
] as const;

/** The NTFS/evtx carvers write their own verdict into the carved filename suffix
 * (`_corrupted`, `.evtx_orphan_record`) — the only structural-validation signal any carver
 * actually emits; every other recorder's verdict, where computed, is discarded before the line. */
export const carvedToolFlags = ["none", "corrupted", "orphan-record"] as const;
export type CarvedToolFlag = (typeof carvedToolFlags)[number];

export const CARVED_COMPLETENESS =
  "not written as structured data — bulk_extractor's carver accepted this object at its own gate " +
  "(e.g. a nonzero validated length) but its complete/truncated/corrupt verdict, where computed, " +
  "is discarded before the feature line; the only verdict any carver emits is the NTFS/evtx " +
  "carved-filename suffix (see toolFlag)";
export const CARVED_STRUCTURAL_VALIDATION =
  "passed the recorder's own acceptance gate before carving; not independently re-validated here; " +
  "the NTFS/evtx recorders alone suffix the carved filename with their verdict (see toolFlag)";
export const CARVED_DEDUP_BASIS =
  "one record per reported digest; the tool's own <CACHED> dedup and this fold are keyed on the " +
  "digest alone — bytes are never re-compared, so a digest collision would present as a duplicate";
export const CARVED_HASH_PROMOTION_CAVEAT =
  "corroboration with other evidence is by digest equality only; md5 is collision-prone under " +
  "adversary-chosen content — treat an md5-only match as a lead to verify against bytes, not a proof";
export const CARVED_FILE_BASIS =
  "a file object bulk_extractor's carver reconstructed from the image's raw or decoded byte " +
  "stream; not proof the file existed as a named filesystem entry, was executed, opened, or " +
  "belongs to any user — corroborate independently before treating it as an event";

const carvedFileBlockSchema = z.object({
  tool: z.enum(recoveredFragmentTools),
  kind: z.literal("carved-file"),
  artifactClass: z.literal("carved-file"),
  /** The `# Feature-Recorder:` name (e.g. `jpeg`, `zip_carved`) — the carver family, a display
   * hint only; never a verified filetype. */
  recorder: z.string().min(1).max(MAX_RECORDER_LEN),
  /** `# BULK_EXTRACTOR-Version:` — the semantics above are 2.x's; the report fingerprint alone
   * would not record which version made the claims. */
  producerVersion: z.string().min(1).max(MAX_RECORDER_LEN),
  /** The tool's own carved relative path from the first non-cached row, plain-truncated; or the
   * importer-synthesized `hash:ALGO:HEX` when `allCachedAnomaly` (never a tool-written value). */
  value: z.string().min(1).max(MAX_VALUE_LEN),
  valueTruncated: z.boolean(),
  hash: z.object({
    algorithm: z.string().min(1).max(MAX_HASH_ALGO_LEN), // `type=` attribute, lower-cased
    hex: z.string().min(1).max(MAX_HASH_HEX_LEN),
  }),
  hashScope: z.enum(CARVED_HASH_SCOPES),
  /** Promoted to a case `hash` IOC only for md5/sha1/sha256 with a matching hex length AND a
   * non-degenerate object; otherwise the digest stays in the record and promotes nothing. */
  hashIocPromoted: z.boolean(),
  hashPromotionCaveat: z.literal(CARVED_HASH_PROMOTION_CAVEAT),
  /** `filesize` of the first non-cached row: the size the tool computed for that occurrence
   * (bytes are written only for a digest's first sighting). Absent when the reported digits
   * exceed the safe-integer range, or when no first-sighting row exists (all-cached anomaly).
   * A row with no `<filesize>` at all is malformed and never becomes a record. */
  filesize: z.number().int().nonnegative().safe().optional(),
  /** filesize 0, filesize absent (over the safe-integer range, or no first-sighting row), or a
   * digest equal to the algorithm's empty-input value — never promoted; the description says
   * which of these it was. */
  degenerate: z.boolean(),
  toolFlag: z.enum(carvedToolFlags),
  /** From `# Filename:` only (never a data row); bounded here AND at parse. */
  sourceMedia: z.string().max(MAX_VALUE_LEN).optional(),
  reportFingerprint: z.string().length(64),
  citations: z.array(recoveryCitationSchema).max(RECOVERY_CITATIONS_MAX),
  notCited: z.number().int().nonnegative(),
  /** Every row for this digest, including the tool's own `<CACHED>` duplicates. */
  occurrences: z.number().int().positive(),
  cachedOccurrences: z.number().int().nonnegative(),
  /** True when EVERY row for this digest was `<CACHED>` — impossible for one pristine feature
   * file (the carve cache starts empty per run), so this upload was pruned, concatenated or
   * edited; imported and flagged, never normalized. */
  allCachedAnomaly: z.boolean(),
  /** A cache marker before the digest's real row, a second real row, or a row folded as cached by
   * filename-absence alone — orderings carve() never produces; flagged, never normalized. */
  orderingAnomaly: z.boolean(),
  completeness: z.literal(CARVED_COMPLETENESS),
  structuralValidation: z.literal(CARVED_STRUCTURAL_VALIDATION),
  dedupBasis: z.literal(CARVED_DEDUP_BASIS),
  basis: z.literal(CARVED_FILE_BASIS),
});
export type CarvedFileBlock = z.infer<typeof carvedFileBlockSchema>;

export const recoveredFragmentBlockSchema = z.discriminatedUnion("artifactClass", [
  stringFragmentBlockSchema,
  carvedFileBlockSchema,
]);
export type RecoveredFragmentBlock = z.infer<typeof recoveredFragmentBlockSchema>;
