// The envelope block one recovered-fragment row carries (#932 item 4): what an external carving/
// recovery tool's OWN report states about a string it found — a URL, in this scope — never a
// claim that the string was visited, executed, or belongs to a reconstructed file. Kept beside
// canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalAcquisition.ts's own sibling-file pattern).

import { z } from "zod";

export const recoveredFragmentTools = ["bulk_extractor"] as const;
export type RecoveredFragmentTool = (typeof recoveredFragmentTools)[number];

/** Extensible: email/domain/ip feature files share this row shape but are not built yet (#1100 item 4). */
export const recoveredFragmentKinds = ["url"] as const;
export type RecoveredFragmentKind = (typeof recoveredFragmentKinds)[number];

export const recoveryPathHopSchema = z.object({
  method: z.string().regex(/^[A-Za-z0-9]+$/),
  offset: z.number().int().nonnegative(),
});
export type RecoveryPathHop = z.infer<typeof recoveryPathHopSchema>;

export const recoveryCitationSchema = z.object({
  /** The tool's own offset field, verbatim — always kept even when the structured parse below
   * does not apply, so a row is never silently reduced to less than the tool itself stated. */
  rawOffset: z.string().min(1),
  /** Whether `rootOffset`/`path` below reflect an unambiguous parse of `rawOffset`. */
  parsed: z.boolean(),
  rootOffset: z.number().int().nonnegative().optional(),
  /** Empty when parsed and direct (no decode hop); absent when `parsed` is false. */
  path: z.array(recoveryPathHopSchema).optional(),
  context: z.string(),
});
export type RecoveryCitation = z.infer<typeof recoveryCitationSchema>;

export const recoveredFragmentBlockSchema = z.object({
  tool: z.enum(recoveredFragmentTools),
  kind: z.enum(recoveredFragmentKinds),
  /** The recovered string itself, verbatim. */
  value: z.string().min(1),
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
   * recorded it, never independently verified, never fabricated when the header is absent. */
  sourceMedia: z.string().optional(),
  /** sha256 of the uploaded report TEXT (this url.txt) — never a disk-image hash; this importer
   * never has image bytes, only the tool's own text report. */
  reportFingerprint: z.string().length(64),
  /** Bounded per-value citation list; `notCited` counts rows beyond the bound. */
  citations: z.array(recoveryCitationSchema),
  notCited: z.number().int().nonnegative(),
  /** Total row count for this value in this upload — citations plus notCited. */
  occurrences: z.number().int().positive(),
  basis: z.literal(
    "a string bulk_extractor's scanner found in the image's raw or decoded byte stream; not a " +
      "browser-history entry, not proof of a completed transfer, and not evidence anyone acted on " +
      "it — corroborate independently before treating it as an event",
  ),
});
export type RecoveredFragmentBlock = z.infer<typeof recoveredFragmentBlockSchema>;
