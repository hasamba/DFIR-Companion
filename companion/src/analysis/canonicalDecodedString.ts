// The envelope block one decoded/stack/tight-string row carries (#932 item 5, "932.6"): what an
// external string-decoding tool's OWN report states about a string it recovered from a malware
// sample — never a claim of network contact, capability use, or a verified configuration. Kept
// beside canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalRecoveredFragment.ts's own sibling-file pattern, #932 item 4).

import { z } from "zod";

export const decodedStringTools = ["floss"] as const;
export type DecodedStringTool = (typeof decodedStringTools)[number];

/** static_strings and "interpreted configuration" are deliberately not built — see
 * RECOMMENDATION-5.md. Extensible if a future item picks either up. */
export const decodedStringKinds = ["decoded", "stack", "tight"] as const;
export type DecodedStringKind = (typeof decodedStringKinds)[number];

export const MAX_VALUE_LEN = 2000;
export const RECOVERY_CITATIONS_MAX = 64;
/** FLOSS's own version string is normally short ("0.1.0", "v2.2.0-0-g783dd8f") — bounded so a
 * pathological upload can't copy an unbounded string into every emitted event (Codex code review
 * finding). */
export const MAX_PRODUCER_VERSION_LEN = 200;

/** Every hash FLOSS itself reported, each validated by hex length/shape before being trusted as
 * an identity component or IOC — reported by the tool, never independently verified: this
 * importer has no access to the original binary, only FLOSS's own text results. */
export const sampleHashSchema = z.object({
  md5: z
    .string()
    .regex(/^[a-f0-9]{32}$/i)
    .optional(),
  sha1: z
    .string()
    .regex(/^[a-f0-9]{40}$/i)
    .optional(),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/i)
    .optional(),
  /** Explicit, not inferred from three absent fields — true only when none of the three above
   * validated; the event is still importable, keyed by report fingerprint alone. */
  hashUnavailable: z.boolean(),
});
export type SampleHash = z.infer<typeof sampleHashSchema>;

const decodedCitationSchema = z.object({
  address: z.number().int().nonnegative().safe(),
  // FLOSS's own AddressType (e.g. "absolute" | "file" | "stack" | "heap"), carried as reported —
  // its enum is FLOSS's to define, not this importer's.
  addressType: z.string(),
  encoding: z.string(),
  decodedAt: z.number().int().nonnegative().safe(),
  decodingRoutine: z.number().int().nonnegative().safe(),
});
export type DecodedCitation = z.infer<typeof decodedCitationSchema>;

const stackCitationSchema = z.object({
  functionAddress: z.number().int().nonnegative().safe(),
  encoding: z.string(),
  programCounter: z.number().int().nonnegative().safe(),
  stackPointer: z.number().int().nonnegative().safe(),
  originalStackPointer: z.number().int().nonnegative().safe(),
  offset: z.number().int().safe(), // FLOSS's own field can be negative
  frameOffset: z.number().int().safe(),
});
export type StackCitation = z.infer<typeof stackCitationSchema>;

export const DECODED_STRING_BASIS =
  "a string FLOSS recovered from the sample via decoding-routine or stack-construction analysis; " +
  "not proof of network contact, not proof a capability was used, and not itself a verified " +
  "configuration — corroborate independently before treating it as an event";

export const decodedStringBlockSchema = z.discriminatedUnion("kind", [
  z.object({
    tool: z.enum(decodedStringTools),
    kind: z.literal("decoded"),
    value: z.string().min(1).max(MAX_VALUE_LEN),
    valueTruncated: z.boolean(),
    sampleHash: sampleHashSchema,
    /** sha256 of the uploaded report TEXT (this FLOSS JSON) — never a sample/disk-image hash. */
    reportFingerprint: z.string().length(64),
    producerVersion: z.string().max(MAX_PRODUCER_VERSION_LEN), // FLOSS's own metadata.version, plain-truncated if oversized
    mappingVersion: z.literal("floss-decoded-v1"),
    citations: z.array(decodedCitationSchema).max(RECOVERY_CITATIONS_MAX),
    notCited: z.number().int().nonnegative(),
    occurrences: z.number().int().positive(),
    basis: z.literal(DECODED_STRING_BASIS),
  }),
  z.object({
    tool: z.enum(decodedStringTools),
    kind: z.enum(["stack", "tight"]),
    value: z.string().min(1).max(MAX_VALUE_LEN),
    valueTruncated: z.boolean(),
    sampleHash: sampleHashSchema,
    reportFingerprint: z.string().length(64),
    producerVersion: z.string().max(MAX_PRODUCER_VERSION_LEN),
    mappingVersion: z.literal("floss-stack-v1"),
    citations: z.array(stackCitationSchema).max(RECOVERY_CITATIONS_MAX),
    notCited: z.number().int().nonnegative(),
    occurrences: z.number().int().positive(),
    basis: z.literal(DECODED_STRING_BASIS),
  }),
]);
export type DecodedStringBlock = z.infer<typeof decodedStringBlockSchema>;
