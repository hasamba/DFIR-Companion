// The envelope block one decoded/stack/tight-string row carries (#932 item 5, "932.6"): what an
// external string-decoding tool's OWN report states about a string it recovered from a malware
// sample — never a claim of network contact, capability use, or a verified configuration. Kept
// beside canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalRecoveredFragment.ts's own sibling-file pattern, #932 item 4).

import { z } from "zod";
import { MAX_PRODUCER_VERSION_LEN, sampleHashSchema } from "./canonicalMalwareSample.js";

export { MAX_PRODUCER_VERSION_LEN, sampleHashSchema };
export type { SampleHash } from "./canonicalMalwareSample.js";

export const decodedStringTools = ["floss"] as const;
export type DecodedStringTool = (typeof decodedStringTools)[number];

/** "Interpreted configuration" is deliberately not built — see RECOMMENDATION-1120.md.
 * static_strings gets IOC-corroboration only, never its own event kind — same doc. */
export const decodedStringKinds = ["decoded", "stack", "tight", "language"] as const;
export type DecodedStringKind = (typeof decodedStringKinds)[number];

export const MAX_VALUE_LEN = 2000;
export const RECOVERY_CITATIONS_MAX = 64;

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

// language_strings/language_strings_missed share FLOSS's own flat StaticString shape: no
// decoding-routine or stack-frame provenance exists for this kind, only a string-table offset.
const languageCitationSchema = z.object({
  offset: z.number().int().safe(), // FLOSS's own field, may be negative for some layouts
  // encoding/language are attacker-controlled report text, same as producerVersion — bounded the
  // same way (Ollama code review finding: these were the only unbounded strings in this block).
  encoding: z.string().max(MAX_PRODUCER_VERSION_LEN),
  language: z.string().max(MAX_PRODUCER_VERSION_LEN),
  languageVersion: z.string().max(MAX_PRODUCER_VERSION_LEN),
  // true when this citation came from language_strings_missed (a candidate FLOSS could not fully
  // confirm), false when it came from language_strings (confirmed) — never silently dropped or
  // promoted to the same confidence as a confirmed citation.
  missed: z.boolean(),
});
export type LanguageCitation = z.infer<typeof languageCitationSchema>;

export const DECODED_STRING_BASIS =
  "a string FLOSS recovered from the sample via decoding-routine or stack-construction analysis; " +
  "not proof of network contact, not proof a capability was used, and not itself a verified " +
  "configuration — corroborate independently before treating it as an event";

export const LANGUAGE_STRING_BASIS =
  "a string FLOSS associated with an identified language runtime's string table; a value derived " +
  "only from language_strings_missed is a candidate FLOSS could not fully confirm — treat as " +
  "less certain than a confirmed value, and never as proof of network contact or capability use";

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
  z.object({
    tool: z.enum(decodedStringTools),
    kind: z.literal("language"),
    value: z.string().min(1).max(MAX_VALUE_LEN),
    valueTruncated: z.boolean(),
    sampleHash: sampleHashSchema,
    reportFingerprint: z.string().length(64),
    producerVersion: z.string().max(MAX_PRODUCER_VERSION_LEN),
    mappingVersion: z.literal("floss-language-v1"),
    citations: z.array(languageCitationSchema).max(RECOVERY_CITATIONS_MAX),
    notCited: z.number().int().nonnegative(),
    occurrences: z.number().int().positive(),
    basis: z.literal(LANGUAGE_STRING_BASIS),
  }),
]);
export type DecodedStringBlock = z.infer<typeof decodedStringBlockSchema>;
