// The envelope blocks one olevba (oletools) VBA/OLE macro static-analysis finding, stomping lead,
// or compound-capability lead carries (#932 items 10-11, "932.10"): structural facts an external
// document-analysis tool found in an Office document — never a claim a macro ran, and never a
// proven entry-point-to-capability chain (co-occurrence in one document is not a call graph). Kept
// beside canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalRecoveredFragment.ts's own sibling-file pattern, #932 item 4).

import { z } from "zod";
import { MAX_PRODUCER_VERSION_LEN } from "./canonicalMalwareSample.js";

export const olevbaFindingTools = ["olevba"] as const;
export type OlevbaFindingTool = (typeof olevbaFindingTools)[number];

/** Real, confirmed `analysis[].type` values (fetched live against olevba's own JSON-building
 * code and a real serialized report) — "Form String" is deliberately excluded, unconfirmed as a
 * real emitted type. */
export const olevbaFindingTypes = [
  "AutoExec",
  "Suspicious",
  "IOC",
  "Hex String",
  "Base64 String",
  "Dridex string",
  "VBA string",
] as const;
export type OlevbaFindingType = (typeof olevbaFindingTypes)[number];

export const MAX_FIELD_LEN = 300;
export const MAX_DESCRIPTION_LEN = 600;
export const MAX_MAPPINGS = 32;
export const MAX_CITATIONS = 64;

export const OLEVBA_FINDING_BASIS =
  "a structural fact olevba's static analysis found in the document — an auto-run entry point, " +
  "a risky API keyword, a decoded obfuscated string, or a source/compiled-macro mismatch; never " +
  "a claim the macro ran, and never a verdict on its own — legitimate automation and blocked/" +
  "disabled macros can carry the same signals";

export const olevbaFindingBlockSchema = z.object({
  tool: z.enum(olevbaFindingTools),
  findingType: z.enum(olevbaFindingTypes),
  keyword: z.string().min(1).max(MAX_FIELD_LEN),
  keywordTruncated: z.boolean(),
  /** Distinct DESCRIPTION variants olevba's own output carried for this (type, keyword) pair,
   * bounded and deduped — never collapsed to one arbitrarily-chosen variant (Codex code review
   * finding: `keyword` is the decoded value for string categories, `description` the raw/encoded
   * one, and two different encodings can decode to the same displayed keyword). */
  descriptions: z.array(z.string().max(MAX_DESCRIPTION_LEN)).max(MAX_CITATIONS),
  notCitedDescriptions: z.number().int().nonnegative(),
  /** Reported by the tool, never independently verified. */
  documentPath: z.string().min(1).max(MAX_FIELD_LEN),
  containerPath: z.string().max(MAX_FIELD_LEN).optional(),
  reportFingerprint: z.string().length(64),
  producerVersion: z.string().min(1).max(MAX_PRODUCER_VERSION_LEN),
  mappingVersion: z.literal("olevba-finding-v1"),
  /** Analysis entries olevba's own output represented for this (type, keyword) pair — NOT a claim
   * about how many times the pattern appears in the underlying macro code (olevba already
   * dedupes AutoExec/Suspicious/IOC internally; only decoded-string categories can repeat). */
  occurrences: z.number().int().positive(),
  basis: z.literal(OLEVBA_FINDING_BASIS),
});
export type OlevbaFindingBlock = z.infer<typeof olevbaFindingBlockSchema>;

export const OLEVBA_STOMPING_LEAD_BASIS =
  "an investigation lead, not automatically malicious stomping: olevba's own analysis states the " +
  "VBA source code and compiled P-code differ, which experimentally can also result from stale " +
  "or cached streams — not a verdict, and detection itself is not exhaustive across all documents";

export const olevbaStompingLeadBlockSchema = z.object({
  tool: z.enum(olevbaFindingTools),
  reportFingerprint: z.string().length(64),
  documentPath: z.string().min(1).max(MAX_FIELD_LEN),
  containerPath: z.string().max(MAX_FIELD_LEN).optional(),
  producerVersion: z.string().min(1).max(MAX_PRODUCER_VERSION_LEN),
  mappingVersion: z.literal("olevba-finding-v1"),
  basis: z.literal(OLEVBA_STOMPING_LEAD_BASIS),
});
export type OlevbaStompingLeadBlock = z.infer<typeof olevbaStompingLeadBlockSchema>;

export const OLEVBA_COMPOUND_LEAD_BASIS =
  "an inspection lead, not a verdict: the report's own structural evidence names BOTH an " +
  "auto-run macro entry point AND a keyword whose own olevba-documented capability is download, " +
  "file-write, or launch, in the SAME document — this is co-occurrence in one static analysis " +
  "pass, not a proven call from the entry point to the capability; legitimate automation and " +
  "intentionally blocked/disabled macros can carry the same combination";

export const olevbaCapabilityClasses = ["download", "file-write", "launch"] as const;
export type OlevbaCapabilityClass = (typeof olevbaCapabilityClasses)[number];

export const olevbaCompoundLeadBlockSchema = z.object({
  tool: z.enum(olevbaFindingTools),
  reportFingerprint: z.string().length(64),
  documentPath: z.string().min(1).max(MAX_FIELD_LEN),
  containerPath: z.string().max(MAX_FIELD_LEN).optional(),
  producerVersion: z.string().min(1).max(MAX_PRODUCER_VERSION_LEN),
  mappingVersion: z.literal("olevba-finding-v1"),
  autoExecKeywords: z.array(z.string().max(MAX_FIELD_LEN)).min(1).max(MAX_MAPPINGS),
  notCitedAutoExecKeywords: z.number().int().nonnegative(),
  capabilityClasses: z.array(z.enum(olevbaCapabilityClasses)).min(1).max(olevbaCapabilityClasses.length),
  capabilityKeywords: z.array(z.string().max(MAX_FIELD_LEN)).min(1).max(MAX_MAPPINGS),
  notCitedCapabilityKeywords: z.number().int().nonnegative(),
  basis: z.literal(OLEVBA_COMPOUND_LEAD_BASIS),
});
export type OlevbaCompoundLeadBlock = z.infer<typeof olevbaCompoundLeadBlockSchema>;
