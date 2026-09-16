// A sandbox report's own stated ASSOCIATION between the sample it analyzed and an object it
// listed during that analysis (#932 item 8). Deliberately NOT a parent/child descent claim —
// CAPEv2's own real report structure (verified via its live GitHub source this session) gives no
// field identifying which process or object actually PRODUCED a dropped/payload entry, so this
// importer states only what the report itself supports: "this report listed object X while
// analyzing target Y." See RECOMMENDATION-932.8.md for the full design-review rationale, including
// why an earlier "parent sample -> child object" framing was rejected.
//
// Kept in its own file for the same reason as canonicalAcquisition.ts / canonicalDiskImage.ts:
// canonicalEvent.ts's own size bound.

import { z } from "zod";

// CAPE's own two real report arrays. NOT mutually exclusive — the same object can be appended to
// both `dropped` and `CAPE.payloads` in one report (confirmed against CAPE's own processing
// source), so this is a membership list, never a single "origin."
export const reportMemberships = ["dropped", "cape-payloads"] as const;
export type ReportMembership = (typeof reportMemberships)[number];

const sampleHashSetSchema = z
  .object({
    sha256: z
      .string()
      .regex(/^[0-9a-f]{64}$/i)
      .optional(),
    sha1: z
      .string()
      .regex(/^[0-9a-f]{40}$/i)
      .optional(),
    md5: z
      .string()
      .regex(/^[0-9a-f]{32}$/i)
      .optional(),
  })
  .refine((h) => Boolean(h.sha256 || h.sha1 || h.md5), {
    message: "at least one valid hash is required",
  });
export type SampleHashSet = z.infer<typeof sampleHashSetSchema>;

export const sampleAssociationFactSchema = z.object({
  // Absent when the report's own target.file is missing (e.g. a URL-target report) — never
  // fabricated to satisfy the schema.
  targetHashes: sampleHashSetSchema.optional(),
  targetName: z.string().max(300).optional(),
  // Required: an association with no valid hash on the observed object is not retained as a fact
  // at all (counted in the block's own `malformed` total instead).
  objectHashes: sampleHashSetSchema,
  // CAPE's own `name` field is a deduplicated LIST of basenames, not a scalar string.
  objectNames: z.array(z.string().max(300)).max(20).optional(),
  // CAPE's own in-sandbox path(s) — never the analysis-host storage path CAPE separately uses to
  // read the captured file back (that path names infrastructure, not the sandboxed endpoint).
  objectGuestPaths: z.array(z.string().max(500)).max(20).optional(),
  reportedIn: z.array(z.enum(reportMemberships)).min(1),
  // CAPE's own real classification, preserved verbatim and by its own numeric code — never
  // reinterpreted into a category this importer cannot independently confirm the meaning of.
  capeType: z.string().max(200).optional(),
  capeTypeCode: z.number().int().optional(),
  // The only fact this importer can state — never "parent"/"child" wording, which would claim a
  // production/descent edge the report's own structure does not support.
  relationship: z.literal("listed-during-analysis-of"),
});
export type SampleAssociationFact = z.infer<typeof sampleAssociationFactSchema>;

export const sampleLineageBlockSchema = z.object({
  // A per-report content fingerprint (never just the target hash + run id, which two separately
  // uploaded/reprocessed reports can share) — disambiguates this report's own facts from another
  // report's in the shared event aggregator, so they can never silently collapse into one row.
  reportLocator: z.string(),
  runId: z.string().optional(),
  facts: z.array(sampleAssociationFactSchema).max(256),
  // Report entries seen past the 256-fact cap, and objects with no valid hash at all — both
  // counted, never silently dropped from the disclosed totals.
  notCited: z.number().int().nonnegative(),
  malformed: z.number().int().nonnegative(),
  basis: z.literal(
    "objects this SAME sandbox report listed together during one analysis — never a claim of direct production or descent, never inferred across separate reports, and never a claim about an incident endpoint",
  ),
});
export type SampleLineageBlock = z.infer<typeof sampleLineageBlockSchema>;
