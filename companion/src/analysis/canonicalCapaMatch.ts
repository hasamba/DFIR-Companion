// The envelope block one capa rule-match row (or the report-level composite lead) carries (#932
// item 6, "932.7"): what capa's own static rule-matching found present in a sample — never a
// claim it ran, never a claim of malicious intent from any single match. Kept beside
// canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalRecoveredFragment.ts's own sibling-file pattern, #932 item 4).

import { z } from "zod";
import { MAX_PRODUCER_VERSION_LEN, sampleHashSchema } from "./canonicalMalwareSample.js";

export const capaMatchTools = ["capa"] as const;
export type CapaMatchTool = (typeof capaMatchTools)[number];

/** Top-level `mandiant/capa-rules` directories, fetched live from the repo listing, not invented.
 * "lib"/"nursery"/"internal"/"targeting" are excluded — real capability categories only (library
 * rules never appear in capa's own output; nursery is unreviewed-draft rules). */
export const capaNamespaceFamilies = [
  "anti-analysis",
  "collection",
  "communication",
  "compiler",
  "data-manipulation",
  "executable",
  "exploitation",
  "host-interaction",
  "impact",
  "persistence",
  "runtime",
] as const;
export type CapaNamespaceFamily = (typeof capaNamespaceFamilies)[number];

export const MAX_FIELD_LEN = 300;
export const MAX_FEATURE_DETAIL_LEN = 600;
export const MAX_MAPPINGS = 32;
export const RECOVERY_CITATIONS_MAX = 64;

const attackSchema = z.object({
  tactic: z.string().max(MAX_FIELD_LEN),
  technique: z.string().max(MAX_FIELD_LEN),
  subtechnique: z.string().max(MAX_FIELD_LEN).optional(),
  id: z.string().max(64),
});
export type AttackMapping = z.infer<typeof attackSchema>;

const mbcSchema = z.object({
  objective: z.string().max(MAX_FIELD_LEN),
  behavior: z.string().max(MAX_FIELD_LEN),
  method: z.string().max(MAX_FIELD_LEN).optional(),
  id: z.string().max(64),
});
export type MbcMapping = z.infer<typeof mbcSchema>;

/** Mirrors capa's own AddressType exactly. Static-only v1 never constructs (and this schema
 * never accepts) "process"/"thread"/"call" — those address kinds are dynamic-analysis-only by
 * capa's own model; a static report naming one is itself malformed, not silently accepted. */
export const capaAddressSchema = z.discriminatedUnion("type", [
  z.object({ type: z.enum(["absolute", "relative", "file"]), value: z.number().int().safe() }),
  z.object({ type: z.literal("dn token"), value: z.number().int().safe() }),
  z.object({
    type: z.literal("dn token offset"),
    value: z.tuple([z.number().int().safe(), z.number().int().safe()]),
  }),
  z.object({ type: z.literal("no address"), value: z.null() }),
]);
export type CapaAddress = z.infer<typeof capaAddressSchema>;

/** A bounded, GENERIC rendering of one successful leaf feature node in a match's evidence tree.
 * capa has ~15-20 distinct feature types (api/string/number/bytes/mnemonic/characteristic/...);
 * this never hand-writes a formatter per type — it discloses the feature's own `type` plus a
 * bounded JSON rendering of its remaining fields, with the address(es) it was found at. */
export const capaFeatureEvidenceSchema = z.object({
  featureType: z.string().max(MAX_FIELD_LEN),
  detail: z.string().max(MAX_FEATURE_DETAIL_LEN),
  locations: z.array(capaAddressSchema).max(RECOVERY_CITATIONS_MAX),
});
export type CapaFeatureEvidence = z.infer<typeof capaFeatureEvidenceSchema>;

export const CAPA_MATCH_BASIS =
  "a named capability capa's static rule-matching found present in the sample; not proof it " +
  "ran, not proof of malicious intent on its own — legitimate installers and protected " +
  "commercial software match many of the same rules (packing, anti-debug checks, common API " +
  "imports) — corroborate independently and weigh the COMBINATION, not any one match";

export const capaMatchBlockSchema = z.object({
  tool: z.enum(capaMatchTools),
  ruleName: z.string().min(1).max(MAX_FIELD_LEN),
  ruleNamespace: z.string().max(MAX_FIELD_LEN).optional(),
  /** sha256 of the rule's own YAML `source` — never the YAML text itself. */
  ruleSourceFingerprint: z.string().length(64),
  attack: z.array(attackSchema).max(MAX_MAPPINGS),
  mbc: z.array(mbcSchema).max(MAX_MAPPINGS),
  sampleHash: sampleHashSchema,
  /** sha256 of the uploaded report TEXT (this capa JSON) — never a sample/disk-image hash. */
  reportFingerprint: z.string().length(64),
  producerVersion: z.string().max(MAX_PRODUCER_VERSION_LEN), // capa's own meta.version
  mappingVersion: z.literal("capa-rule-match-v1"),
  outerLocations: z.array(capaAddressSchema).max(RECOVERY_CITATIONS_MAX),
  notCitedOuterLocations: z.number().int().nonnegative(),
  evidence: z.array(capaFeatureEvidenceSchema).max(RECOVERY_CITATIONS_MAX),
  notCitedEvidence: z.number().int().nonnegative(),
  occurrences: z.number().int().positive(),
  basis: z.literal(CAPA_MATCH_BASIS),
});
export type CapaMatchBlock = z.infer<typeof capaMatchBlockSchema>;

export const CAPA_COMPOSITE_LEAD_BASIS =
  "an inspection lead, not a verdict: this sample matched capa rules from an anti-analysis " +
  "(packing/anti-debug/anti-VM) family AND at least one other capability family together — " +
  "legitimate installers and protected commercial software also pack code and use the same " +
  "APIs; corroborate independently before treating this as malicious";

/** Fires only when the report has at least one "anti-analysis" match AND at least one match from
 * ANY other family — the spec's own illustrative "likely packing" + "imported capabilities"
 * pairing, never packing alone (a legitimate protected binary) and never capability alone (nearly
 * every binary matches SOME host-interaction rule). At most one per report. */
export const capaCompositeLeadBlockSchema = z.object({
  tool: z.enum(capaMatchTools),
  reportFingerprint: z.string().length(64),
  sampleHash: sampleHashSchema,
  contributingFamilies: z.array(z.string().max(MAX_FIELD_LEN)).min(2).max(capaNamespaceFamilies.length),
  contributingRules: z.array(z.string().max(MAX_FIELD_LEN)).max(MAX_MAPPINGS),
  notCitedRules: z.number().int().nonnegative(),
  basis: z.literal(CAPA_COMPOSITE_LEAD_BASIS),
});
export type CapaCompositeLeadBlock = z.infer<typeof capaCompositeLeadBlockSchema>;
