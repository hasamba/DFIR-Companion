// The schema for a "collection generation" record (#1108, the prerequisite 932.2's own design
// review required before any cross-snapshot comparator could be built soundly). See
// RECOMMENDATION-1108.md for the full design rationale, including the 6 High findings a Codex
// adversarial design review round found in the first draft and how each was fixed.
//
// This is NOT a canonicalEvent.ts block: a generation is examiner-authored case metadata, not a
// forensic-timeline fact, and is stored in its own file (collectionGenerationStore.ts) — mirroring
// hostScopeStore.ts's / evidenceAttestationStore.ts's own separation from the timeline.
//
// v1 is domain-scoped to EXACTLY ONE evidence domain, "persistence" (PersistenceSniper rows),
// matching 932.2's own original scoping ("persistence entries only, one comparison capability").
// Growing `collectionDomains` to a second value is a deliberate, reviewed decision each time, never
// an incidental one.

import { z } from "zod";

export const collectionDomains = ["persistence"] as const;
export type CollectionDomain = (typeof collectionDomains)[number];

export const completenessStates = ["complete", "partial", "unknown"] as const;
export type CompletenessState = (typeof completenessStates)[number];

export const persistenceFilters = ["severity-floor", "event-cap", "partial-hive"] as const;
export type PersistenceFilter = (typeof persistenceFilters)[number];

/** A real capture timestamp, or an explicit examiner-declared order — never inferred from a
 * free-text label (Codex design-review finding H4). Two rows for the same (host, domain) cohort
 * must use the SAME kind to be orderable; a cohort mixing kinds is not comparable (see the
 * comparator's own eligibility rule this ledger exists to make possible, in 932.2). */
export const generationOrderSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("captured"), capturedAt: z.string().datetime({ offset: true }) }),
  z.object({ kind: z.literal("declared"), sequence: z.number().int().positive() }),
]);
export type GenerationOrder = z.infer<typeof generationOrderSchema>;

export const persistenceEntryFactSchema = z.object({
  technique: z.string().min(1),
  path: z.string().min(1),
  value: z.string(),
});
export type PersistenceEntryFact = z.infer<typeof persistenceEntryFactSchema>;

// Exported (#1132) so a sibling generation-ledger schema (mobile backup pairing) can reuse the
// SAME actor shape rather than redefining it — this shape is genuinely domain-blind already.
export const actorSchema = z.object({ id: z.string().min(1), displayName: z.string().min(1) });
export type GenerationActor = z.infer<typeof actorSchema>;

export const collectionGenerationSchema = z.object({
  generationId: z.string().uuid(),
  /** The examiner's own words for the host. Never resolved/frozen at write time — a caller re-runs
   * host resolution against the CURRENT alias index at read time (#1110's own established fix for
   * the identical failure mode: a stored resolution can go stale the moment an analyst merges two
   * aliases after this row was recorded). */
  rawHost: z.string().min(1),
  domain: z.enum(collectionDomains),
  /** Structured, code-evaluable comparability — never inferred from prose (Codex finding H2). Two
   * generations are comparable only when BOTH have completenessState "complete" and an EMPTY
   * filtersApplied; this is the comparator's own eligibility predicate, defined once here so it can
   * never be re-derived differently in two places. */
  completenessState: z.enum(completenessStates),
  filtersApplied: z.array(z.enum(persistenceFilters)).default([]),
  order: generationOrderSchema,
  artifactRef: z.object({
    importSeq: z.number().int().positive(),
    /** sha256 of the raw stored file at record time, so a later read can detect a changed or
     * missing artifact rather than silently trusting whatever the sequence number now resolves
     * to (Codex finding M2). */
    artifactHash: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  /** Frozen at record time from the artifact's own RAW stored file — never the post-import
   * forensic timeline, which has already lost rows to severity-floor/cap demotion before the next
   * import's merge could ever see them (Codex finding H1, the issue's own "including Info-severity
   * entries" requirement). At least one fact, since a generation with zero matching rows is
   * rejected at record time rather than stored empty. */
  inventory: z.array(persistenceEntryFactSchema).min(1),
  /** Supplemental examiner notes only — never authoritative for comparability (Codex finding H2). */
  checked: z.string().optional(),
  gaps: z.string().optional(),
  recordedBy: actorSchema,
  recordedAt: z.string().datetime({ offset: true }),
  revokedBy: actorSchema.optional(),
  revokedAt: z.string().datetime({ offset: true }).optional(),
});
export type CollectionGeneration = z.infer<typeof collectionGenerationSchema>;

/** One generation's own eligibility for ANY comparison, independent of what it might be paired
 * with — exported (#1128) so an N-wise cohort filter and `generationsComparable`'s own pairwise
 * check share exactly one definition and can never drift apart (Codex code-review finding M3 on
 * #1128's own design: the two were at risk of being redefined separately). */
export function generationEligible(g: CollectionGeneration): boolean {
  return g.completenessState === "complete" && g.filtersApplied.length === 0;
}

/** Two generations of the SAME resolved host + domain are eligible for a "removed"/"changed"
 * comparison only when both satisfy this — the comparator (932.2's own follow-on) is the intended
 * caller, but the rule lives here so it is defined exactly once. Default is "not comparable": a
 * cohort mixing `captured`/`declared` ordering is deliberately NOT handled by inventing a
 * cross-mode total order (Codex finding H4) — such a pair is simply never eligible. */
export function generationsComparable(a: CollectionGeneration, b: CollectionGeneration): boolean {
  if (a.domain !== b.domain) return false;
  if (a.order.kind !== b.order.kind) return false;
  return generationEligible(a) && generationEligible(b);
}
