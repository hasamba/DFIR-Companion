// #1128: the ONE domain-specific orchestrator over the persistence domain's own already-shipped
// ledger (#1108's collectionGenerationStore.ts). See RECOMMENDATION-1128.md for the full design
// rationale, including the 3 High findings a Codex adversarial design review round found in the
// first draft (no envelope/kernel/adapter separation, tied-order fabrication, an unsafe
// concatenated map key) and how each was fixed, plus a second Codex code-review round's own
// findings (captured-time ordering by string representation instead of instant, resource caps
// applied too late to bound work) and how each was fixed, plus a third round's own findings
// (#1138, surfaced by #1132's own design review: truncatedEntries was computed and discarded
// instead of disclosed) fixed the same way.
//
// This module knows about persistence's own technique/path/value shape; snapshotComparisonKernel.ts
// does not. Building the envelope (resolving identity, choosing keys, detecting duplicates) is
// this module's own responsibility, per the kernel's own documented contract.

import { resolveHost, type HostAliasIndex } from "./hostAlias.js";
import {
  generationEligible,
  type CollectionGeneration,
  type GenerationOrder,
} from "./canonicalCollectionGeneration.js";
import { diffEnvelopes, type EntryChange, type SnapshotEnvelope } from "./snapshotComparisonKernel.js";

const MAX_CHANGES_PER_PAIR = 500;
const MAX_PAIRS_PER_COHORT = 50;
const MAX_COHORTS = 200;
// A hard ceiling on how many facts one generation's own envelope can hold, applied BEFORE
// diffEnvelopes runs (Codex code-review finding: the per-pair change cap was applied only after a
// full diff+sort, so a pathologically large inventory still cost unbounded work). Far above any
// real persistence-entry count seen in practice; this exists to bound a corrupted or adversarial
// import, not to affect a real case.
const MAX_ENTRIES_PER_ENVELOPE = 10_000;

function keyFor(technique: string, path: string): string {
  // Collision-free, unlike `${technique}|${path}` — a `|` inside either field would otherwise let
  // two distinct identities collide (Codex design-review finding H3).
  return JSON.stringify([technique, path]);
}

type EnvelopeResult =
  | { ok: true; envelope: SnapshotEnvelope<string>; truncatedEntries: boolean }
  | { ok: false; reason: "ambiguous-identity" };

/** Builds this one generation's own envelope, or reports it as ambiguous when its inventory holds
 * two rows sharing an identity (technique, path) but disagreeing on value — quarantined rather
 * than silently collapsed by Map insertion order (Codex finding H3's own second half). Stops
 * accepting new entries past MAX_ENTRIES_PER_ENVELOPE rather than materializing an unbounded Map. */
function generationToEnvelope(g: CollectionGeneration, resolvedHost: string): EnvelopeResult {
  const entries = new Map<string, string>();
  let truncatedEntries = false;
  for (const fact of g.inventory) {
    const key = keyFor(fact.technique, fact.path);
    const existing = entries.get(key);
    if (existing !== undefined && existing !== fact.value) {
      return { ok: false, reason: "ambiguous-identity" };
    }
    if (entries.size >= MAX_ENTRIES_PER_ENVELOPE && existing === undefined) {
      truncatedEntries = true;
      continue;
    }
    entries.set(key, fact.value);
  }
  return {
    ok: true,
    truncatedEntries,
    envelope: {
      version: 1,
      snapshotId: g.generationId,
      subject: resolvedHost,
      domain: g.domain,
      order: g.order,
      entries,
      provenance: [g.artifactRef],
    },
  };
}

/** The raw order value, for DISPLAY only (the ambiguousOrder disclosure's own orderKey field) —
 * never for sorting or interval comparison. A `captured` value is the examiner-facing ISO string
 * exactly as recorded. */
function orderDisplayValue(order: GenerationOrder): string | number {
  return order.kind === "captured" ? order.capturedAt : order.sequence;
}

/** The real chronological/sequence value used for EVERY sort, tie-detection, and interval
 * comparison. A `captured` order is a real-world instant: two different offset-bearing ISO
 * strings can name the SAME instant, or sort in the opposite order from their own lexicographic
 * comparison (`"2026-01-01T01:00:00+02:00"` names an EARLIER instant than
 * `"2026-01-01T00:30:00Z"`, but sorts later as a string). Comparing the parsed epoch instead is
 * the fix for a Codex code-review High finding: string-keyed ordering could reverse or fabricate
 * a directional diff. `collectionGenerationSchema`'s own `z.string().datetime({offset:true})`
 * guarantees `capturedAt` always parses. */
function orderSortValue(order: GenerationOrder): number {
  return order.kind === "captured" ? Date.parse(order.capturedAt) : order.sequence;
}

export type ExclusionReason = "partial" | "filtered" | "ambiguous-identity";

export interface PersistencePairResult {
  earlier: {
    generationId: string;
    order: GenerationOrder;
    artifactRef: { importSeq: number; artifactHash: string };
  };
  later: {
    generationId: string;
    order: GenerationOrder;
    artifactRef: { importSeq: number; artifactHash: string };
  };
  interveningExcludedCount: number;
  changes: EntryChange<string>[];
  truncated: boolean;
  /** True when either side's own inventory exceeded MAX_ENTRIES_PER_ENVELOPE and was built from a
   * prefix of it (#1138) — this comparison may miss real differences past that prefix on the
   * truncated side, and must never be reported as if it saw the whole inventory. */
  inventoryTruncated: boolean;
}

export interface PersistenceCohortResult {
  resolvedHost: string;
  domain: "persistence";
  eligibleCount: number;
  excluded: { generationId: string; reason: ExclusionReason }[];
  ambiguousOrder: { generationId: string; orderKey: string | number }[];
  pairs: PersistencePairResult[];
  truncatedPairs: boolean;
}

export interface ComparePersistenceGenerationsResult {
  cohorts: PersistenceCohortResult[];
  /** True when more (resolvedHost) cohorts existed than MAX_COHORTS — the response holds only the
   * first MAX_COHORTS, sorted by resolvedHost, never a silent partial list (design doc's own M4). */
  truncatedCohorts: boolean;
}

/** Groups every ACTIVE generation of the "persistence" domain into (resolvedHost) cohorts and
 * diffs each cohort's own eligible generations, adjacent pair only, within one order mode. Never
 * infers continuity across a gap the ledger itself did not record, and never sorts a tied order
 * key into a fabricated earlier/later (Codex findings H2/H4). */
export function comparePersistenceGenerations(
  generations: readonly CollectionGeneration[],
  aliasIndex: HostAliasIndex,
): ComparePersistenceGenerationsResult {
  const persistence = generations.filter((g) => g.domain === "persistence");
  const byHost = new Map<string, CollectionGeneration[]>();
  for (const g of persistence) {
    const resolvedHost = resolveHost(aliasIndex, g.rawHost);
    const list = byHost.get(resolvedHost) ?? [];
    list.push(g);
    byHost.set(resolvedHost, list);
  }

  const hosts = [...byHost.keys()].sort();
  const truncatedCohorts = hosts.length > MAX_COHORTS;
  const cohorts = hosts
    .slice(0, MAX_COHORTS)
    .map((resolvedHost) => buildCohort(resolvedHost, byHost.get(resolvedHost)!));
  return { cohorts, truncatedCohorts };
}

function buildCohort(resolvedHost: string, cohort: CollectionGeneration[]): PersistenceCohortResult {
  const excluded: { generationId: string; reason: ExclusionReason }[] = [];
  // Every non-participating generation's own order, kept ONLY to compute interveningExcludedCount
  // below — never used to sort or compare directly, since these generations are excluded
  // precisely because they cannot soundly participate in a pairwise comparison.
  const nonParticipatingOrders: { order: GenerationOrder }[] = [];
  const eligibleByOrderMode = new Map<GenerationOrder["kind"], CollectionGeneration[]>();

  let eligibleCount = 0;
  for (const g of cohort) {
    if (!generationEligible(g)) {
      excluded.push({
        generationId: g.generationId,
        reason: g.completenessState !== "complete" ? "partial" : "filtered",
      });
      nonParticipatingOrders.push({ order: g.order });
      continue;
    }
    eligibleCount += 1;
    const list = eligibleByOrderMode.get(g.order.kind) ?? [];
    list.push(g);
    eligibleByOrderMode.set(g.order.kind, list);
  }

  const ambiguousOrder: { generationId: string; orderKey: string | number }[] = [];
  const pairs: PersistencePairResult[] = [];
  let truncatedPairs = false;

  for (const list of eligibleByOrderMode.values()) {
    // Sort and detect ties on the RAW generations first — a tie has no real temporal basis for a
    // pairwise comparison (Codex finding H2) and is excluded before any envelope is ever built,
    // which is also what bounds envelope construction to only the generations a pair can use
    // (Codex code-review finding: envelopes were built for the whole cohort regardless of the
    // per-cohort pair cap below).
    const sorted = [...list].sort((a, b) => orderSortValue(a.order) - orderSortValue(b.order));

    const tiedValues = new Set<number>();
    for (let i = 0; i < sorted.length; i++) {
      const value = orderSortValue(sorted[i].order);
      const clashesLeft = i > 0 && orderSortValue(sorted[i - 1].order) === value;
      const clashesRight = i + 1 < sorted.length && orderSortValue(sorted[i + 1].order) === value;
      if (clashesLeft || clashesRight) tiedValues.add(value);
    }
    const ordered = sorted.filter((g) => {
      const value = orderSortValue(g.order);
      if (tiedValues.has(value)) {
        ambiguousOrder.push({ generationId: g.generationId, orderKey: orderDisplayValue(g.order) });
        nonParticipatingOrders.push({ order: g.order });
        eligibleCount -= 1; // was counted above; a tied generation cannot participate in any pair
        return false;
      }
      return true;
    });

    // Only as many generations as MAX_PAIRS_PER_COHORT can actually produce a pair need an
    // envelope at all — building one for every remaining generation in a very long cohort would
    // be pure waste (Codex code-review finding). Anything past the cap is disclosed via
    // truncatedPairs, never silently dropped from eligibleCount.
    const capacity = MAX_PAIRS_PER_COHORT + 1;
    if (ordered.length > capacity) truncatedPairs = true;
    const withinCap = ordered.slice(0, capacity);

    const envelopes: {
      generation: CollectionGeneration;
      envelope: SnapshotEnvelope<string>;
      truncatedEntries: boolean;
    }[] = [];
    for (const g of withinCap) {
      const built = generationToEnvelope(g, resolvedHost);
      if (!built.ok) {
        excluded.push({ generationId: g.generationId, reason: "ambiguous-identity" });
        nonParticipatingOrders.push({ order: g.order });
        eligibleCount -= 1;
        continue;
      }
      envelopes.push({ generation: g, envelope: built.envelope, truncatedEntries: built.truncatedEntries });
    }

    for (let i = 1; i < envelopes.length; i++) {
      const earlier = envelopes[i - 1];
      const later = envelopes[i];
      const changes = diffEnvelopes(earlier.envelope, later.envelope, (a, b) => a === b);
      const truncated = changes.length > MAX_CHANGES_PER_PAIR;
      const earlierValue = orderSortValue(earlier.generation.order);
      const laterValue = orderSortValue(later.generation.order);
      const interveningExcludedCount = nonParticipatingOrders.filter((item) => {
        if (item.order.kind !== earlier.generation.order.kind) return false;
        const value = orderSortValue(item.order);
        return value > earlierValue && value < laterValue;
      }).length;
      pairs.push({
        earlier: {
          generationId: earlier.generation.generationId,
          order: earlier.generation.order,
          artifactRef: earlier.generation.artifactRef,
        },
        later: {
          generationId: later.generation.generationId,
          order: later.generation.order,
          artifactRef: later.generation.artifactRef,
        },
        interveningExcludedCount,
        changes: truncated ? changes.slice(0, MAX_CHANGES_PER_PAIR) : changes,
        truncated,
        inventoryTruncated: earlier.truncatedEntries || later.truncatedEntries,
      });
    }
  }

  pairs.sort((a, b) => orderSortValue(a.earlier.order) - orderSortValue(b.earlier.order));

  return {
    resolvedHost,
    domain: "persistence",
    eligibleCount,
    excluded,
    ambiguousOrder,
    pairs,
    truncatedPairs,
  };
}
