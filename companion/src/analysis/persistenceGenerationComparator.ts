// #1128: the ONE domain-specific orchestrator over the persistence domain's own already-shipped
// ledger (#1108's collectionGenerationStore.ts). See RECOMMENDATION-1128.md for the full design
// rationale, including the 3 High findings a Codex adversarial design review round found in the
// first draft (no envelope/kernel/adapter separation, tied-order fabrication, an unsafe
// concatenated map key) and how each was fixed.
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

function keyFor(technique: string, path: string): string {
  // Collision-free, unlike `${technique}|${path}` — a `|` inside either field would otherwise let
  // two distinct identities collide (Codex design-review finding H3).
  return JSON.stringify([technique, path]);
}

type EnvelopeResult =
  { ok: true; envelope: SnapshotEnvelope<string> } | { ok: false; reason: "ambiguous-identity" };

/** Builds this one generation's own envelope, or reports it as ambiguous when its inventory holds
 * two rows sharing an identity (technique, path) but disagreeing on value — quarantined rather
 * than silently collapsed by Map insertion order (Codex finding H3's own second half). */
function generationToEnvelope(g: CollectionGeneration, resolvedHost: string): EnvelopeResult {
  const entries = new Map<string, string>();
  for (const fact of g.inventory) {
    const key = keyFor(fact.technique, fact.path);
    const existing = entries.get(key);
    if (existing !== undefined && existing !== fact.value) {
      return { ok: false, reason: "ambiguous-identity" };
    }
    entries.set(key, fact.value);
  }
  return {
    ok: true,
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

function orderKey(order: GenerationOrder): string | number {
  return order.kind === "captured" ? order.capturedAt : order.sequence;
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

/** Groups every ACTIVE generation of the "persistence" domain into (resolvedHost) cohorts and
 * diffs each cohort's own eligible generations, adjacent pair only, within one order mode. Never
 * infers continuity across a gap the ledger itself did not record, and never sorts a tied order
 * key into a fabricated earlier/later (Codex findings H2/H4). */
export function comparePersistenceGenerations(
  generations: readonly CollectionGeneration[],
  aliasIndex: HostAliasIndex,
): PersistenceCohortResult[] {
  const persistence = generations.filter((g) => g.domain === "persistence");
  const byHost = new Map<string, CollectionGeneration[]>();
  for (const g of persistence) {
    const resolvedHost = resolveHost(aliasIndex, g.rawHost);
    const list = byHost.get(resolvedHost) ?? [];
    list.push(g);
    byHost.set(resolvedHost, list);
  }

  const results: PersistenceCohortResult[] = [];
  for (const resolvedHost of [...byHost.keys()].sort()) {
    results.push(buildCohort(resolvedHost, byHost.get(resolvedHost)!));
  }
  return results;
}

function buildCohort(resolvedHost: string, cohort: CollectionGeneration[]): PersistenceCohortResult {
  const excluded: { generationId: string; reason: ExclusionReason }[] = [];
  // Every non-participating generation's own order, kept ONLY to compute interveningExcludedCount
  // below — never used to sort or compare, since these generations are excluded precisely because
  // they cannot soundly participate in a pairwise comparison.
  const nonParticipatingOrders: { order: GenerationOrder }[] = [];
  const eligibleByOrderMode = new Map<
    GenerationOrder["kind"],
    { generation: CollectionGeneration; envelope: SnapshotEnvelope<string> }[]
  >();

  for (const g of cohort) {
    if (!generationEligible(g)) {
      excluded.push({
        generationId: g.generationId,
        reason: g.completenessState !== "complete" ? "partial" : "filtered",
      });
      nonParticipatingOrders.push({ order: g.order });
      continue;
    }
    const built = generationToEnvelope(g, resolvedHost);
    if (!built.ok) {
      excluded.push({ generationId: g.generationId, reason: "ambiguous-identity" });
      nonParticipatingOrders.push({ order: g.order });
      continue;
    }
    const list = eligibleByOrderMode.get(g.order.kind) ?? [];
    list.push({ generation: g, envelope: built.envelope });
    eligibleByOrderMode.set(g.order.kind, list);
  }

  const ambiguousOrder: { generationId: string; orderKey: string | number }[] = [];
  const pairs: PersistencePairResult[] = [];
  let truncatedPairs = false;
  let eligibleCount = 0;

  for (const list of eligibleByOrderMode.values()) {
    eligibleCount += list.length;
    // Sort by order key, but detect ties: two generations sharing an identical order key have no
    // real temporal basis for a pairwise comparison (Codex finding H2) and are excluded from every
    // pair, disclosed separately instead.
    const sorted = [...list].sort((a, b) => {
      const ak = orderKey(a.generation.order);
      const bk = orderKey(b.generation.order);
      return ak < bk ? -1 : ak > bk ? 1 : 0;
    });

    const tiedKeys = new Set<string | number>();
    for (let i = 0; i < sorted.length; i++) {
      const key = orderKey(sorted[i].generation.order);
      const clashesLeft = i > 0 && orderKey(sorted[i - 1].generation.order) === key;
      const clashesRight = i + 1 < sorted.length && orderKey(sorted[i + 1].generation.order) === key;
      if (clashesLeft || clashesRight) tiedKeys.add(key);
    }
    const ordered = sorted.filter((item) => {
      const key = orderKey(item.generation.order);
      if (tiedKeys.has(key)) {
        ambiguousOrder.push({ generationId: item.generation.generationId, orderKey: key });
        nonParticipatingOrders.push({ order: item.generation.order });
        return false;
      }
      return true;
    });

    for (let i = 1; i < ordered.length; i++) {
      if (pairs.length >= MAX_PAIRS_PER_COHORT) {
        truncatedPairs = true;
        break;
      }
      const earlier = ordered[i - 1];
      const later = ordered[i];
      const changes = diffEnvelopes(earlier.envelope, later.envelope, (a, b) => a === b);
      const truncated = changes.length > MAX_CHANGES_PER_PAIR;
      const earlierKey = orderKey(earlier.generation.order);
      const laterKey = orderKey(later.generation.order);
      const interveningExcludedCount = nonParticipatingOrders.filter((item) => {
        if (item.order.kind !== earlier.generation.order.kind) return false;
        const k = orderKey(item.order);
        return k > earlierKey && k < laterKey;
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
      });
    }
  }

  pairs.sort((a, b) => String(orderKey(a.earlier.order)).localeCompare(String(orderKey(b.earlier.order))));

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
