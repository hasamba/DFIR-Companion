// #1132: the ONE domain-specific orchestrator over mobileBackupGenerationStore.ts's own ledger.
// See RECOMMENDATION-1132.md for the full design rationale. Mirrors persistenceGenerationComparator.ts
// (#1128) structurally — cohort/sort/tie-quarantine/pair-cap logic is identical in shape — but this
// module knows about the mobile app-presence domain's own {bundleId, itemName, version} shape;
// snapshotComparisonKernel.ts does not, and is reused here completely unchanged.

import {
  generationEligible,
  type MobileBackupGeneration,
  type DeviceIdentity,
} from "./canonicalMobileBackupGeneration.js";
import type { GenerationOrder } from "./canonicalCollectionGeneration.js";
import { diffEnvelopes, type EntryChange, type SnapshotEnvelope } from "./snapshotComparisonKernel.js";

const MAX_CHANGES_PER_PAIR = 500;
const MAX_PAIRS_PER_COHORT = 50;
const MAX_COHORTS = 200;
// A hard ceiling on how many facts one generation's own envelope can hold, applied BEFORE
// diffEnvelopes runs — same rationale as persistenceGenerationComparator.ts's own constant.
const MAX_ENTRIES_PER_ENVELOPE = 10_000;

export interface MobileAppValue {
  itemName: string;
  version: string;
}

/** Structural equality for the mobile envelope's own value type (Codex design-review finding H4:
 * `diffEnvelopes()`'s own generic `valuesEqual` parameter is exactly what a non-string value type
 * needs — no kernel change required, just a real equality function instead of `===`). */
function mobileValuesEqual(a: MobileAppValue, b: MobileAppValue): boolean {
  return a.itemName === b.itemName && a.version === b.version;
}

type EnvelopeResult =
  | { ok: true; envelope: SnapshotEnvelope<MobileAppValue>; truncatedEntries: boolean }
  | { ok: false; reason: "ambiguous-identity" };

/** Builds this one generation's own envelope, or reports it as ambiguous when its inventory holds
 * two rows sharing a Bundle ID but disagreeing on itemName/version — quarantined rather than
 * silently collapsed by Map insertion order. Bundle ID alone is already a collision-free Map key
 * (a single field — no composite/delimiter risk the way persistence's technique+path pair has). */
function generationToEnvelope(g: MobileBackupGeneration, subject: string): EnvelopeResult {
  const entries = new Map<string, MobileAppValue>();
  let truncatedEntries = false;
  for (const fact of g.inventory) {
    const key = fact.bundleId;
    const existing = entries.get(key);
    const value: MobileAppValue = { itemName: fact.itemName, version: fact.version };
    if (existing !== undefined && !mobileValuesEqual(existing, value)) {
      return { ok: false, reason: "ambiguous-identity" };
    }
    if (entries.size >= MAX_ENTRIES_PER_ENVELOPE && existing === undefined) {
      truncatedEntries = true;
      continue;
    }
    entries.set(key, value);
  }
  return {
    ok: true,
    truncatedEntries,
    envelope: {
      version: 1,
      snapshotId: g.generationId,
      subject,
      domain: g.domain,
      order: g.order,
      entries,
      provenance: [g.backupInfoRef, g.installedAppsRef],
    },
  };
}

/** The raw order value, for DISPLAY only. */
function orderDisplayValue(order: GenerationOrder): string | number {
  return order.kind === "captured" ? order.capturedAt : order.sequence;
}

/** The real chronological/sequence value used for EVERY sort, tie-detection, and interval
 * comparison — parsed epoch for `captured`, never the raw string (mirrors
 * persistenceGenerationComparator.ts's own fix for the identical failure mode). */
function orderSortValue(order: GenerationOrder): number {
  return order.kind === "captured" ? Date.parse(order.capturedAt) : order.sequence;
}

export type ExclusionReason = "partial" | "filtered" | "ambiguous-identity";

export interface MobilePairResult {
  earlier: {
    generationId: string;
    order: GenerationOrder;
    backupInfoRef: { importSeq: number; artifactHash: string };
    installedAppsRef: { importSeq: number; artifactHash: string };
  };
  later: {
    generationId: string;
    order: GenerationOrder;
    backupInfoRef: { importSeq: number; artifactHash: string };
    installedAppsRef: { importSeq: number; artifactHash: string };
  };
  interveningExcludedCount: number;
  changes: EntryChange<MobileAppValue>[];
  truncated: boolean;
  inventoryTruncated: boolean;
}

export interface MobileCohortResult {
  resolvedDevice: DeviceIdentity;
  domain: "mobile-app-presence";
  eligibleCount: number;
  excluded: { generationId: string; reason: ExclusionReason }[];
  ambiguousOrder: { generationId: string; orderKey: string | number }[];
  pairs: MobilePairResult[];
  truncatedPairs: boolean;
}

export interface CompareMobileGenerationsResult {
  cohorts: MobileCohortResult[];
  truncatedCohorts: boolean;
}

function deviceCohortKey(d: DeviceIdentity): string {
  return `${d.kind}|${d.value.toLowerCase()}`;
}

/** Groups every ACTIVE generation of the "mobile-app-presence" domain into (deviceIdentity)
 * cohorts and diffs each cohort's own eligible generations, adjacent pair only, within one order
 * mode. Never infers continuity across a gap the ledger itself did not record, and never sorts a
 * tied order key into a fabricated earlier/later — mirrors comparePersistenceGenerations()
 * exactly, WITHOUT its #1138 bug (truncatedEntries is disclosed here from the start). */
export function compareMobileGenerations(
  generations: readonly MobileBackupGeneration[],
): CompareMobileGenerationsResult {
  const mobile = generations.filter((g) => g.domain === "mobile-app-presence");
  const byDevice = new Map<string, { identity: DeviceIdentity; generations: MobileBackupGeneration[] }>();
  for (const g of mobile) {
    const key = deviceCohortKey(g.deviceIdentity);
    const entry = byDevice.get(key) ?? { identity: g.deviceIdentity, generations: [] };
    entry.generations.push(g);
    byDevice.set(key, entry);
  }

  const keys = [...byDevice.keys()].sort();
  const truncatedCohorts = keys.length > MAX_COHORTS;
  const cohorts = keys.slice(0, MAX_COHORTS).map((key) => {
    const entry = byDevice.get(key)!;
    return buildCohort(entry.identity, entry.generations);
  });
  return { cohorts, truncatedCohorts };
}

function buildCohort(resolvedDevice: DeviceIdentity, cohort: MobileBackupGeneration[]): MobileCohortResult {
  const excluded: { generationId: string; reason: ExclusionReason }[] = [];
  const nonParticipatingOrders: { order: GenerationOrder }[] = [];
  const eligibleByOrderMode = new Map<GenerationOrder["kind"], MobileBackupGeneration[]>();

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
  const pairs: MobilePairResult[] = [];
  let truncatedPairs = false;

  for (const list of eligibleByOrderMode.values()) {
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
        eligibleCount -= 1;
        return false;
      }
      return true;
    });

    const capacity = MAX_PAIRS_PER_COHORT + 1;
    if (ordered.length > capacity) truncatedPairs = true;
    const withinCap = ordered.slice(0, capacity);

    const envelopes: {
      generation: MobileBackupGeneration;
      envelope: SnapshotEnvelope<MobileAppValue>;
      truncatedEntries: boolean;
    }[] = [];
    for (const g of withinCap) {
      const built = generationToEnvelope(g, deviceCohortKey(resolvedDevice));
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
      const changes = diffEnvelopes(earlier.envelope, later.envelope, mobileValuesEqual);
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
          backupInfoRef: earlier.generation.backupInfoRef,
          installedAppsRef: earlier.generation.installedAppsRef,
        },
        later: {
          generationId: later.generation.generationId,
          order: later.generation.order,
          backupInfoRef: later.generation.backupInfoRef,
          installedAppsRef: later.generation.installedAppsRef,
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
    resolvedDevice,
    domain: "mobile-app-presence",
    eligibleCount,
    excluded,
    ambiguousOrder,
    pairs,
    truncatedPairs,
  };
}
