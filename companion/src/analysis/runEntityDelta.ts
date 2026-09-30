import { claimSnapshot } from "./analysisRunHash.js";
import type {
  AnalysisRunClaim,
  AnalysisRunHash,
  AnalysisRunInput,
  AnalysisRunOutput,
} from "./analysisRunTypes.js";
import type { Finding } from "./stateTypes.js";

/**
 * What an import changed in the case's entities (#1887): the forensic events and IOCs, by id.
 *
 * An import receipt used to list every id the case held before and after, so each receipt grew with
 * the case (1.2 MB at 40k rows). It now lists what the import added and removed, plus both counts.
 * The ids are a MULTISET: a second row with an id already present counts as added, and one of two
 * duplicates removed counts as removed. A row whose id is not a string is left out of the lists but
 * is still counted. `added` keeps the order of `after`, `removed` the order of `before`.
 */
export interface EntityDelta {
  added: string[];
  removed: string[];
  beforeCount: number;
  afterCount: number;
}

export function entityDelta(before: readonly unknown[], after: readonly unknown[]): EntityDelta {
  const left = new Map<string, number>();
  for (const id of before) if (typeof id === "string") left.set(id, (left.get(id) ?? 0) + 1);
  const added: string[] = [];
  for (const id of after) {
    if (typeof id !== "string") continue;
    const n = left.get(id) ?? 0;
    if (n > 0) left.set(id, n - 1);
    else added.push(id);
  }
  const removed: string[] = [];
  for (const id of before) {
    if (typeof id !== "string") continue;
    const n = left.get(id) ?? 0;
    if (n === 0) continue;
    left.set(id, n - 1);
    removed.push(id);
  }
  return { added, removed, beforeCount: before.length, afterCount: after.length };
}

/** One claim per finding, as every run recorder builds it (analysisRunSnapshot.ts). */
export function findingClaims(findings: readonly Finding[]): AnalysisRunClaim[] {
  return findings.map((finding) =>
    claimSnapshot(finding.id, {
      title: finding.title,
      severity: finding.severity,
      description: finding.description,
      evidenceEventIds: finding.relatedEventIds,
    }),
  );
}

/**
 * An import receipt's input (less its artifacts) and output: the entity counts before and after, the
 * ids added and removed, the case fingerprint, and the findings as claims (findings are not entities
 * here: `claims` carries them).
 */
export function importReceipt(
  before: readonly unknown[],
  after: readonly unknown[],
  hashes: readonly AnalysisRunHash[],
  findings: readonly Finding[],
): { input: Omit<AnalysisRunInput, "artifacts">; output: AnalysisRunOutput } {
  const delta = entityDelta(before, after);
  return {
    input: { eventIds: [], entityIds: [], entityCount: delta.beforeCount },
    output: {
      entityIds: delta.added,
      removedEntityIds: delta.removed,
      entityCount: delta.afterCount,
      hashes: [...hashes],
      claims: findingClaims(findings),
    },
  };
}
