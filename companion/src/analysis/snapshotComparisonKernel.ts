// A generic, domain-blind pair-comparison kernel (#1128, the shared prerequisite 932.17's own
// design review required before either the persistence domain — #1108's own collection-generation
// ledger — or a future mobile domain could get a sound "was this present before, and is it now"
// comparator). See RECOMMENDATION-1128.md for the full design rationale.
//
// This module knows NOTHING about persistence, mobile, hosts, or any specific evidence domain — it
// operates purely on two already-built `SnapshotEnvelope`s and a caller-supplied equality check.
// Building the envelope (resolving identity, choosing keys, detecting duplicates) is the CALLER's
// own responsibility; this kernel trusts the keys it is given to already be collision-free.

export interface SnapshotEnvelope<TValue> {
  version: 1;
  snapshotId: string;
  subject: string;
  domain: string;
  order: { kind: "captured"; capturedAt: string } | { kind: "declared"; sequence: number };
  entries: Map<string, TValue>;
  provenance: { importSeq: number; artifactHash: string }[];
}

export type EntryChange<TValue> =
  | { direction: "present-only-in-earlier"; key: string; earlierValue: TValue }
  | { direction: "present-only-in-later"; key: string; laterValue: TValue }
  | { direction: "changed"; key: string; earlierValue: TValue; laterValue: TValue };

/** A pure exact-key diff between two envelopes — never claims descent, causation, or intent; only
 * that a key present in one is absent from (or has a different value in) the other. Never labeled
 * "added"/"removed"/"deleted": those verbs claim an event this kernel cannot support (932.2's own
 * "report an observed difference... not an exact creation/deletion time" guardrail). Sorted
 * deterministically by key, then direction, so equivalent evidence always serializes identically
 * regardless of the entries' own Map insertion order. */
export function diffEnvelopes<TValue>(
  earlier: SnapshotEnvelope<TValue>,
  later: SnapshotEnvelope<TValue>,
  valuesEqual: (a: TValue, b: TValue) => boolean,
): EntryChange<TValue>[] {
  const changes: EntryChange<TValue>[] = [];
  for (const [key, earlierValue] of earlier.entries) {
    if (!later.entries.has(key)) {
      changes.push({ direction: "present-only-in-earlier", key, earlierValue });
      continue;
    }
    const laterValue = later.entries.get(key)!;
    if (!valuesEqual(earlierValue, laterValue)) {
      changes.push({ direction: "changed", key, earlierValue, laterValue });
    }
  }
  for (const [key, laterValue] of later.entries) {
    if (!earlier.entries.has(key)) changes.push({ direction: "present-only-in-later", key, laterValue });
  }
  const directionRank = { "present-only-in-earlier": 0, changed: 1, "present-only-in-later": 2 } as const;
  changes.sort((a, b) => a.key.localeCompare(b.key) || directionRank[a.direction] - directionRank[b.direction]);
  return changes;
}
