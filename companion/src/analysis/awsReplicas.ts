// CloudTrail replicas (#931 item 5): one cross-account action produces TWO records — one in the
// caller's account, one in the resource owner's — with different eventIDs and recipientAccountIds
// and the same `sharedEventID`. Counted as two rows they inflate every count and every threshold
// downstream; keyed together by the aggregator they lose one record's provenance. This pass runs
// BEFORE the optional aggregation and independent of it: replicas of one artifact become one row,
// count 1, with every replica's raw-record pointer, and the more informative identity kept — a
// named principal over an AWSAccount/AWSService view, else the first. Replicas imported from two
// files stay two rows (their ids are import-prefixed); the manual says so.

import type { MappedEvent } from "./siemImport.js";
import type { CanonicalFieldProvenance } from "./canonicalEvent.js";

export interface ReplicaCandidate {
  event: MappedEvent;
  /** CloudTrail's sharedEventID; "" when the record is not a replica. */
  replicaId: string;
  /** A named principal (IAMUser, AssumedRole, …) beats an account or service view. */
  informative: boolean;
  recipientAccountId: string;
}

export function mergeReplicas(candidates: readonly ReplicaCandidate[]): MappedEvent[] {
  const groups = new Map<string, ReplicaCandidate[]>();
  const order: Array<ReplicaCandidate | string> = [];
  for (const c of candidates) {
    if (!c.replicaId) {
      order.push(c);
      continue;
    }
    const g = groups.get(c.replicaId);
    if (g) g.push(c);
    else {
      groups.set(c.replicaId, [c]);
      order.push(c.replicaId);
    }
  }
  return order.map((entry) => {
    if (typeof entry !== "string") return entry.event;
    const group = groups.get(entry)!;
    if (group.length === 1) return group[0].event;
    const kept = group.find((c) => c.informative) ?? group[0];
    const others = group.filter((c) => c !== kept);
    const pointers = others.flatMap((c) => c.event.canonical?.evidence.rawRecords ?? []);
    const alsoIn = [
      ...new Set(others.map((c) => c.recipientAccountId).filter((a) => a && a !== kept.recipientAccountId)),
    ];
    const note = alsoIn.length ? ` [also recorded in account ${alsoIn.join(", ")}]` : "";
    const description = `${kept.event.description}${note}`.slice(0, 600);
    // The two accounts of a cross-account action are the caller's (`cloud.accountId`) and the
    // resource owner's: the merged row's `cloud.recipientAccountId` is the one that is NOT the
    // caller's, so a Hunt on either account id finds the action.
    const caller = kept.event.canonical?.cloud?.accountId ?? "";
    const ownerCandidate =
      group.find((c) => c.recipientAccountId && c.recipientAccountId !== caller) ??
      group.find((c) => c.recipientAccountId);
    const owner = ownerCandidate?.recipientAccountId ?? "";
    // The value's provenance must point at the REPLICA that carries it: the owner's record, not
    // the kept caller record whose own recipientAccountId is a different account.
    const ownerLocator = ownerCandidate?.event.canonical?.evidence.rawRecords[0]?.locator ?? "";
    const provenance = kept.event.canonical?.fieldProvenance ?? {};
    const recipientProvenance: Record<string, CanonicalFieldProvenance> =
      owner && ownerLocator
        ? {
            "cloud.recipientAccountId": {
              origin: "raw",
              confidence: "high",
              rawFields: ["recipientAccountId"],
              recordLocators: [ownerLocator],
            },
          }
        : {};
    return {
      ...kept.event,
      description,
      ...(kept.event.canonical
        ? {
            canonical: {
              ...kept.event.canonical,
              cloud: { ...kept.event.canonical.cloud, ...(owner ? { recipientAccountId: owner } : {}) },
              fieldProvenance: { ...provenance, ...recipientProvenance },
              evidence: {
                ...kept.event.canonical.evidence,
                rawRecords: [...kept.event.canonical.evidence.rawRecords, ...pointers],
              },
            },
          }
        : {}),
    };
  });
}
