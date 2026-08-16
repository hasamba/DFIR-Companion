import { findNearDuplicates, type HostAliasIndex, type NearDuplicate } from "./hostAlias.js";
import { dismissalKey, type HostDuplicateDismissal } from "./hostDuplicateDismissals.js";
import type { InvestigationState } from "./stateTypes.js";

// The pre-synthesis gate: one machine spelled two ways (WIN11 vs WIN11.windomain.local) is two
// hosts to every derivation the model reads, so synthesis is blocked until the analyst says which
// it is. Pure — the caller supplies the host names, the alias index and the dismissals.
//
// WHY THE PENDING LIST IS DERIVED RATHER THAN STORED. A merge already resolves both spellings to
// one canonical name through the alias index, so a merged pair stops being a near-duplicate with no
// bookkeeping. Storing the pending list too would mean a second copy of the truth that has to be
// invalidated on every merge, every import and every fleet refresh. Deriving it means a duplicate
// arriving on import 47 is treated exactly like one arriving on import 1.

/** Thrown by synthesize() when a case holds an unresolved near-duplicate host pair. The route layer
 *  turns this into HTTP 409 so the dashboard can render the merge panel. */
export class HostMergeDecisionRequired extends Error {
  constructor(public readonly pairs: NearDuplicate[]) {
    super(
      `${pairs.length} possible duplicate host${pairs.length === 1 ? "" : "s"} awaiting a merge decision`,
    );
    this.name = "HostMergeDecisionRequired";
  }
}

// The host names synthesis will actually read. The forensic timeline is the complete source: the
// super timeline is only touched AFTER the model call (the second-look sweep), so a host that lives
// only there cannot reach the prompt — and scanning it here would put a full table scan on every
// synthesis. See the design doc's "Source of truth" section.
export function hostNamesFromState(state: InvestigationState): string[] {
  const seen = new Set<string>();
  for (const e of state.forensicTimeline ?? []) {
    const asset = (e.asset ?? "").trim();
    if (asset) seen.add(asset);
  }
  return [...seen];
}

export function pendingNearDuplicates(
  hostNames: readonly string[],
  aliasIndex: HostAliasIndex,
  dismissals: readonly HostDuplicateDismissal[],
): NearDuplicate[] {
  const dismissed = new Set(dismissals.map((d) => dismissalKey(d.canonical, d.other)));
  return findNearDuplicates(aliasIndex, [...hostNames]).filter(
    (pair) => !dismissed.has(dismissalKey(pair.canonical, pair.other)),
  );
}
