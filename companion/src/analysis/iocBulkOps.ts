// Pure helpers for bulk IOC operations (bulk-enrich, bulk-tag, bulk-dismiss).
// Kept separate so they can be unit-tested without importing the full server.

import type { IOC } from "./stateTypes.js";
import { mergeIntelState } from "./intelHistory.js";

// After running enrichIocs() on a filtered subset of IOCs, merge the enriched results back
// into the full case IOC list. IOCs not in `enrichedSubset` are returned unchanged; order is
// preserved from `allIocs`. Extra IDs in the subset that don't exist in `allIocs` are ignored.
// An enriched copy never replaces a whole IOC (#1024): a stale completion of one re-check must not
// erase the history a faster one appended, nor resurrect an older assertion state. The intel
// fields merge by assertion id and check time; the checked-provider list unions.
export function mergeEnrichedSubset(allIocs: readonly IOC[], enrichedSubset: readonly IOC[]): IOC[] {
  const byId = new Map(enrichedSubset.map((i) => [i.id, i]));
  return allIocs.map((i) => {
    const e = byId.get(i.id);
    if (!e) return i;
    return {
      ...i,
      ...mergeIntelState(i, e),
      enrichedBy: [...new Set([...(i.enrichedBy ?? []), ...(e.enrichedBy ?? [])])],
    };
  });
}
