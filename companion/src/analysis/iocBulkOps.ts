// Pure helpers for bulk IOC operations (bulk-enrich, bulk-tag, bulk-dismiss).
// Kept separate so they can be unit-tested without importing the full server.

import type { IOC } from "./stateTypes.js";

// After running enrichIocs() on a filtered subset of IOCs, merge the enriched results back
// into the full case IOC list. IOCs not in `enrichedSubset` are returned unchanged; order is
// preserved from `allIocs`. Extra IDs in the subset that don't exist in `allIocs` are ignored.
export function mergeEnrichedSubset(allIocs: readonly IOC[], enrichedSubset: readonly IOC[]): IOC[] {
  const byId = new Map(enrichedSubset.map((i) => [i.id, i]));
  return allIocs.map((i) => byId.get(i.id) ?? i);
}
