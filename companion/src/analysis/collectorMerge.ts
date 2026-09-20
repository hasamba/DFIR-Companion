// Collector attribution through a correlation merge (#1477).
//
// ONE physical log record read by several parsers (correlate.ts step 0b) is one observation. If any
// parser's reading recognised it as the case's own collector at work (`origin: "collector"` —
// collectorDeployment.ts, veloDetectionNoise.ts), that holds for the record whichever reading's
// text won primary: the fact came from the engine's own fields on that record (the SYSTEM logon,
// the script path under the collector's tool tree, the collector exe as parent), not from the
// parser's wording. So the merged row keeps the Info the collector rule assigned instead of the
// worst member's grade, and keeps the origin the post-import tagger honours. Before this, a Chainsaw
// High reading of a PersistenceSniper record became primary, the Velociraptor reading's origin was
// dropped, and the row reached the forensic timeline.
//
// Only for a SAME-RECORD group: a group joined on hash / path / pid holds DIFFERENT records, and a
// collector row's grade says nothing about the others'. The aggregator strips sourceRecordId from
// any collapsed member, so a group with one absent is never same-record.

import type { ForensicEvent, Severity } from "./stateTypes.js";

/** The grade and origin a same-record merge must carry, or null when the group is not one. */
export function collectorRecordGrade(
  primary: ForensicEvent,
  events: readonly ForensicEvent[],
): { severity: Severity; origin: "collector" } | null {
  const id = primary.sourceRecordId;
  if (!id || !events.every((e) => e.sourceRecordId === id)) return null;
  return events.some((e) => e.origin === "collector") ? { severity: "Info", origin: "collector" } : null;
}
