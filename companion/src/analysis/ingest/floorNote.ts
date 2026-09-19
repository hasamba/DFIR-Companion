// The analyst's severity floor (`applySeverityFloor`, forwarded per batch by the unified Import
// button) runs on the EVENTS only — the parser's IOC list (a sample's hashes, an alert's C2 URL,
// a THOR hash the analyst will execute) is never floored. Two consequences every importer that
// merges IOCs has to honour (#1353, the class-wide follow-up to #1337 / #1304):
//
//   1. The empty-import guard tests events AND IOCs. An events-only guard sends a total floor to
//      `noteEmptyImport`, which merges `iocs: []` — the IOCs are discarded, while an import where
//      even one event survives keeps ALL of them. That is a cliff, not a policy; the policy is
//      that a floor removes events, never IOCs.
//   2. The note reports the events actually merged plus how many the floor removed, so an
//      analyst reading "0 event(s) … 5 below the severity floor, 3 IOC(s)" knows the IOCs
//      landed and why the timeline did not move.
//
// `preFloor` is the parser's own event count (`parsed.kept`, or the parser rows plus any
// cross-upload rows); `postFloor` is what survived the floor.
export function describeFloor(preFloor: number, postFloor: number): string {
  const removed = preFloor - postFloor;
  return removed > 0 ? `, ${removed} below the severity floor` : "";
}
