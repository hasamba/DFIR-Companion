// Repair a case's IOC list after a known corruption class: concurrent imports racing on the same
// case's state (two importers each `load` a stale snapshot before either `save`s — see
// stateStore.ts, which has no per-case write lock) can independently assign the SAME next-sequential
// id to a new IOC, and both survive as separate array entries once the writes land. Every consumer
// (findings.relatedIocs, tags/comments, enrichment badges) treats an id as unique, so a same-id
// duplicate is pure noise, never a distinct entity — collapsing it needs no reference remapping.
//
// Deliberately NOT touching same-value-but-different-id duplicates here (e.g. a hostname that arrived
// with different casing before mergeDelta's dedup became case-insensitive): collapsing those would
// require remapping every relatedIocs/comment/tag reference from the dropped id to the kept one, which
// risks silently orphaning analyst annotations. New imports no longer create that class going forward;
// existing ones are left for a future, more careful migration if needed.
import type { InvestigationState, IOC } from "./stateTypes.js";

export interface IocRepairResult {
  state: InvestigationState;
  removed: number;   // duplicate rows dropped (same id as an earlier row)
}

export function dedupeIocsById(state: InvestigationState): IocRepairResult {
  const seen = new Set<string>();
  const kept: IOC[] = [];
  let removed = 0;
  for (const ioc of state.iocs) {
    if (seen.has(ioc.id)) { removed++; continue; }
    seen.add(ioc.id);
    kept.push(ioc);
  }
  if (removed === 0) return { state, removed: 0 };
  return { state: { ...state, iocs: kept }, removed };
}
