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
import { repairIocValue } from "./iocValue.js";

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

export interface IocValueRepairResult {
  state: InvestigationState;
  changed: { id: string; before: string; after: string; note?: string }[];
}

// Backfill for cases written before ingest-time value normalization (#177): lift the human
// annotation out of each `value` into `note`, and canonicalize the indicator. Repair-ONLY — an
// entry whose value can't be salvaged is left exactly as it is rather than dropped, because on an
// existing case that value may be the only record of something an analyst saw. (Ingest is stricter:
// mergeDelta never CREATES an unusable row in the first place.)
//
// Deliberately does NOT collapse rows that end up sharing a value — e.g. a case holding both
// "10.10.20.15" and "10.10.20.15 (DC01)" keeps two rows after repair. Merging them means remapping
// every findings.relatedIocs / tag / comment reference from the dropped id to the kept one, which
// risks silently orphaning analyst annotations; the analyst-facing IOC merge (#82) does that
// safely and deliberately. Exports dedupe by value regardless, so the pushed result is clean.
export function repairIocValues(state: InvestigationState): IocValueRepairResult {
  const changed: IocValueRepairResult["changed"] = [];
  const iocs = state.iocs.map((ioc) => {
    const repaired = repairIocValue(ioc);
    if (!repaired) return ioc;
    const note = ioc.note ?? repaired.note;
    if (repaired.value === ioc.value && note === ioc.note) return ioc;
    changed.push({ id: ioc.id, before: ioc.value, after: repaired.value, ...(note ? { note } : {}) });
    return { ...ioc, value: repaired.value, ...(note ? { note } : {}) };
  });
  if (changed.length === 0) return { state, changed };
  return { state: { ...state, iocs }, changed };
}
