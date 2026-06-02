import type { InvestigationState } from "./stateTypes.js";
import { type ScopeWindow, hasScope, inScope } from "./scope.js";

// Deterministic, AI-independent projection of an investigation onto a time window.
//
// Re-synthesis (the AI pass) re-derives findings/IOCs/MITRE from in-scope events,
// but that is model-dependent and asynchronous. This projection gives the SAME
// scoping structurally and instantly: drop out-of-scope events, then drop any
// finding/IOC/technique that is now supported ONLY by out-of-scope evidence.
//
// Linkage used (set by synthesis):
//   forensicEvent.relatedFindingIds  — which findings an event backs
//   finding.relatedIocs              — which IOCs a finding cites
//   technique.findingIds             — which findings a technique aggregates
//
// "Can't prove it's out of scope" → keep it (mirrors inScope() keeping undated
// events): a finding/IOC/technique with NO links at all is preserved.
export function projectScope(state: InvestigationState, scope: ScopeWindow): InvestigationState {
  if (!hasScope(scope)) return state;

  const forensicTimeline = state.forensicTimeline.filter((e) => inScope(e.timestamp, scope));

  // Which findings are backed by in-scope vs out-of-scope events.
  const backedInScope = new Set<string>();
  const backedOutScope = new Set<string>();
  for (const e of state.forensicTimeline) {
    const target = inScope(e.timestamp, scope) ? backedInScope : backedOutScope;
    for (const fid of e.relatedFindingIds) target.add(fid);
  }
  const findingKept = (id: string): boolean =>
    backedInScope.has(id) || !backedOutScope.has(id); // kept unless backed ONLY by out-of-scope events

  const findings = state.findings.filter((f) => findingKept(f.id));
  const survivingFindings = new Set(findings.map((f) => f.id));

  // IOCs: cited by findings. Keep an IOC if a surviving finding cites it, or if
  // no finding cites it at all (can't prove out of scope).
  const citedBySurviving = new Set<string>();
  const citedByAny = new Set<string>();
  for (const f of state.findings) {
    for (const iid of f.relatedIocs) {
      citedByAny.add(iid);
      if (survivingFindings.has(f.id)) citedBySurviving.add(iid);
    }
  }
  const iocs = state.iocs.filter((i) => citedBySurviving.has(i.id) || !citedByAny.has(i.id));

  // MITRE: recompute each technique's finding links to the survivors. A technique
  // that had links and loses them all is dropped; one with no links is preserved.
  const mitreTechniques = state.mitreTechniques
    .map((t) => ({ ...t, findingIds: t.findingIds.filter((id) => survivingFindings.has(id)) }))
    .filter((t, idx) => t.findingIds.length > 0 || state.mitreTechniques[idx].findingIds.length === 0);

  return { ...state, forensicTimeline, findings, iocs, mitreTechniques };
}
