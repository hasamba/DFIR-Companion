import type { InvestigationState } from "./stateTypes.js";

// ATT&CK techniques the analyst removed by accepting a second-opinion `mitre_removed` delta (#1742).
//
// The decision used to delete the row from the stored MITRE table and nothing else. The findings kept
// the tag, and the table is completed at read time from the tags findings and events carry (#893), so
// the removed technique came straight back in the panel, the report and every export.
//
// So the decision is RECORDED, not applied to stored data: `state.rejectedTechniques` lists the ids,
// and this projection hides them at every conclusion-facing seam — the report state (filteredState),
// the dashboard state route and the live state push. Stored events, findings and the model's table
// keep exactly what the importer, the tagger and the model wrote. That is what makes the decision
// reversible: switching the delta back to rejected clears the id, and the next read shows it again.

/** The minimum a delta needs for this module — the second-opinion record's delta shape. */
interface TechniqueDecision {
  kind: string;
  title: string;
  status: string;
}

/**
 * The ids an accepted `mitre_removed` delta rejects, in delta order. A later accepted `mitre_added`
 * for the same id wins — the analyst changed their mind. Sorted, so the stored value is stable.
 */
export function rejectedTechniqueIds(deltas: readonly TechniqueDecision[]): string[] {
  const rejected = new Set<string>();
  for (const d of deltas) {
    if (d.status !== "accepted") continue;
    if (d.kind === "mitre_removed") rejected.add(d.title);
    else if (d.kind === "mitre_added") rejected.delete(d.title);
  }
  return [...rejected].sort();
}

/** The state with its recorded rejections replaced; unchanged (same object) when nothing differs. */
export function withRejectedTechniqueIds(
  state: InvestigationState,
  ids: readonly string[],
): InvestigationState {
  const before = state.rejectedTechniques ?? [];
  if (before.length === ids.length && before.every((id, i) => id === ids[i])) return state;
  if (ids.length > 0) return { ...state, rejectedTechniques: [...ids] };
  const { rejectedTechniques: _cleared, ...rest } = state;
  return rest;
}

/**
 * The rejections a synthesis save keeps. The run applied the second-opinion record it read at the
 * start; an analyst who accepted or reversed a removal while it ran saved a newer list. Newer wins:
 * when `latest` differs from the snapshot, the decision changed during the run (Codex review, #1742).
 */
export function concurrentRejections(
  loaded: Pick<InvestigationState, "rejectedTechniques">,
  next: InvestigationState,
  latest: Pick<InvestigationState, "rejectedTechniques">,
): InvestigationState {
  const a = loaded.rejectedTechniques ?? [];
  const b = latest.rejectedTechniques ?? [];
  const changed = a.length !== b.length || a.some((id, i) => id !== b[i]);
  return changed ? withRejectedTechniqueIds(next, b) : next;
}

/**
 * The read-time view with every rejected id hidden: the MITRE table row, each finding's tags and each
 * forensic event's tags. Pure — the input is never modified. No rejections → the same object.
 */
export function withoutRejectedTechniques<S extends Partial<InvestigationState>>(state: S): S {
  const rejected = new Set(state.rejectedTechniques ?? []);
  if (rejected.size === 0) return state;
  const keep = (ids: readonly string[] | undefined) => (ids ?? []).filter((id) => !rejected.has(id));
  return {
    ...state,
    ...(state.mitreTechniques
      ? { mitreTechniques: state.mitreTechniques.filter((t) => !rejected.has(t.id)) }
      : {}),
    ...(state.findings
      ? { findings: state.findings.map((f) => ({ ...f, mitreTechniques: keep(f.mitreTechniques) })) }
      : {}),
    ...(state.forensicTimeline
      ? { forensicTimeline: withoutRejectedEventTags(state.forensicTimeline, rejected) }
      : {}),
  };
}

/** Event tags without the rejected ids — for a route that returns events apart from the state. */
export function withoutRejectedEventTags<E extends { mitreTechniques: string[] }>(
  events: readonly E[],
  rejected: ReadonlySet<string> | readonly string[] | undefined,
): E[] {
  const ids = rejected instanceof Set ? rejected : new Set(rejected ?? []);
  if (ids.size === 0) return [...events];
  return events.map((e) =>
    e.mitreTechniques.some((id) => ids.has(id))
      ? { ...e, mitreTechniques: e.mitreTechniques.filter((id) => !ids.has(id)) }
      : e,
  );
}
