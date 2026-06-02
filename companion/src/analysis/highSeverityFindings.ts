import type { InvestigationState, Finding, Severity } from "./stateTypes.js";

const HIGH_SEVERITY = new Set<Severity>(["Critical", "High"]);

// A concise finding title from an event description: first sentence, capped in length.
export function shortTitle(description: string, max = 90): string {
  const firstSentence = description.split(/(?<=[.!?])\s/)[0] ?? description;
  const t = firstSentence.trim();
  return t.length <= max ? t : t.slice(0, max - 1).trimEnd() + "…";
}

// Deterministic safety net for the heuristic "a Critical/High artifact row is almost
// always a finding". After synthesis, any eligible (in-scope, non-legitimate)
// Critical/High forensic event that synthesis left WITHOUT a linked finding gets an
// auto-generated finding, so a high-severity detection can never be silently missed.
//
// Pure: returns a new state (never mutates). Idempotent — the finding id is derived
// from the event id, and events already carrying a finding link are skipped, so
// re-running never duplicates.
export function backfillHighSeverityFindings(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
  timestamp: string,
): InvestigationState {
  const newFindings: Finding[] = [];
  const linkByEvent = new Map<string, string>();

  for (const e of state.forensicTimeline) {
    if (!HIGH_SEVERITY.has(e.severity)) continue;     // only Critical/High
    if (!eligibleIds.has(e.id)) continue;             // respect scope + legitimate exclusions
    if (e.relatedFindingIds.length > 0) continue;     // synthesis already covered it
    const id = `f-auto-${e.id}`;
    newFindings.push({
      id,
      severity: e.severity,
      title: shortTitle(e.description),
      description: `${e.description} (auto-flagged from a ${e.severity}-severity artifact row that had no finding).`,
      relatedIocs: [],
      mitreTechniques: [...e.mitreTechniques],
      sourceScreenshots: [...e.sourceScreenshots],
      firstSeen: e.timestamp || timestamp,
      lastUpdated: timestamp,
      status: "open",
    });
    linkByEvent.set(e.id, id);
  }

  if (newFindings.length === 0) return state;
  return {
    ...state,
    findings: [...state.findings, ...newFindings],
    forensicTimeline: state.forensicTimeline.map((e) =>
      linkByEvent.has(e.id)
        ? { ...e, relatedFindingIds: [...e.relatedFindingIds, linkByEvent.get(e.id)!] }
        : e,
    ),
  };
}
