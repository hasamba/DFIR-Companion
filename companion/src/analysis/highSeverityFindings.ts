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
// Events are GROUPED by their shortTitle before creating findings, so a burst of
// near-identical detections (e.g. 30 Windows Defender hits from one Sigma rule) becomes
// ONE finding + ONE playbook task rather than one per event.
//
// Pure: returns a new state (never mutates). Idempotent — the finding id is derived from
// the lex-first event id in each title-group, and synthesis resets relatedFindingIds
// before backfill runs, so re-running over the same events produces the same ids.
export function backfillHighSeverityFindings(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
  timestamp: string,
): InvestigationState {
  // Collect uncovered eligible events.
  const eligible: InvestigationState["forensicTimeline"] = [];
  for (const e of state.forensicTimeline) {
    if (!HIGH_SEVERITY.has(e.severity)) continue;
    if (!eligibleIds.has(e.id)) continue;
    if (e.relatedFindingIds.length > 0) continue;
    eligible.push(e);
  }
  if (eligible.length === 0) return state;

  // Group by shortTitle so near-identical events collapse into one finding.
  const groups = new Map<string, InvestigationState["forensicTimeline"]>();
  for (const e of eligible) {
    const title = shortTitle(e.description);
    const group = groups.get(title) ?? [];
    group.push(e);
    groups.set(title, group);
  }

  const newFindings: Finding[] = [];
  const linkByEvent = new Map<string, string>();

  for (const [title, events] of groups) {
    // Stable finding id: lex-first event id in the group.
    const repId = [...events].sort((a, b) => a.id.localeCompare(b.id))[0].id;
    const findingId = `f-auto-${repId}`;
    const repEvent = events.find((e) => e.id === repId)!;
    const severity: Severity = events.some((e) => e.severity === "Critical") ? "Critical" : "High";
    const mitre = [...new Set(events.flatMap((e) => e.mitreTechniques))];
    const screenshots = [...new Set(events.flatMap((e) => e.sourceScreenshots))];
    const firstSeen = events.map((e) => e.timestamp).filter(Boolean).sort()[0] || timestamp;
    const count = events.length;
    const suffix = count > 1
      ? ` (auto-flagged; ${count} similar ${severity}-severity events grouped under this title).`
      : ` (auto-flagged from a ${severity}-severity artifact row that had no finding).`;

    newFindings.push({
      id: findingId,
      severity,
      confidence: 100,
      title,
      description: `${repEvent.description}${suffix}`,
      relatedIocs: [],
      mitreTechniques: mitre,
      sourceScreenshots: screenshots,
      firstSeen,
      lastUpdated: timestamp,
      status: "open",
    });

    for (const e of events) {
      linkByEvent.set(e.id, findingId);
    }
  }

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
