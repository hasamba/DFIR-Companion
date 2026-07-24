import type { InvestigationState, Finding, IOC } from "./stateTypes.js";

// A coach recommendation returned to the dashboard sidebar.
export interface CoachRecommendation {
  id: string;
  priority: number;        // higher = more important
  action: string;          // short imperative title
  rationale: string;       // one-sentence why this matters now
  cta: string;             // button label, e.g. "Run enrichment"
  route?: string;          // optional API route that performs the action
  panel?: string;          // optional dashboard panel to open
}

// Stable heuristics that score what the analyst should do next. No AI calls here — only
// deterministic reads of existing case state, so this is fast and safe to call repeatedly.
export function recommendNextActions(state: InvestigationState): CoachRecommendation[] {
  const recs: CoachRecommendation[] = [];

  const openFindings = state.findings.filter((f) => !isConfirmedOrDismissed(f));
  const unenrichedIocs = state.iocs.filter((ioc) => !ioc.enrichedBy?.length && !ioc.enrichments?.length);
  const unansweredQuestions = state.keyQuestions.filter((q) => !q.answer || q.answer.trim().length === 0);
  const openNextSteps = state.nextSteps.filter((s) => !s.staleReSynth);
  const hasEvents = state.forensicTimeline.length > 0 || state.timeline.length > 0;

  // 1. No evidence yet — the case is empty.
  if (!hasEvents && state.findings.length === 0 && state.iocs.length === 0) {
    recs.push({
      id: "import-evidence",
      priority: 100,
      action: "Import evidence",
      rationale: "The case has no events, findings, or IOCs yet — start by importing logs, screenshots, or tool output.",
      cta: "Open import",
      panel: "import",
    });
  }

  // 2. Unenriched IOCs are the highest-value quick win.
  if (unenrichedIocs.length > 0) {
    recs.push({
      id: "enrich-iocs",
      priority: 90,
      action: `Enrich ${unenrichedIocs.length} IOC${unenrichedIocs.length > 1 ? "s" : ""}`,
      rationale: "Threat-intel enrichment turns raw IOCs into verdicts and context in seconds.",
      cta: "Run enrichment",
      route: `/cases/${state.caseId}/enrich`,
      panel: "iocs",
    });
  }

  // 3. Key questions the AI needs answered to ground synthesis.
  if (unansweredQuestions.length > 0) {
    recs.push({
      id: "answer-questions",
      priority: 80,
      action: `Answer ${unansweredQuestions.length} key question${unansweredQuestions.length > 1 ? "s" : ""}`,
      rationale: "Key questions anchor the investigation; answering them improves finding confidence.",
      cta: "View questions",
      panel: "questions",
    });
  }

  // 4. Open findings that haven't been triaged.
  if (openFindings.length > 0) {
    recs.push({
      id: "triage-findings",
      priority: 70,
      action: `Triage ${openFindings.length} open finding${openFindings.length > 1 ? "s" : ""}`,
      rationale: "Unreviewed findings leave the case narrative incomplete and can hide the real attack path.",
      cta: "Open findings",
      panel: "findings",
    });
  }

  // 5. Open next steps from synthesis.
  if (openNextSteps.length > 0) {
    recs.push({
      id: "run-next-steps",
      priority: 60,
      action: `Run ${openNextSteps.length} recommended next step${openNextSteps.length > 1 ? "s" : ""}`,
      rationale: "Synthesis identified concrete follow-up actions that are still pending.",
      cta: "View playbook",
      panel: "playbook",
    });
  }

  // 6. Case has evidence but no synthesis yet.
  if (hasEvents && state.findings.length === 0 && state.iocs.length === 0) {
    recs.push({
      id: "run-synthesis",
      priority: 85,
      action: "Run synthesis",
      rationale: "Evidence has been imported but no AI synthesis has produced findings or IOCs yet.",
      cta: "Synthesize",
      route: `/cases/${state.caseId}/synthesize`,
      panel: "summary",
    });
  }

  // 7. Stale synthesis (no update in 24 h with new events).
  const lastEventAt = lastEventTimestamp(state);
  const stateUpdatedAt = Date.parse(state.updatedAt) || 0;
  if (lastEventAt > stateUpdatedAt + 60_000) {
    recs.push({
      id: "re-synthesize",
      priority: 65,
      action: "Re-run synthesis",
      rationale: "New evidence arrived after the last synthesis run; refresh findings and IOCs.",
      cta: "Synthesize",
      route: `/cases/${state.caseId}/synthesize`,
      panel: "summary",
    });
  }

  // 8. Export-ready cases.
  if (state.findings.length > 0 && unenrichedIocs.length === 0 && openFindings.length === 0 && unansweredQuestions.length === 0) {
    recs.push({
      id: "generate-report",
      priority: 40,
      action: "Generate report",
      rationale: "The case appears well-triaged — generate a report for stakeholders or handoff.",
      cta: "Create report",
      route: `/cases/${state.caseId}/report`,
      panel: "report",
    });
  }

  return recs.sort((a, b) => b.priority - a.priority);
}

function isConfirmedOrDismissed(finding: Finding): boolean {
  return finding.status === "confirmed" || finding.status === "dismissed";
}

function lastEventTimestamp(state: InvestigationState): number {
  let latest = 0;
  for (const e of state.forensicTimeline) {
    const t = Date.parse(e.timestamp);
    if (t > latest) latest = t;
  }
  for (const e of state.timeline) {
    const t = Date.parse(e.timestamp);
    if (t > latest) latest = t;
  }
  return latest;
}
