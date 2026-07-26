import type { InvestigationState, Finding } from "./stateTypes.js";
import type { PlaybookTask } from "./playbook.js";

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

/**
 * The signals the coach needs that DON'T live in InvestigationState. Both are supplied by the route
 * from the subsystem that owns them, so a recommendation can never disagree with what the app would
 * actually do if the analyst clicked its CTA.
 */
export interface CoachInputs {
  // How many IOCs an enrichment run would really query right now — from the enrichment engine's own
  // candidate filter (countEnrichableWork over the providers ENABLED for this case). It is NOT
  // "IOCs with no enrichments yet": IOC types no provider can ever look up (file/sid/other) and a
  // case with enrichment switched off would both make that count stick above zero forever, pinning
  // a dead "Run enrichment" card at the top of the list and blocking rule 8 permanently.
  // Omitted (a caller with no provider context) = say nothing about enrichment rather than guess.
  pendingEnrichmentIocs?: number;
  // The case's playbook tasks (state/playbook.json), which is where next-step PROGRESS lives — a
  // NextStep has no "done" field by design, so this is the only way to know what's actually left.
  // Omitted / empty = fall back to the raw next-step list (see openNextStepCount).
  playbookTasks?: readonly PlaybookTask[];
}

// Stable heuristics that score what the analyst should do next. No AI calls here — only
// deterministic reads of existing case state plus the two derived inputs above.
export function recommendNextActions(state: InvestigationState, inputs: CoachInputs = {}): CoachRecommendation[] {
  const recs: CoachRecommendation[] = [];

  const openFindings = state.findings.filter((f) => !isConfirmedOrDismissed(f));
  const pendingEnrichmentIocs = inputs.pendingEnrichmentIocs ?? 0;
  // `status`, not the answer text: a "partial" answer has text but is NOT settled, and the rest of
  // the app agrees on that spelling (playbook.ts, collectSatisfaction.ts, secondLook.ts all treat
  // anything other than "answered" as outstanding). Sniffing q.answer instead both undercounts the
  // card and lets rule 8 call a case well-triaged while a key question is still half-answered.
  const unansweredQuestions = state.keyQuestions.filter((q) => q.status !== "answered");
  const openNextSteps = openNextStepCount(state, inputs.playbookTasks);
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
  if (pendingEnrichmentIocs > 0) {
    recs.push({
      id: "enrich-iocs",
      priority: 90,
      action: `Enrich ${pendingEnrichmentIocs} IOC${pendingEnrichmentIocs > 1 ? "s" : ""}`,
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
  if (openNextSteps > 0) {
    recs.push({
      id: "run-next-steps",
      priority: 60,
      action: `Run ${openNextSteps} recommended next step${openNextSteps > 1 ? "s" : ""}`,
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
  if (state.findings.length > 0 && pendingEnrichmentIocs === 0 && openFindings.length === 0 && unansweredQuestions.length === 0) {
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

/**
 * How many of synthesis's next steps still need doing.
 *
 * Progress is tracked in the PLAYBOOK (state/playbook.json), not in InvestigationState: a NextStep
 * deliberately carries no "done" field, because playbook.ts keeps the per-task todo/in_progress/
 * done/skipped status in a side file so a re-synthesis can never wipe analyst progress. So count the
 * next-step-derived tasks that are still open. `staleReSynth` is NOT a stand-in for that — it badges
 * "stale, re-synthesis queued" after an FP cascade (see fpCascade.ts), so filtering on it produces a
 * count that never falls, no matter how much of the playbook the analyst has worked through.
 *
 * No next_step-sourced tasks at all means no playbook store is configured, or one that has never
 * been derived — there is no completion signal to honour in that deployment, so fall back to the raw
 * list. (derivePlaybookTasks folds a next step that cites a Critical/High finding INTO that finding's
 * task rather than emitting an overlapping one, so a folded step has no task of its own; those are
 * represented by the finding task, and by rule 4, instead of being counted twice here.)
 */
function openNextStepCount(state: InvestigationState, playbookTasks?: readonly PlaybookTask[]): number {
  const derived = (playbookTasks ?? []).filter((t) => t.source === "next_step");
  if (derived.length === 0) return state.nextSteps.length;
  return derived.filter((t) => t.status === "todo" || t.status === "in_progress").length;
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
