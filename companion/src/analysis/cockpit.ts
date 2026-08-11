import type { FindingWorkflow } from "./findingWorkflow.js";
import type { Hypothesis } from "./hypothesis.js";
import type { ImportMeta } from "./importMeta.js";
import type { Job } from "./jobRegistry.js";
import type { InvestigationState, Finding, Severity, CollectDirective } from "./stateTypes.js";
import type { SynthMeta } from "./synthMeta.js";

export type CockpitPhase = "triage" | "active-investigation" | "report-preparation";
export type CockpitCardKind =
  "lead" | "hypothesis" | "contradiction" | "gap" | "change" | "activity" | "blocker";
export type CockpitAction = "pin" | "unpin" | "dismiss" | "restore" | "defer" | "assign" | "review";

export interface CockpitActionInput {
  action: CockpitAction;
  actor?: string;
  value?: string;
}

export interface CockpitCardDecision {
  cardId: string;
  pinned?: boolean;
  dismissedAt?: string;
  deferredUntil?: string;
  assignee?: string;
  updatedAt: string;
  updatedBy: string;
}

export interface CockpitReview {
  investigatorKey: string;
  investigator: string;
  reviewedAt: string;
}

export interface CockpitActionHistory {
  action: CockpitAction;
  cardId?: string;
  actor: string;
  at: string;
  value?: string;
}

export interface CockpitDecisionState {
  cards: CockpitCardDecision[];
  reviews: CockpitReview[];
  history: CockpitActionHistory[];
}

export interface CockpitTarget {
  panel: string;
  findingId?: string;
  hypothesisId?: string;
  questionId?: string;
  eventId?: string;
  jobId?: string;
}

export interface CockpitCard {
  id: string;
  kind: CockpitCardKind;
  title: string;
  summary: string;
  severity?: Severity;
  confidence?: number;
  occurredAt?: string;
  evidenceIds: string[];
  target: CockpitTarget;
  action?: string;
  pinned?: boolean;
  dismissedAt?: string;
  deferredUntil?: string;
  assignee?: string;
}

export interface CockpitSections {
  leads: CockpitCard[];
  hypotheses: CockpitCard[];
  contradictions: CockpitCard[];
  gaps: CockpitCard[];
  changes: CockpitCard[];
  activity: CockpitCard[];
  blockers: CockpitCard[];
}

export interface CockpitSnapshot {
  caseId: string;
  investigator: string;
  phase: CockpitPhase;
  generatedAt: string;
  lastReviewedAt: string | null;
  newSinceReview: number;
  sections: CockpitSections;
  parked: CockpitCard[];
  readiness: {
    ready: boolean;
    blockers: CockpitCard[];
  };
}

export interface CockpitInput {
  state: InvestigationState;
  hypotheses?: readonly Hypothesis[];
  workflows?: readonly FindingWorkflow[];
  pinnedFindingIds?: readonly string[];
  jobs?: readonly Job[];
  importMeta?: ImportMeta;
  synthMeta?: SynthMeta;
  decisions?: CockpitDecisionState;
  investigator?: string;
  now?: string;
}

interface ScoredCard {
  card: CockpitCard;
  score: number;
}

const EMPTY_DECISIONS: CockpitDecisionState = { cards: [], reviews: [], history: [] };
const SEVERITY_SCORE: Record<Severity, number> = {
  Critical: 500,
  High: 400,
  Medium: 300,
  Low: 200,
  Info: 100,
};
const SEVERITIES = new Set<string>(Object.keys(SEVERITY_SCORE));

function cleanIdentity(value: unknown): string {
  return (
    String(value ?? "")
      .trim()
      .slice(0, 120) || "analyst"
  );
}

function identityKey(value: unknown): string {
  return cleanIdentity(value).toLowerCase();
}

function normalizeSeverity(value: unknown): Severity {
  const severity = String(value ?? "");
  return SEVERITIES.has(severity) ? (severity as Severity) : "Info";
}

function isAfter(value: string | undefined, threshold: string | null): boolean {
  if (!value) return false;
  const time = Date.parse(value);
  const floor = threshold ? Date.parse(threshold) : 0;
  return Number.isFinite(time) && time > (Number.isFinite(floor) ? floor : 0);
}

function evidenceForFinding(state: InvestigationState, finding: Finding): string[] {
  const direct = finding.relatedEventIds ?? [];
  const reverse = state.forensicTimeline
    .filter((event) => event.relatedFindingIds.includes(finding.id))
    .map((event) => event.id);
  return [...new Set([...direct, ...reverse])];
}

function leadCards(input: CockpitInput): ScoredCard[] {
  const workflowByFinding = new Map((input.workflows ?? []).map((item) => [item.findingId, item]));
  const pinned = new Set(input.pinnedFindingIds ?? []);
  const findings: ScoredCard[] = input.state.findings
    .filter((finding) => finding.status !== "dismissed" && finding.relevance !== "unrelated-but-real")
    .map((finding) => {
      const evidenceIds = evidenceForFinding(input.state, finding);
      const workflow = workflowByFinding.get(finding.id);
      return {
        score:
          SEVERITY_SCORE[finding.severity] +
          (finding.confidence ?? 0) +
          (finding.status === "confirmed" ? 20 : 0) +
          (finding.ungrounded ? -80 : 0) +
          (finding.relevance === "disconnected" ? -50 : 0),
        card: {
          id: `lead:finding:${finding.id}`,
          kind: "lead",
          title: finding.title,
          summary: finding.description,
          severity: finding.severity,
          ...(finding.confidence !== undefined ? { confidence: finding.confidence } : {}),
          occurredAt: finding.lastUpdated,
          evidenceIds,
          target: {
            panel: "findings",
            findingId: finding.id,
            ...(evidenceIds[0] ? { eventId: evidenceIds[0] } : {}),
          },
          ...(pinned.has(finding.id) ? { pinned: true } : {}),
          ...(workflow?.assignee ? { assignee: workflow.assignee } : {}),
        },
      };
    });
  const hypotheses: ScoredCard[] = (input.hypotheses ?? [])
    .filter((item) => item.status === "open" || item.status === "unknown")
    .map((item) => ({
      score: 275 + item.relatedEventIds.length * 5 - (item.exhausted ? 100 : 0),
      card: {
        id: `lead:hypothesis:${item.id}`,
        kind: "lead",
        title: item.title,
        summary:
          item.expectedOutcome || item.description || "Test this open hypothesis against the evidence.",
        severity: "Medium",
        occurredAt: item.updatedAt,
        evidenceIds: [...item.relatedEventIds],
        target: {
          panel: "hypotheses",
          hypothesisId: item.id,
          ...(item.relatedEventIds[0] ? { eventId: item.relatedEventIds[0] } : {}),
        },
        ...(item.assignee ? { assignee: item.assignee } : {}),
      },
    }));
  return [...findings, ...hypotheses].sort((a, b) => b.score - a.score || a.card.id.localeCompare(b.card.id));
}

function hypothesisCards(hypotheses: readonly Hypothesis[]): CockpitCard[] {
  return hypotheses
    .filter((item) => item.status === "open" || item.status === "unknown" || item.needsReview)
    .map((item) => {
      const history = item.statusHistory ?? [];
      const previous = history.length > 1 ? history[history.length - 2].status : "";
      const change =
        previous && previous !== item.status ? ` Status changed from ${previous} to ${item.status}.` : "";
      return {
        id: `hypothesis:${item.id}`,
        kind: "hypothesis",
        title: item.title,
        summary: `${item.expectedOutcome || item.description || "No expected outcome recorded."}${change}`,
        severity: item.needsReview ? "High" : "Medium",
        occurredAt: item.updatedAt,
        evidenceIds: [...item.relatedEventIds],
        target: {
          panel: "hypotheses",
          hypothesisId: item.id,
          ...(item.relatedEventIds[0] ? { eventId: item.relatedEventIds[0] } : {}),
        },
        ...(item.assignee ? { assignee: item.assignee } : {}),
      } satisfies CockpitCard;
    });
}

function contradictionCards(input: CockpitInput): CockpitCard[] {
  const questionCards = input.state.keyQuestions
    .filter((question) => question.contradicted?.eventIds.length)
    .map((question) => ({
      id: `contradiction:question:${question.id}`,
      kind: "contradiction" as const,
      title: question.question,
      summary: `The current answer conflicts with timeline evidence carrying ${question.contradicted!.techniques.join(", ")}.`,
      severity: "High" as const,
      evidenceIds: [...question.contradicted!.eventIds],
      target: {
        panel: "questions",
        questionId: question.id,
        eventId: question.contradicted!.eventIds[0],
      },
    }));
  const hypothesisContradictions = (input.hypotheses ?? [])
    .filter((item) => item.contradictingEventIds.length > 0)
    .map((item) => ({
      id: `contradiction:hypothesis:${item.id}`,
      kind: "contradiction" as const,
      title: `Evidence weakens: ${item.title}`,
      summary: `${item.contradictingEventIds.length} event${item.contradictingEventIds.length === 1 ? "" : "s"} conflict with this explanation.`,
      severity: "High" as const,
      evidenceIds: [...item.contradictingEventIds],
      target: {
        panel: "hypotheses",
        hypothesisId: item.id,
        eventId: item.contradictingEventIds[0],
      },
    }));
  const uncertainties = input.state.uncertainties
    .filter((item) => item.status !== "confirmed")
    .map((item, index) => ({
      id: `contradiction:uncertainty:${index}`,
      kind: "contradiction" as const,
      title: `${item.topic} remains ${item.status}`,
      summary: item.basis || item.gap || "The case does not yet support a firm conclusion.",
      severity:
        item.status === "speculated" || item.status === "unknown" ? ("High" as const) : ("Medium" as const),
      evidenceIds: [],
      target: { panel: "uncertainties" },
    }));
  return [...questionCards, ...hypothesisContradictions, ...uncertainties];
}

function collectionAction(collect: CollectDirective | undefined, fallback: string): string {
  if (!collect) return fallback;
  const what = collect.artifact || collect.logSource || "the missing evidence";
  const where = collect.host ? ` from ${collect.host}` : "";
  const outcome = collect.expectedOutcome ? ` — ${collect.expectedOutcome}` : "";
  return `Collect ${what}${where}${outcome}`;
}

function gapCards(state: InvestigationState): CockpitCard[] {
  const hasEvidence = state.forensicTimeline.length > 0 || state.timeline.length > 0;
  if (!hasEvidence && state.findings.length === 0 && state.iocs.length === 0) {
    return [
      {
        id: "gap:import-evidence",
        kind: "gap",
        title: "Import the first evidence",
        summary: "This case has no events, findings, or IOCs yet.",
        severity: "High",
        evidenceIds: [],
        target: { panel: "import" },
        action: "Import evidence",
      },
    ];
  }
  const questions = state.keyQuestions
    .filter((question) => question.status !== "answered")
    .map((question) => ({
      id: `gap:question:${question.id}`,
      kind: "gap" as const,
      title: question.question,
      summary: question.answer || "This key question is not answered by the current evidence.",
      severity: question.status === "unknown" ? ("High" as const) : ("Medium" as const),
      evidenceIds: question.contradicted?.eventIds ? [...question.contradicted.eventIds] : [],
      target: { panel: "questions", questionId: question.id },
      action: collectionAction(
        question.collect,
        question.pointer || "Review the key question and collect the missing source.",
      ),
    }));
  const uncertainties = state.uncertainties
    .filter((item) => item.status !== "confirmed" && item.gap)
    .map((item, index) => ({
      id: `gap:uncertainty:${index}`,
      kind: "gap" as const,
      title: `Resolve ${item.topic}`,
      summary: item.basis || "The current assessment is not confirmed.",
      severity: "Medium" as const,
      evidenceIds: [],
      target: { panel: "uncertainties" },
      action: item.gap,
    }));
  const nextSteps = state.nextSteps
    .filter((step) => step.collect)
    .map((step) => ({
      id: `gap:next-step:${step.id}`,
      kind: "gap" as const,
      title: step.action,
      summary: step.rationale,
      severity:
        step.priority === "critical"
          ? ("Critical" as const)
          : step.priority === "high"
            ? ("High" as const)
            : ("Medium" as const),
      evidenceIds: [],
      target: { panel: "playbook" },
      action: collectionAction(step.collect, step.pointer),
    }));
  return [...questions, ...uncertainties, ...nextSteps];
}

function changeCards(input: CockpitInput, lastReviewedAt: string | null): CockpitCard[] {
  const cards: CockpitCard[] = [];
  for (const finding of input.state.findings) {
    if (!isAfter(finding.lastUpdated, lastReviewedAt)) continue;
    const evidenceIds = evidenceForFinding(input.state, finding);
    cards.push({
      id: `change:finding:${finding.id}`,
      kind: "change",
      title: `Finding updated: ${finding.title}`,
      summary: finding.description,
      severity: finding.severity,
      confidence: finding.confidence,
      occurredAt: finding.lastUpdated,
      evidenceIds,
      target: {
        panel: "findings",
        findingId: finding.id,
        ...(evidenceIds[0] ? { eventId: evidenceIds[0] } : {}),
      },
    });
  }
  if (input.importMeta && isAfter(input.importMeta.lastImportedAt, lastReviewedAt)) {
    const meta = input.importMeta;
    const forensicCount = meta.addedCount;
    const hasSuperTimelineCount = meta.superTimelineAddedCount !== undefined;
    const superTimelineCount = meta.superTimelineAddedCount ?? 0;
    const importCountTitle = hasSuperTimelineCount
      ? `${forensicCount} forensic event${forensicCount === 1 ? "" : "s"} · ${superTimelineCount} super-timeline event${superTimelineCount === 1 ? "" : "s"}`
      : `${forensicCount} forensic event${forensicCount === 1 ? "" : "s"} · super-timeline count unavailable`;
    cards.push({
      id: `change:import:${meta.lastImportedAt}`,
      kind: "change",
      title: `Import added ${importCountTitle}`,
      summary: `${meta.lastImportKind || "Evidence"} · ${meta.lastImportFile || "latest import"}`,
      severity: forensicCount > 0 || superTimelineCount > 0 ? "Medium" : "Low",
      occurredAt: meta.lastImportedAt,
      evidenceIds: [],
      target: {
        panel: forensicCount > 0 ? "timeline" : superTimelineCount > 0 ? "super-timeline" : "timeline",
      },
    });
  }
  if (input.synthMeta && isAfter(input.synthMeta.lastSynthesizedAt, lastReviewedAt)) {
    for (const changed of input.synthMeta.lastDiff?.severityChanged ?? []) {
      cards.push({
        id: `change:severity:${changed.title}`,
        kind: "change",
        title: `Severity changed: ${changed.title}`,
        summary: `${changed.from} → ${changed.to}`,
        severity: normalizeSeverity(changed.to),
        occurredAt: input.synthMeta.lastSynthesizedAt,
        evidenceIds: [],
        target: { panel: "findings" },
      });
    }
  }
  return cards
    .sort((a, b) => String(b.occurredAt).localeCompare(String(a.occurredAt)) || a.id.localeCompare(b.id))
    .slice(0, 8);
}

function activityCards(jobs: readonly Job[]): CockpitCard[] {
  return jobs
    .filter(
      (job) =>
        job.status === "running" ||
        job.status === "queued" ||
        job.status === "failed" ||
        job.status === "interrupted",
    )
    .map((job) => {
      const needsAttention = job.status === "failed" || job.status === "interrupted";
      return {
        id: `activity:job:${job.id}`,
        kind: "activity" as const,
        title: needsAttention ? `${job.kind} ${job.status}` : `${job.kind} is ${job.status}`,
        // Running-job detail is high-frequency progress. Keep the decision cockpit stable and
        // leave those live numbers to Background Jobs; failures still surface their explanation.
        summary: needsAttention
          ? job.error || job.detail || job.label || "Background work needs attention."
          : job.label || "Background work is in progress.",
        severity: needsAttention ? ("High" as const) : ("Medium" as const),
        occurredAt: job.endedAt || job.startedAt,
        evidenceIds: [],
        target: { panel: "jobs", jobId: job.id },
      };
    })
    .sort((a, b) => String(b.occurredAt).localeCompare(String(a.occurredAt)))
    .slice(0, 6);
}

function blockerCards(state: InvestigationState, jobs: readonly Job[]): CockpitCard[] {
  const cards: CockpitCard[] = [];
  const hasEvidence = state.forensicTimeline.length > 0 || state.timeline.length > 0;
  if (!hasEvidence) {
    cards.push({
      id: "blocker:no-evidence",
      kind: "blocker",
      title: "No evidence has been imported",
      summary: "A report cannot be grounded until the case contains evidence.",
      severity: "Critical",
      evidenceIds: [],
      target: { panel: "import" },
      action: "Import evidence",
    });
  }
  if (state.findings.length === 0) {
    cards.push({
      id: "blocker:no-findings",
      kind: "blocker",
      title: "No findings have been established",
      summary: hasEvidence
        ? "Synthesize or manually assess the imported evidence."
        : "Import and assess evidence first.",
      severity: "High",
      evidenceIds: [],
      target: { panel: hasEvidence ? "findings" : "import" },
    });
  }
  const untriaged = state.findings.filter((finding) => finding.status === "open");
  if (untriaged.length > 0) {
    const highImpact = untriaged.filter(
      (finding) => finding.severity === "Critical" || finding.severity === "High",
    );
    cards.push({
      id: "blocker:untriaged-high",
      kind: "blocker",
      title:
        highImpact.length > 0
          ? `${highImpact.length} high-impact finding${highImpact.length === 1 ? "" : "s"} still open`
          : `${untriaged.length} finding${untriaged.length === 1 ? "" : "s"} still open`,
      summary: "Confirm or dismiss open findings before treating the report as ready.",
      severity: highImpact.length > 0 ? "High" : "Medium",
      evidenceIds: untriaged.flatMap((finding) => finding.relatedEventIds ?? []).slice(0, 20),
      target: { panel: "findings", findingId: untriaged[0].id },
    });
  }
  const unanswered = state.keyQuestions.filter(
    (question) => question.status !== "answered" || question.contradicted,
  );
  if (unanswered.length > 0) {
    cards.push({
      id: "blocker:questions",
      kind: "blocker",
      title: `${unanswered.length} key question${unanswered.length === 1 ? "" : "s"} unresolved`,
      summary: "Resolve partial, unknown, or contradicted answers before finalizing conclusions.",
      severity: "High",
      evidenceIds: unanswered.flatMap((question) => question.contradicted?.eventIds ?? []).slice(0, 20),
      target: { panel: "questions", questionId: unanswered[0].id },
    });
  }
  if (!state.lastSummary.trim()) {
    cards.push({
      id: "blocker:no-summary",
      kind: "blocker",
      title: "Investigation summary is missing",
      summary: "Record the current conclusion before report generation.",
      severity: "Medium",
      evidenceIds: [],
      target: { panel: "summary" },
    });
  }
  if (!state.attackerPath.trim()) {
    cards.push({
      id: "blocker:no-attack-path",
      kind: "blocker",
      title: "Attack path is missing",
      summary: "Document the evidenced sequence of attacker activity.",
      severity: "Medium",
      evidenceIds: [],
      target: { panel: "attack-path" },
    });
  }
  const running = jobs.filter((job) => job.status === "running" || job.status === "queued");
  if (running.length > 0) {
    cards.push({
      id: "blocker:running-jobs",
      kind: "blocker",
      title: `${running.length} analysis or import job${running.length === 1 ? "" : "s"} still running`,
      summary: "Wait for in-flight work before freezing report conclusions.",
      severity: "Medium",
      evidenceIds: [],
      target: { panel: "jobs", jobId: running[0].id },
    });
  }
  return cards;
}

function applyDecision(card: CockpitCard, decisions: CockpitDecisionState, input: CockpitInput): CockpitCard {
  const decision = decisions.cards.find((item) => item.cardId === card.id);
  if (!decision) return card;
  const findingOwnsPin = Boolean(card.target.findingId && input.pinnedFindingIds !== undefined);
  const ownerIsAuthoritative = Boolean(
    (card.target.findingId && input.workflows !== undefined) ||
    (card.target.hypothesisId && input.hypotheses !== undefined),
  );
  return {
    ...card,
    ...(!findingOwnsPin && decision.pinned !== undefined ? { pinned: decision.pinned } : {}),
    ...(decision.dismissedAt ? { dismissedAt: decision.dismissedAt } : {}),
    ...(decision.deferredUntil ? { deferredUntil: decision.deferredUntil } : {}),
    ...(!ownerIsAuthoritative && decision.assignee ? { assignee: decision.assignee } : {}),
  };
}

function isParked(card: CockpitCard, now: string): boolean {
  if (card.dismissedAt) return true;
  return Boolean(card.deferredUntil && Date.parse(card.deferredUntil) > Date.parse(now));
}

function prioritize(cards: readonly CockpitCard[]): CockpitCard[] {
  return [...cards].sort(
    (a, b) =>
      Number(Boolean(b.pinned)) - Number(Boolean(a.pinned)) ||
      SEVERITY_SCORE[b.severity ?? "Info"] - SEVERITY_SCORE[a.severity ?? "Info"] ||
      a.id.localeCompare(b.id),
  );
}

export function deriveCockpit(input: CockpitInput): CockpitSnapshot {
  const now = input.now ?? new Date().toISOString();
  const investigator = cleanIdentity(input.investigator);
  const decisions = input.decisions ?? EMPTY_DECISIONS;
  const review = decisions.reviews.find((item) => item.investigatorKey === identityKey(investigator));
  const lastReviewedAt = review?.reviewedAt ?? null;
  const blockers = blockerCards(input.state, input.jobs ?? []);
  const leads = leadCards(input).map((item) => item.card);
  const raw: CockpitSections = {
    leads,
    hypotheses: hypothesisCards(input.hypotheses ?? []),
    contradictions: contradictionCards(input),
    gaps: gapCards(input.state),
    changes: changeCards(input, lastReviewedAt),
    activity: activityCards(input.jobs ?? []),
    blockers,
  };
  const parked: CockpitCard[] = [];
  const sectionEntries = Object.entries(raw) as [keyof CockpitSections, CockpitCard[]][];
  const sections = Object.fromEntries(
    sectionEntries.map(([key, cards]) => {
      const decorated = cards.map((card) => applyDecision(card, decisions, input));
      parked.push(...decorated.filter((card) => isParked(card, now)));
      const active = prioritize(decorated.filter((card) => !isParked(card, now)));
      return [key, key === "leads" ? active.slice(0, 3) : active];
    }),
  ) as unknown as CockpitSections;
  const hasEvidence = input.state.forensicTimeline.length > 0 || input.state.timeline.length > 0;
  const readinessReady = blockers.length === 0;
  const phase: CockpitPhase =
    !hasEvidence || input.state.findings.length === 0
      ? "triage"
      : readinessReady
        ? "report-preparation"
        : "active-investigation";
  return {
    caseId: input.state.caseId,
    investigator,
    phase,
    generatedAt: now,
    lastReviewedAt,
    newSinceReview: sections.changes.length,
    sections,
    parked: prioritize(parked),
    readiness: { ready: readinessReady, blockers: sections.blockers },
  };
}
