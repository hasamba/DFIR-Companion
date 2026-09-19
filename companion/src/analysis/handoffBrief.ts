// The shift-handoff brief (#1406): what the case holds, what is open, what to check next — built
// from state the case already carries, plus the outgoing analyst's own note.
//
// Everything here is DERIVED: counts by severity and status, the open findings with the workflow
// owner the analyst recorded, the key questions still unknown or partial, the open hypotheses and
// threads, the critical/high next steps, the IOCs no provider has checked, the last import. The
// note is a notebook entry of type `handoff` (notebookStore.ts): the per-case, synthesis-proof side
// file the notebook already is, so nothing new is stored and a re-synthesis never wipes it. A count
// is a count — the brief never says "contained", "clean" or "done"; the words are the analyst's.
//
// Inputs from side stores arrive as plain shapes (no store types imported): the brief sits in the
// workflow tier and must not reach up into the AI tier for the hypothesis type.

import type { Finding, InvestigationState, Severity } from "./stateTypes.js";
import { SEVERITY_RANK } from "./stateTypes.js";

/** Items listed per section; the rest are counted. */
export const HANDOFF_LIST_MAX = 10;
/** Handoff notes carried, newest first. */
export const HANDOFF_NOTES_MAX = 5;
const TEXT_MAX = 300;
const NOTE_MAX = 4000;

export interface HandoffExtras {
  notebook?: readonly { id: string; timestamp: string; text: string; type: string; author?: string }[];
  hypotheses?: readonly { title: string; status: string }[];
  workflow?: readonly { findingId: string; assignee: string; status: string | null }[];
  importMeta?: {
    lastImportedAt: string;
    lastImportKind: string;
    lastImportFile: string;
    lastImportSource: string;
  } | null;
}

export interface HandoffBrief {
  caseId: string;
  generatedAt: string;
  stateUpdatedAt: string;
  lastImport: { at: string; kind: string; source: string } | null;
  findings: {
    bySeverity: Record<Severity, number>;
    byStatus: Record<Finding["status"], number>;
    open: {
      id: string;
      title: string;
      severity: Severity;
      status: Finding["status"];
      workflowStatus: string | null;
      assignee: string;
    }[];
    openTotal: number;
    openNotShown: number;
    inProgress: number;
    unassigned: number;
  };
  questions: { question: string; status: string; pointer: string }[];
  questionsNotShown: number;
  hypotheses: { title: string }[];
  hypothesesNotShown: number;
  threads: { description: string; openedAt: string }[];
  threadsNotShown: number;
  nextSteps: { priority: string; action: string; pointer: string }[];
  nextStepsNotShown: number;
  iocs: { total: number; unenriched: number };
  handoffNotes: { author: string; timestamp: string; text: string }[];
  handoffNotesNotShown: number;
}

const clip = (s: string, max = TEXT_MAX): string => {
  const t = (s ?? "").replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
};
const take = <T>(items: readonly T[]): { shown: T[]; notShown: number } => ({
  shown: items.slice(0, HANDOFF_LIST_MAX),
  notShown: Math.max(0, items.length - HANDOFF_LIST_MAX),
});

export function buildHandoffBrief(state: InvestigationState, extras: HandoffExtras): HandoffBrief {
  const bySeverity: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const byStatus: Record<Finding["status"], number> = { open: 0, confirmed: 0, dismissed: 0 };
  for (const f of state.findings) {
    if (f.severity in bySeverity) bySeverity[f.severity] += 1;
    if (f.status in byStatus) byStatus[f.status] += 1;
  }
  const workflow = new Map((extras.workflow ?? []).map((w) => [w.findingId, w]));
  const openAll = state.findings
    .filter((f) => f.status !== "dismissed" && workflow.get(f.id)?.status !== "resolved")
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.id.localeCompare(b.id))
    .map((f) => {
      const w = workflow.get(f.id);
      return {
        id: f.id,
        title: clip(f.title),
        severity: f.severity,
        status: f.status,
        workflowStatus: w?.status ?? null,
        assignee: w?.assignee?.trim() ?? "",
      };
    });
  const open = take(openAll);
  const questions = take(
    state.keyQuestions
      .filter((q) => q.status === "unknown" || q.status === "partial")
      .map((q) => ({ question: clip(q.question), status: q.status, pointer: clip(q.pointer) })),
  );
  const hypotheses = take(
    (extras.hypotheses ?? []).filter((h) => h.status === "open").map((h) => ({ title: clip(h.title) })),
  );
  const threads = take(
    state.openThreads
      .filter((t) => t.status === "open")
      .map((t) => ({ description: clip(t.description), openedAt: t.openedAt })),
  );
  const nextSteps = take(
    state.nextSteps
      .filter((n) => n.priority === "critical" || n.priority === "high")
      .sort((a, b) => (a.priority === b.priority ? 0 : a.priority === "critical" ? -1 : 1))
      .map((n) => ({ priority: n.priority, action: clip(n.action), pointer: clip(n.pointer) })),
  );
  const notesAll = (extras.notebook ?? [])
    .filter((n) => n.type === "handoff")
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .map((n) => ({
      author: clip(n.author ?? "anonymous", 80),
      timestamp: n.timestamp,
      text: clip(n.text, NOTE_MAX),
    }));
  const im = extras.importMeta;
  return {
    caseId: state.caseId,
    generatedAt: new Date().toISOString(),
    stateUpdatedAt: state.updatedAt,
    lastImport:
      im && im.lastImportedAt
        ? { at: im.lastImportedAt, kind: im.lastImportKind, source: im.lastImportSource || im.lastImportFile }
        : null,
    findings: {
      bySeverity,
      byStatus,
      open: open.shown,
      openTotal: openAll.length,
      openNotShown: open.notShown,
      inProgress: openAll.filter((f) => f.workflowStatus === "in_progress").length,
      unassigned: openAll.filter((f) => !f.assignee).length,
    },
    questions: questions.shown,
    questionsNotShown: questions.notShown,
    hypotheses: hypotheses.shown,
    hypothesesNotShown: hypotheses.notShown,
    threads: threads.shown,
    threadsNotShown: threads.notShown,
    nextSteps: nextSteps.shown,
    nextStepsNotShown: nextSteps.notShown,
    iocs: { total: state.iocs.length, unenriched: state.iocs.filter((i) => !i.enrichedBy?.length).length },
    handoffNotes: notesAll.slice(0, HANDOFF_NOTES_MAX),
    handoffNotesNotShown: Math.max(0, notesAll.length - HANDOFF_NOTES_MAX),
  };
}
