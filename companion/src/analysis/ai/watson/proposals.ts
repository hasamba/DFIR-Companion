import type { InvestigationState } from "../../stateTypes.js";
import {
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
  type WatsonProposalAction,
} from "./proposalErrors.js";
import { proposalTargetId, type WatsonChat, type WatsonProposal, type WatsonProposalKind } from "./types.js";
import { eventPromoteWriter } from "./writers/eventPromoteWriter.js";
import { findingWriter } from "./writers/findingWriter.js";
import { nextStepWriter } from "./writers/nextStepWriter.js";
import { questionWriter } from "./writers/questionWriter.js";
import { reportTextWriter } from "./writers/reportTextWriter.js";
import type { WatsonTargetType, WatsonWriter, WriterDeps, WriterResult } from "./writers/writerTypes.js";

export {
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
  type WatsonProposalAction,
  type WatsonProposalDeps,
} from "./proposalErrors.js";
export { nextQuestions } from "./writers/questionWriter.js";
export type { WatsonReportText, WriterDeps } from "./writers/writerTypes.js";

// The analyst's decision on one Watson proposal: apply it, reject it, or undo an applied one. The
// proposal status and the case write change together: the status check runs inside
// chatStore.update() (so two clicks cannot both apply), the case write in the kind's writer under
// the state lock (so it cannot race a synthesis save). Nesting order is always chat first, then
// state lock. A self-locking writer takes the lock itself.

const FROM: Record<WatsonProposalAction, WatsonProposal["status"]> = {
  apply: "pending",
  reject: "pending",
  undo: "applied",
};
const TO: Record<WatsonProposalAction, WatsonProposal["status"]> = {
  apply: "applied",
  reject: "rejected",
  undo: "undone",
};

// One writer per kind. A kind with no writer yet is refused, never silently marked applied.
const WRITERS: Partial<Record<WatsonProposalKind, WatsonWriter<WatsonProposal>>> = {
  question_update: questionWriter,
  question_new: questionWriter,
  finding_new: findingWriter,
  finding_update: findingWriter,
  next_step_new: nextStepWriter,
  report_text: reportTextWriter,
  event_promote: eventPromoteWriter,
};

// The pasted file stays the evidence, so held rows an analyst undid may be applied again.
const REAPPLIABLE: ReadonlySet<WatsonProposalKind> = new Set<WatsonProposalKind>(["event_promote"]);
const allowed = (p: WatsonProposal, action: WatsonProposalAction): boolean =>
  p.status === FROM[action] || (action === "apply" && p.status === "undone" && REAPPLIABLE.has(p.kind));

const TARGET_TYPE: Record<WatsonProposalKind, WatsonTargetType> = {
  question_update: "question",
  question_new: "question",
  finding_new: "finding",
  finding_update: "finding",
  next_step_new: "next_step",
  report_text: "report",
  event_promote: "event",
};

function describe(p: WatsonProposal): string {
  switch (p.kind) {
    case "question_new":
      return `new key question: ${p.after.question}`;
    case "question_update":
      return `key question answer: ${p.after.question}`;
    case "finding_new":
      return `new finding: ${p.after.title}`;
    case "finding_update":
      return `finding update: ${p.after.title}`;
    case "next_step_new":
      return `next step: ${p.after.action}`;
    case "report_text":
      return `report text (${p.field})`;
    case "event_promote":
      return `promotion of ${p.events.length} pasted row(s)`;
  }
}

function detailFor(action: WatsonProposalAction, p: WatsonProposal): string {
  const verb = { apply: "Applied", reject: "Rejected", undo: "Undid" }[action];
  return `${verb} Watson's ${describe(p)}`.slice(0, 240);
}

async function runWriter(
  deps: WriterDeps,
  caseId: string,
  p: WatsonProposal,
  action: "apply" | "undo",
  actor?: string,
): Promise<WriterResult<WatsonProposal>> {
  const writer = WRITERS[p.kind];
  if (!writer) throw new WatsonProposalConflict(`Watson cannot ${action} a ${p.kind} proposal yet`);
  const run = () =>
    action === "apply" ? writer.apply(deps, caseId, p, actor) : writer.undo(deps, caseId, p);
  return writer.selfLocking ? run() : deps.stateLock.runExclusive(caseId, run);
}

function decided(
  p: WatsonProposal,
  action: WatsonProposalAction,
  recorded: WatsonProposal | undefined,
  actor: string | undefined,
): WatsonProposal {
  const base = { ...(recorded ?? p), status: TO[action] };
  if (action !== "apply") return base;
  return { ...base, appliedAt: new Date().toISOString(), ...(actor ? { appliedBy: actor } : {}) };
}

export async function applyWatsonProposal(
  deps: WriterDeps,
  caseId: string,
  proposalId: string,
  action: WatsonProposalAction,
  actor?: string,
): Promise<{ chat: WatsonChat; state?: InvestigationState }> {
  let state: InvestigationState | undefined;
  let done: WatsonProposal | undefined;
  const chat = await deps.chatStore.update(caseId, async (c) => {
    const p = c.proposals.find((x) => x.id === proposalId);
    if (!p) throw new WatsonProposalNotFoundError(proposalId);
    if (!allowed(p, action)) throw new WatsonProposalStateError(action, p.status);
    const result = action === "reject" ? {} : await runWriter(deps, caseId, p, action, actor);
    state = result.state;
    const next = decided(p, action, result.proposal, actor);
    done = next;
    return { ...c, proposals: c.proposals.map((x) => (x.id === proposalId ? next : x)) };
  });
  if (done) {
    await deps.activity.add(caseId, {
      ...(actor ? { actor } : {}),
      category: "ai",
      action: `watson.${action}`,
      detail: detailFor(action, done),
      targetType: TARGET_TYPE[done.kind],
      targetId: proposalTargetId(done),
    });
  }
  return state ? { chat, state } : { chat };
}
