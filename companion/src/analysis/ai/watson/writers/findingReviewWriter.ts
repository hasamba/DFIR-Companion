import type { Finding, InvestigationState } from "../../../stateTypes.js";
import { isWatsonItem } from "../../../timeline/watsonItems.js";
import { findingVerdictKey, reviewFinding, withoutReview } from "../../../timeline/watsonVerdicts.js";
import type { WatsonFindingVerdict } from "../../../watsonItemTypes.js";
import { isDemotion } from "../findingReviewSchema.js";
import { WatsonProposalConflict } from "../proposalErrors.js";
import type { WatsonFindingReviewProposal } from "../types.js";
import { WATSON_AUTO_ACTOR, type WatsonWriter, type WriterDeps } from "./writerTypes.js";

// #2682: Watson's demotion or dismissal of a finding synthesis wrote. Apply re-reads the finding and
// refuses when it is gone, is Watson's (the analyst's), already carries a verdict, or changed since
// Watson read it. It stores the verdict in the case (so later synthesis runs apply it again) and
// marks the finding. Undo removes the verdict and puts back what the mark changed, wherever the
// finding is now (a re-synthesis gives it a new id; the mark carries the proposal id).

const OUT_OF_DATE = "Watson changed a synthesis finding";
const asWritten = (id: string): string => id;

/** The change in words, for the activity log, the Auto listing and the card. */
export function reviewChange(p: WatsonFindingReviewProposal): string {
  const verb =
    p.action === "dismiss"
      ? "dismiss finding"
      : `demote finding ${p.before.severity} -> ${p.severity ?? "?"}`;
  return `${verb}: ${p.before.title}`;
}

const same = (a: Finding, b: Finding): boolean =>
  a.severity === b.severity && a.status === b.status && a.title === b.title;

function checkTarget(stored: Finding | undefined, p: WatsonFindingReviewProposal): Finding {
  if (!stored || !same(stored, p.before)) {
    throw new WatsonProposalConflict(
      `Finding ${p.targetId} changed or left the case after Watson proposed this. Watson changed nothing`,
    );
  }
  if (isWatsonItem(stored)) {
    throw new WatsonProposalConflict(`Watson never changes a finding that you wrote. Watson changed nothing`);
  }
  if (stored.watsonReview || stored.status === "dismissed") {
    throw new WatsonProposalConflict(
      `Finding ${p.targetId} is already dismissed or reviewed. Watson changed nothing`,
    );
  }
  if (p.action === "demote" && !isDemotion(stored.severity, p.severity)) {
    throw new WatsonProposalConflict(`Watson only lowers a finding's severity. Watson changed nothing`);
  }
  return stored;
}

function verdictFor(stored: Finding, p: WatsonFindingReviewProposal, actor?: string): WatsonFindingVerdict {
  return {
    key: findingVerdictKey(stored),
    action: p.action,
    ...(p.action === "demote" && p.severity ? { severity: p.severity } : {}),
    reason: p.why,
    eventIds: [...p.eventIds],
    consideredEventIds: [...new Set([...(stored.relatedEventIds ?? []), ...p.eventIds])],
    proposalId: p.id,
    approvedBy: actor || "an analyst",
    at: new Date().toISOString(),
    title: stored.title,
    ...(actor === WATSON_AUTO_ACTOR ? { auto: true as const } : {}),
  };
}

async function apply(deps: WriterDeps, caseId: string, p: WatsonFindingReviewProposal, actor?: string) {
  const overview = await deps.stateStore.loadOverview(caseId);
  const stored = checkTarget(
    overview.findings.find((f) => f.id === p.targetId),
    p,
  );
  const verdict = verdictFor(stored, p, actor);
  const others = (overview.watsonFindingVerdicts ?? []).filter((v) => v.key !== verdict.key);
  // Only the target changes now; the case's citations are its own, so ids compare as written.
  const state: InvestigationState = {
    ...overview,
    findings: overview.findings.map((f) => (f.id === stored.id ? reviewFinding(f, verdict, asWritten) : f)),
    watsonFindingVerdicts: [...others, verdict],
  };
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return { state, proposal: { ...p, key: verdict.key } };
}

async function undo(deps: WriterDeps, caseId: string, p: WatsonFindingReviewProposal) {
  const overview = await deps.stateStore.loadOverview(caseId);
  const verdicts = overview.watsonFindingVerdicts ?? [];
  const marked = overview.findings.some((f) => f.watsonReview?.proposalId === p.id);
  if (!marked && !verdicts.some((v) => v.proposalId === p.id)) {
    throw new WatsonProposalConflict(
      `Watson's change to this finding is no longer in the case. Watson changed nothing`,
    );
  }
  const left = verdicts.filter((v) => v.proposalId !== p.id);
  const { watsonFindingVerdicts: _old, ...rest } = overview;
  const state: InvestigationState = {
    ...rest,
    findings: overview.findings.map((f) => (f.watsonReview?.proposalId === p.id ? withoutReview(f) : f)),
    ...(left.length ? { watsonFindingVerdicts: left } : {}),
  };
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return { state };
}

export const findingReviewWriter: WatsonWriter<WatsonFindingReviewProposal> = { apply, undo };
