import type { InvestigationState, NextStep } from "../../../stateTypes.js";
import { WatsonProposalConflict } from "../proposalErrors.js";
import type { WatsonNextStepUpdateProposal } from "../types.js";
import type { WatsonWriter, WriterDeps } from "./writerTypes.js";

// A change Watson proposed to a next step already in the case (user decision of 2026-11-16): mark it
// done (it leaves the list) or change its priority. Apply refuses when the step changed since Watson
// proposed it; undo refuses when someone changed it after the apply, so neither ever overwrites an
// analyst's edit or a synthesis rewrite. The step's own fields are compared, never the stale badge.

const OUT_OF_DATE = "Watson changed a next step";

/** The fields a step change compares. */
function sameStep(a: NextStep, b: NextStep): boolean {
  return (
    a.priority === b.priority &&
    a.action === b.action &&
    a.rationale === b.rationale &&
    a.pointer === b.pointer
  );
}

/** The change in words, for the activity log, the Auto listing and the card. */
export function stepChange(p: WatsonNextStepUpdateProposal): string {
  if (!p.after) return `next step done: ${p.before.action}`;
  return `next step priority ${p.before.priority} -> ${p.after.priority}: ${p.before.action}`;
}

async function apply(deps: WriterDeps, caseId: string, p: WatsonNextStepUpdateProposal) {
  const overview = await deps.stateStore.loadOverview(caseId);
  const stored = overview.nextSteps.find((s) => s.id === p.targetId);
  if (!stored || !sameStep(stored, p.before)) {
    throw new WatsonProposalConflict(
      `Next step ${p.targetId} changed or left the case after Watson proposed this. Watson changed nothing`,
    );
  }
  const priority = p.after?.priority;
  const nextSteps = priority
    ? overview.nextSteps.map((s) => (s.id === p.targetId ? { ...s, priority } : s))
    : overview.nextSteps.filter((s) => s.id !== p.targetId);
  const state: InvestigationState = { ...overview, nextSteps };
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return { state };
}

async function undo(deps: WriterDeps, caseId: string, p: WatsonNextStepUpdateProposal) {
  const overview = await deps.stateStore.loadOverview(caseId);
  const stored = overview.nextSteps.find((s) => s.id === p.targetId);
  let nextSteps: NextStep[];
  if (!p.after) {
    // Done: put the step back where it was, unless a step with its id is in the case again.
    if (stored) {
      throw new WatsonProposalConflict(
        `Next step ${p.targetId} is in the case again. Watson changed nothing`,
      );
    }
    const at = Math.min(p.index, overview.nextSteps.length);
    nextSteps = [...overview.nextSteps.slice(0, at), p.before, ...overview.nextSteps.slice(at)];
  } else {
    if (!stored || !sameStep(stored, { ...p.before, priority: p.after.priority })) {
      throw new WatsonProposalConflict(
        `Someone changed or removed next step ${p.targetId} after Watson changed it. Watson changed nothing`,
      );
    }
    nextSteps = overview.nextSteps.map((s) =>
      s.id === p.targetId ? { ...s, priority: p.before.priority } : s,
    );
  }
  const state: InvestigationState = { ...overview, nextSteps };
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return { state };
}

export const nextStepUpdateWriter: WatsonWriter<WatsonNextStepUpdateProposal> = { apply, undo };
