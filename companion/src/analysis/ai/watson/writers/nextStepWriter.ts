import type { InvestigationState, NextStep } from "../../../stateTypes.js";
import { WatsonProposalConflict } from "../proposalErrors.js";
import type { WatsonNextStepProposal } from "../types.js";
import type { WatsonWriter, WriterDeps } from "./writerTypes.js";

// A next step Watson proposed, applied by the analyst: appended to the overview's next steps with the
// Watson mark (synthesis keeps it, keepWatsonItems). Undo removes it only while the fields Watson
// wrote are unchanged; the stale badge other paths set is not an analyst change.

const OUT_OF_DATE = "Watson wrote a next step";

/** The fields Watson authored: what undo compares. */
function sameStep(a: NextStep, b: NextStep): boolean {
  return (
    a.priority === b.priority &&
    a.action === b.action &&
    a.rationale === b.rationale &&
    a.pointer === b.pointer &&
    a.author === b.author
  );
}

async function apply(deps: WriterDeps, caseId: string, p: WatsonNextStepProposal) {
  const overview = await deps.stateStore.loadOverview(caseId);
  if (overview.nextSteps.some((s) => s.id === p.targetId)) {
    throw new WatsonProposalConflict(`Next step ${p.targetId} is already in the case; nothing was written`);
  }
  const step: NextStep = { ...p.after, id: p.targetId, author: "watson" };
  const state: InvestigationState = { ...overview, nextSteps: [...overview.nextSteps, step] };
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return { state, proposal: { ...p, after: step } };
}

async function undo(deps: WriterDeps, caseId: string, p: WatsonNextStepProposal) {
  const overview = await deps.stateStore.loadOverview(caseId);
  const stored = overview.nextSteps.find((s) => s.id === p.targetId);
  if (!stored || !sameStep(stored, { ...p.after, author: "watson" })) {
    throw new WatsonProposalConflict(
      `Next step ${p.targetId} changed or is gone since it was applied; nothing was changed`,
    );
  }
  const state: InvestigationState = {
    ...overview,
    nextSteps: overview.nextSteps.filter((s) => s.id !== p.targetId),
  };
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return { state };
}

export const nextStepWriter: WatsonWriter<WatsonNextStepProposal> = { apply, undo };
