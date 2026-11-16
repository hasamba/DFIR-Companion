import type { InvestigationState } from "../../stateTypes.js";

/** NEXT STEPS block: the most urgent steps first, at most this many, each line cut. */
export const WATSON_NEXT_STEPS_MAX = 15;
const STEP_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * The next steps Watson's prompt shows, most urgent first (a stable sort keeps the case's own order).
 * Auto's open items use the same list (autoProgress.ts), so it never waits on a step Watson cannot see.
 */
export function shownSteps(state: Pick<InvestigationState, "nextSteps">): InvestigationState["nextSteps"] {
  return [...(state.nextSteps ?? [])]
    .sort((a, b) => (STEP_RANK[a.priority] ?? 4) - (STEP_RANK[b.priority] ?? 4))
    .slice(0, WATSON_NEXT_STEPS_MAX);
}
