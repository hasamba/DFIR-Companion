import type { ContainmentCoverage, ContainmentJevState } from "../analysis/ai/jev/containmentState.js";
import { buildContainmentState } from "../analysis/ai/jev/containmentState.js";
import type { Finding, InvestigationState } from "../analysis/stateTypes.js";
import type { CaseStore } from "../storage/caseStore.js";
import { jevMasking, type JevMasking } from "./jevMasking.js";

/**
 * What the containment check sends Jev (#1925), split out of the route (#2515) so "Preview what the AI
 * will see" builds EXACTLY the state a real check would send: the route and the preview both call
 * `containmentRequest`. It reads the FORENSIC TIMELINE ONLY — the finding and the events it cites —
 * and writes nothing.
 */
export interface ContainmentRequest extends JevMasking {
  readonly finding: Finding;
  readonly jevState: ContainmentJevState;
  readonly coverage: ContainmentCoverage;
}

/** null when the finding is not in the case. */
export async function containmentRequest(
  store: CaseStore,
  caseId: string,
  state: InvestigationState,
  findingId: string,
): Promise<ContainmentRequest | null> {
  const finding = state.findings.find((f) => f.id === findingId);
  if (!finding) return null;
  // Masked like every Jev call: the revision is read BEFORE the lists load (#1840).
  const masking = await jevMasking(store, caseId, state);
  const { state: jevState, coverage } = buildContainmentState(finding, state, masking.masker.mask);
  return { ...masking, finding, jevState, coverage };
}
