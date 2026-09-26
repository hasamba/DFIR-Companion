import type { SynthMetaStore } from "../synthMeta.js";
import type { InvestigationState } from "../stateTypes.js";

/** Why a synthesis stopped before any model call (#1676). */
export type SynthesisSkipReason = "empty-timeline";

/**
 * Nothing to synthesize: the forensic timeline is empty (#1676). No model call and no run record.
 * When the case also holds no findings, its empty conclusions match the case, so the #1599
 * "conclusions out of date" marker is cleared — otherwise pressing Re-synthesize left it in place.
 * Findings left from an earlier run are stale, so then the marker stays. A dry run writes nothing.
 */
export async function skipEmptyTimeline(
  meta: SynthMetaStore | undefined,
  caseId: string,
  loaded: InvestigationState,
  startRevision: number,
  opts: { dryRun?: boolean; onSkip?: (reason: SynthesisSkipReason) => void },
): Promise<InvestigationState> {
  if (!opts.dryRun && loaded.findings.length === 0) await meta?.clearOutOfDate(caseId, startRevision);
  opts.onSkip?.("empty-timeline");
  return loaded;
}
