import { runHuntSettle } from "../analysis/huntSettleHook.js";
import type { VeloHuntJob } from "../analysis/veloHuntStore.js";

/**
 * A hunt collect's completeness, and hunt grading that sees it (#2670).
 *
 * Hunt grading runs at the import seam and reads coverage — which artifacts were skipped, cut short
 * or read without their source list — from the PERSISTED hunt job. Those are final once the fetch
 * loop ends, so the collect writes them with its pre-import job update (`completeness`): grading
 * never sees a partial collection as complete, and absence is never proven by a failed fetch. Every
 * field is written, `undefined` when empty, so a previous collect's flags never linger.
 *
 * After the final job write the collect grades once more with no new rows (`regradeAfterCollect`):
 * a collect that imported nothing (or whose coverage changed) still re-grades, so rare entries from
 * an earlier, complete pass do not survive a now-partial one. Outside hunt mode it does nothing.
 */
export function completeness(
  skipped: NonNullable<VeloHuntJob["skippedArtifacts"]>,
  cutShort: NonNullable<VeloHuntJob["truncatedArtifacts"]>,
  unread: NonNullable<VeloHuntJob["unreadArtifacts"]>,
): Pick<VeloHuntJob, "skippedArtifacts" | "truncatedArtifacts" | "unreadArtifacts"> {
  return {
    skippedArtifacts: skipped.length ? skipped : undefined,
    truncatedArtifacts: cutShort.length ? cutShort : undefined,
    unreadArtifacts: unread.length ? unread : undefined,
  };
}

export async function regradeAfterCollect(
  stateStore: object | undefined,
  caseId: string,
  runStateExclusive: (<T>(caseId: string, fn: () => Promise<T>) => Promise<T>) | undefined,
  log: (line: string) => void,
): Promise<void> {
  if (!stateStore) return;
  const run = () =>
    runHuntSettle(stateStore, caseId, [], (e) => log(`[hunt] ${caseId}: re-grade skipped: ${e.message}`));
  try {
    await (runStateExclusive ? runStateExclusive(caseId, run) : run());
  } catch (e) {
    log(`[hunt] ${caseId}: re-grade skipped: ${(e as Error).message}`); // never fails the collect
  }
}
