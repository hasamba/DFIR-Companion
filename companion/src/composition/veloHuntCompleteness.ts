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
): Pick<VeloHuntJob, "skippedArtifacts" | "truncatedArtifacts" | "unreadArtifacts" | "earlierCoverage"> {
  return {
    skippedArtifacts: skipped.length ? skipped : undefined,
    truncatedArtifacts: cutShort.length ? cutShort : undefined,
    unreadArtifacts: unread.length ? unread : undefined,
    earlierCoverage: undefined, // these lists are this collect's own (#2842)
  };
}

/**
 * The job of a collect that failed as a whole (#2842): the collect's own catch, and the startup
 * sweep for a collect a restart cut off. Both write it through here, so they agree on what the
 * job's per-artifact lists then mean.
 *
 * A collect replaces the lists with its own when it leaves the "fetching" phase (`completeness`, in
 * the same write that moves the phase to "queued"). A failure while the STORED phase is still
 * "fetching" therefore leaves an EARLIER collect's lists on the job, under the new error. They are
 * kept — they are still true of the case, and the collection inventory reads them — and marked, so
 * the hunt card can say whose results they are. In every other stored state the lists are this
 * collect's own and nothing is marked. An existing mark is kept: a second early failure changes nothing.
 */
export function failedCollect(cur: VeloHuntJob, error: string): VeloHuntJob {
  const lists = [
    cur.skippedArtifacts,
    cur.truncatedArtifacts,
    cur.unreadArtifacts,
    cur.emptyArtifacts,
    cur.superCappedArtifacts,
  ];
  const earlier = cur.collectPhase === "fetching" && lists.some((l) => !!l?.length);
  return {
    ...cur,
    status: "error",
    collectPhase: undefined,
    collectRows: undefined,
    error,
    ...(earlier ? { earlierCoverage: true as const } : {}),
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
