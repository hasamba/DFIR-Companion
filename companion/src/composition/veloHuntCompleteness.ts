import { runHuntSettle } from "../analysis/huntSettleHook.js";
import type { VeloHuntJob, VeloHuntStore } from "../analysis/veloHuntStore.js";
import { warnLine } from "../logging/serverLogger.js";

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

/**
 * The collect's own final job, once it has built one (#2850) — else `undefined`.
 *
 * `job` IS `before` (the stored job, which may say "imported" from an EARLIER collect) until the
 * collect's first write, is "collecting" from there until it builds its outcome, and is that outcome
 * — "imported", or its own part-imported "error" (#2817) — after it.
 */
export function ownOutcome(job: VeloHuntJob, before: VeloHuntJob): VeloHuntJob | undefined {
  return job !== before && job.status !== "collecting" ? job : undefined;
}

/** What the collect's catch needs from the collect (`collectFailed`). */
export interface CollectFailureIo {
  huntStore: Pick<VeloHuntStore, "get" | "upsert">;
  /** The `[import] … FAILED` line and the diagnostics entry. */
  record: (err: unknown) => void;
  onVeloHunt?: (caseId: string) => void;
  onAiStatus?: (caseId: string, event: { status: "error"; at: string; detail: string }) => void;
  markConclusionsOutOfDate?: (caseId: string, reason: string) => Promise<void>;
}

/**
 * The collect's catch. Never throws: the collect's `finally` must still release its holds.
 *
 * With no outcome of its own (`own` undefined) the collect failed as a whole: the failure is
 * recorded and the job is written through `failedCollect` (#2842).
 *
 * With one, the import already finished and only a LATER step failed — in production the final job
 * write itself (a full disk, a file lock that outlasts the retry budget) (#2850). The rows, the
 * import record and the undo checkpoint are in the case, so the job keeps the collect's outcome
 * (written again) and no import failure is recorded. The throw skipped whatever followed it — the
 * final re-grade, the synthesis start, the out-of-date mark — so the late error is logged, the
 * conclusions are marked out of date and the status says what happened.
 */
export async function collectFailed(
  io: CollectFailureIo,
  caseId: string,
  huntId: string,
  err: unknown,
  own: VeloHuntJob | undefined,
): Promise<void> {
  const message = err instanceof Error ? err.message : String(err);
  const quietly = async (what: string, step: () => unknown): Promise<void> => {
    try {
      await step();
    } catch (e) {
      warnLine(`[velociraptor] ${caseId} hunt ${huntId}: ${what} failed: ${(e as Error).message}`);
    }
  };
  if (own)
    warnLine(
      `[velociraptor] ${caseId} hunt ${huntId}: the collect kept its result, but a later step failed: ${message}`,
    );
  else await quietly("recording the failed collect", () => io.record(err));
  await quietly("writing the hunt job after a failure", async () => {
    const cur = await io.huntStore.get(caseId, huntId);
    // A forgotten hunt is not written back.
    if (cur) await io.huntStore.upsert(caseId, own ?? failedCollect(cur, message));
  });
  if (own)
    await quietly("marking the conclusions out of date", () =>
      io.markConclusionsOutOfDate?.(caseId, "a hunt collect's follow-up step failed"),
    );
  const detail = own
    ? `Velociraptor hunt collect kept its result, but a follow-up step failed: ${message}`
    : `Velociraptor hunt collect failed: ${message}`;
  await quietly("the dashboard refresh", () => io.onVeloHunt?.(caseId));
  await quietly("the status update", () =>
    io.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail }),
  );
}
