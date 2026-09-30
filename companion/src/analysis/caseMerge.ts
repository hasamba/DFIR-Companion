import type { AnalysisDelta } from "./responseSchema.js";
import type { InvestigationState } from "./stateTypes.js";
import type { StateStore } from "./stateStore.js";
import type { WindowContext } from "./stateMerge.js";
import { correlationGroups } from "./correlate.js";
import { getAppVersion } from "../version.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { MERGE_INDEX_VERSION, MergeCommitUnknown, mergeIncrementally } from "./incrementalMerge.js";
import { fixedPoints, readBack } from "./incrementalMergeRows.js";
import { mergeIndexEntry } from "./mergeIndex.js";

/**
 * Merge an importer's delta into a case and save it (#1874) — the incremental merge when it can show
 * the result is today's, today's full load → merge → save otherwise. Call it inside the case's state
 * lock, as every importer already does.
 *
 * `complete` says whether `state` is the whole case. The incremental merge returns the case metadata,
 * the IOCs it touched and the forensic rows it wrote, not every row: it never read the others.
 */
export interface CaseMergeResult {
  state: InvestigationState;
  complete: boolean;
}

/** The stamp a case's merge index must carry to be trusted: this merge's version and this build's. */
export function mergeIndexStamp(): string {
  return `${MERGE_INDEX_VERSION}:${getAppVersion()}`;
}

function supportsIncremental(store: StateStore): boolean {
  return typeof (store as Partial<StateStore>).mergeSnapshot === "function";
}

export async function mergeIntoCase(
  store: StateStore,
  caseId: string,
  delta: AnalysisDelta,
  ctx: WindowContext,
  fullMerge: (state: InvestigationState) => InvestigationState | Promise<InvestigationState>,
): Promise<CaseMergeResult> {
  const log = getServerLogger();
  const stamp = mergeIndexStamp();
  const incremental = supportsIncremental(store);
  if (incremental) {
    try {
      const result = await mergeIncrementally(store, caseId, delta, ctx, stamp);
      if (result.ok) {
        log.debug(`[merge] incremental: read ${result.read} row(s), placed ${result.written}`, { caseId });
        return { state: result.state, complete: false };
      }
      log.info(`[merge] full-state merge: ${result.reason}`, { caseId });
    } catch (err) {
      // An apply whose outcome is unknown (it may have committed) is never followed by a second
      // merge of the same delta: the import fails, as a failed save always made it.
      if (err instanceof MergeCommitUnknown) throw err.cause;
      // Anything else was thrown before the apply, by a step that only reads: nothing was written.
      const reason = err instanceof Error ? err.message : String(err);
      log.warn(`[merge] incremental merge stopped (${reason}); taking the full-state merge`, { caseId });
    }
  }
  const merged = await fullMerge(await store.load(caseId));
  if (!incremental) {
    await store.save(merged);
    return { state: merged, complete: true };
  }
  // Saved with the index marked unsettled: until indexAfterFullSave says otherwise, the next merge
  // is a full one too.
  const saved = await store.saveFull(merged, true);
  try {
    await indexAfterFullSave(store, caseId, merged, saved, stamp, ctx.timestamp);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    log.warn(`[merge] could not index the case after a full merge (${reason})`, { caseId });
  }
  return { state: merged, complete: true };
}

/**
 * Index the rows a full save wrote (every row, the first time and after an upgrade), and record whether the stored
 * timeline would fold again on the next merge. A full save stores the timeline in array order, so a
 * row's position names its event.
 */
async function indexAfterFullSave(
  store: StateStore,
  caseId: string,
  merged: InvestigationState,
  saved: number,
  stamp: string,
  at: string,
): Promise<void> {
  const stale = await store.mergeStalePositions(caseId, stamp);
  const rows = merged.forensicTimeline;
  // The entries come from `merged`: only while nothing was written since the save do the stored rows
  // read as `merged` does. Otherwise the index stays as it was (the next merge re-reads those rows).
  if (!stale || stale.generation !== saved || stale.rowCount !== rows.length) return;
  const values = rows.map(readBack);
  const staleValues = stale.positions.map((p) => values[p]);
  const clean = fixedPoints(staleValues, at);
  const stable = !correlationGroups(values).some((group) => group.length > 1);
  await store.mergeIndexWrite(
    caseId,
    saved,
    stale.positions.map((position, i) => ({
      position,
      index: { ...mergeIndexEntry(staleValues[i]), clean: clean[i] },
    })),
    { stamp, stable },
  );
}
