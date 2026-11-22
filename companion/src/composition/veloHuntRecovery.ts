/**
 * The seam settle for a hunt collect that a server restart cut off while it was IMPORTING (#2851).
 *
 * A collect imports its artifacts one at a time and settles them once, after the last one
 * (composition/veloHuntSettle.ts). A process that dies in between leaves the whole-file artifacts'
 * rows in the forensic timeline without ever crossing the seam (routes/importSettle.ts): no
 * raw-record copy, no tagger pass, no demote. The next import's settle cannot see them — it settles
 * only rows new since its own snapshot — but its demote is case-wide, so it moves those rows out of
 * the forensic timeline UNTAGGED: a row the tagger would have graded up is lost to the AI.
 *
 * Start-up recovery calls this for each such collect, as the drop folder does for an interrupted
 * batch (composition/importIngestBatch.ts `recoverDropBatch`, #2540). Under the case's import lock,
 * reading the forensic timeline in pages (the trigger is often an out-of-memory kill), it selects the
 * rows whose source is a stored file of THIS hunt and that carry no import stamp, then runs the
 * settle's own steps on them: stamp (+ the first-party egress and generic Sysmon downgrades), dual-
 * write, tagger, demote — merge-all → tagger → demote, as every import.
 *
 * The missing stamp is the marker. A whole-file artifact's rows are stamped only by the settle; a
 * batched artifact's rows are stamped per batch, when each batch crosses the seam, so they are left
 * alone. A second run finds nothing to do. Rows an analyst or Watson promoted are not the import's.
 *
 * Not recovered (as for the drop batch): the import record, the Undo entry and the run record, and
 * the look-alike, cap and hunt-grading passes. The hunt card says so (#2849). Rows of an uploaded
 * report are stored under the report's own name, so they are not selected here.
 */
import type { AppOptions } from "./appOptions.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { ImportLock } from "../analysis/importLock.js";
import { SCAN_PAGE_ROWS } from "../analysis/forensicRows.js";
import { isManualId } from "../analysis/manualId.js";
import { carryAndStampPaged, dualWriteAndTagPaged } from "../routes/importSettlePaged.js";
import { runUnlocked, type RunExclusive } from "../routes/importSettleRows.js";
import { getServerLogger } from "../logging/serverLogger.js";

export interface HuntRecoveryDeps {
  options: Pick<AppOptions, "stateStore" | "superTimelineStore" | "onSuperTimeline">;
  importLock: Pick<ImportLock, "runExclusive">;
  runStateExclusive?: RunExclusive;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  demoteForensicForCase: (caseId: string) => Promise<unknown>;
}

/** The stored-file prefix of this hunt's artifacts (veloEvidenceFirst.ts, importCommit.ts names). */
export function huntFilePattern(huntId: string): RegExp {
  const safe = huntId.replace(/[^\w.\-]+/g, "_").replace(/[.\-]/g, "\\$&");
  return new RegExp(`^\\d+_velo-hunt_${safe}_`);
}

const unsettled = (e: ForensicEvent, file: RegExp): boolean =>
  !e.importBatchId &&
  !e.promotedAt &&
  !isManualId(e.id) &&
  e.sourceScreenshots.some((s) => typeof s === "string" && file.test(s));

/**
 * Settle this hunt's unstamped rows; returns how many it settled. Throws on a store failure — the
 * caller (start-up recovery) logs it with the case and hunt id.
 */
export async function settleInterruptedHuntRows(
  deps: HuntRecoveryDeps,
  caseId: string,
  huntId: string,
): Promise<number> {
  const store = deps.options.stateStore;
  if (!store) return 0;
  const lock = deps.runStateExclusive ?? runUnlocked;
  const file = huntFilePattern(huntId);
  return deps.importLock.runExclusive(caseId, async () => {
    const ids: string[] = [];
    for await (const page of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS }))
      for (const e of page) if (unsettled(e, file)) ids.push(e.id);
    if (!ids.length) return 0; // nothing of this hunt is unsettled: no case-wide demote either
    const ledger = await store.loadOverviewWithoutIocs(caseId);
    const scope = { addedIds: ids, touchedRowIds: [], touchedKnown: true, mergedCount: 0 };
    const superStore = deps.options.superTimelineStore;
    const stamped = await lock(caseId, () =>
      carryAndStampPaged(store, caseId, ledger, scope, false, {
        capturedAt: undefined,
        downgrade: !!superStore,
      }),
    );
    if (superStore && stamped.addedIds.length) {
      const dualDeps = { ...deps.options, stateStore: store, runStateExclusive: lock };
      await dualWriteAndTagPaged(
        { ...dualDeps, autoTagImported: deps.autoTagImported },
        caseId,
        stamped.addedIds,
      );
    }
    await deps.demoteForensicForCase(caseId);
    getServerLogger().warn(
      `[velo-hunt] ${caseId}: settled ${stamped.addedIds.length} row(s) of hunt ${huntId}'s collect ` +
        "that a restart interrupted (no import record or Undo entry)",
      { caseId },
    );
    return stamped.addedIds.length;
  });
}
