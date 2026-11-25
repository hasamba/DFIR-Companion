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
 * the look-alike, cap and hunt-grading passes. The hunt card says so (#2849).
 *
 * Rows of an uploaded report (THOR, …) are stored under the report's own name, not the hunt's. The
 * collect records those stored names on the job before it imports (`importingUploads`, #2852), and
 * they are selected by exact name. A job written before that field existed has none: its uploads'
 * rows are not selected.
 *
 * The same settle runs in-process when the collect's OWN settle failed (#2852,
 * `settleAfterFailedSettle`). Known limit: the marker is the stamp, and the settle stamps first, so a
 * settle that failed AFTER stamping (in the dual-write or the tagger) leaves rows this cannot find.
 */
import type { AppOptions } from "./appOptions.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { ALL_CASES, type ImportLock } from "../analysis/importLock.js";
import { SCAN_PAGE_ROWS } from "../analysis/forensicRows.js";
import { isManualId } from "../analysis/manualId.js";
import { carryAndStampPaged, dualWriteAndTagPaged } from "../routes/importSettlePaged.js";
import { runUnlocked, type RunExclusive } from "../routes/importSettleRows.js";
import { getServerLogger } from "../logging/serverLogger.js";

export interface HuntRecoveryDeps {
  options: Pick<AppOptions, "stateStore" | "superTimelineStore" | "onSuperTimeline">;
  /** `runPastHolds`: start-up holds imports into the case until THIS settle has run (see below). */
  importLock: Pick<ImportLock, "runPastHolds">;
  runStateExclusive?: RunExclusive;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  demoteForensicForCase: (caseId: string) => Promise<unknown>;
}

/** The longest a start-up hold keeps a case's imports waiting; the settle itself is not cut off. */
export const RECOVERY_HOLD_TIMEOUT_MS = 120_000;

/**
 * The start-up barrier (#2851 review). The sweep is not awaited: the server serves, the monitors
 * resume and the drop watcher arms while it lists cases and marks jobs. An import that reached an
 * affected case first would snapshot the stranded rows as existing data, tag only its own and demote
 * case-wide, moving them out untagged where this settle (which scans the forensic timeline) cannot
 * find them. So imports into every case wait while the sweep enumerates (`ALL_CASES`, armed
 * synchronously at start-up), and into an affected case until its settle has run. Reads never wait.
 * `work` always settles the hold, success or failure; past `timeoutMs` the hold is let go with a
 * WARN. A settle still running then holds the case's import section, so a released import still
 * queues behind it.
 */
export function holdImportsDuring(
  lock: Pick<ImportLock, "hold"> | undefined,
  key: string | typeof ALL_CASES,
  work: Promise<unknown>,
  timeoutMs = RECOVERY_HOLD_TIMEOUT_MS,
): void {
  if (!lock) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<void>((resolve) => {
    timer = setTimeout(() => {
      const scope = key === ALL_CASES ? "every case" : key;
      getServerLogger().warn(
        `[velo-hunt] start-up recovery still running after ${Math.round(timeoutMs / 1000)} s — ` +
          `imports into ${scope} no longer wait for it`,
        key === ALL_CASES ? undefined : { caseId: key },
      );
      resolve();
    }, timeoutMs);
    timer.unref?.();
  });
  const settled = work.then(
    () => clearTimeout(timer),
    () => clearTimeout(timer),
  );
  lock.hold(key, Promise.race([settled, expired]));
}

/** The stored-file prefix of this hunt's artifacts (veloEvidenceFirst.ts, importCommit.ts names). */
export function huntFilePattern(huntId: string): RegExp {
  const safe = huntId.replace(/[^\w.\-]+/g, "_").replace(/[.\-]/g, "\\$&");
  return new RegExp(`^\\d+_velo-hunt_${safe}_`);
}

/** The uploads' stored names for the job (#2852); none for a collect without uploads. */
export function uploadStoredNames(uploads: readonly { storedName: string }[]): string[] | undefined {
  return uploads.length ? uploads.map((u) => u.storedName) : undefined;
}

/** A row of this collect: from this hunt's stored artifact files, or one of its uploaded reports. */
type CollectFile = (source: string) => boolean;

function collectFile(huntId: string, uploadFiles: readonly unknown[] | undefined): CollectFile {
  const file = huntFilePattern(huntId);
  // Read back from the job file: only strings are names.
  const uploads = new Set((uploadFiles ?? []).filter((n): n is string => typeof n === "string" && !!n));
  return (s) => file.test(s) || uploads.has(s);
}

const unsettled = (e: ForensicEvent, ofCollect: CollectFile): boolean =>
  !e.importBatchId &&
  !e.promotedAt &&
  !isManualId(e.id) &&
  e.sourceScreenshots.some((s) => typeof s === "string" && ofCollect(s));

export interface HuntRecoveryOpts {
  /** The stored names of the uploaded reports the collect imported (#2852). */
  uploadFiles?: readonly string[];
  /** Why the rows are unsettled, for the WARN line. */
  cause?: string;
}

const RESTART_CAUSE = "that a restart interrupted";

/**
 * Settle this hunt's unstamped rows; returns how many it settled. Throws on a store failure — the
 * caller (start-up recovery) logs it with the case and hunt id.
 */
export async function settleInterruptedHuntRows(
  deps: HuntRecoveryDeps,
  caseId: string,
  huntId: string,
  opts: HuntRecoveryOpts = {},
): Promise<number> {
  const store = deps.options.stateStore;
  if (!store) return 0;
  const lock = deps.runStateExclusive ?? runUnlocked;
  const ofCollect = collectFile(huntId, opts.uploadFiles);
  return deps.importLock.runPastHolds(caseId, async () => {
    const ids: string[] = [];
    for await (const page of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS }))
      for (const e of page) if (unsettled(e, ofCollect)) ids.push(e.id);
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
        `${opts.cause ?? RESTART_CAUSE} (no import record or Undo entry)`,
      { caseId },
    );
    return stamped.addedIds.length;
  });
}

/** The collect already holds the case's import section, and the lock is not re-entrant. */
const insideSection: Pick<ImportLock, "runPastHolds"> = { runPastHolds: (_caseId, fn) => fn() };

/**
 * #2852: the collect's own settle failed (composition/veloHuntSettle.ts). Settle the rows it did not
 * reach NOW, before the collect lets go of the import section — otherwise the next import's case-wide
 * demote moves them out untagged. Called from INSIDE that section, so it does not take it again.
 * Never throws: the settle may have failed for memory, and a second failure is logged, not raised.
 * Returns how many rows it settled.
 */
export async function settleAfterFailedSettle(
  deps: HuntRecoveryDeps,
  caseId: string,
  huntId: string,
  uploadFiles: readonly string[] | undefined,
): Promise<number> {
  try {
    const inside = { ...deps, importLock: insideSection };
    return await settleInterruptedHuntRows(inside, caseId, huntId, {
      uploadFiles,
      cause: "whose own settle failed",
    });
  } catch (err) {
    getServerLogger().warn(
      `[velo-hunt] ${caseId}: settling hunt ${huntId}'s rows after its settle failed did not work either: ` +
        `${(err as Error)?.message ?? String(err)}`,
      { caseId },
    );
    return 0;
  }
}
