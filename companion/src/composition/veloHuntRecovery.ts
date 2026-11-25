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
 * alone. Without a batch id (below) a second run finds nothing to do; with one it re-settles that
 * batch's rows, which the tagger and the super-timeline's dedupe make harmless. Rows an analyst or
 * Watson promoted are not the import's.
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
 * `settleAfterFailedSettle`). The settle stamps first, so a settle that failed partway through the
 * stamp or AFTER it (the dual-write's page reads) leaves rows that DO carry a stamp. The collect picks
 * its settle's batch id itself and records it on the job in the same write as the stored names
 * (`importingBatchId`, #2888); the recovery then also selects the rows stamped with that id, and
 * re-stamps them with the SAME id, so a second failure leaves them findable again. It widens only
 * when the settle itself failed: after a record or Undo failure every row was settled. A job written
 * before that field existed has no id: only its unstamped rows are selected.
 */
import { randomUUID } from "node:crypto";
import type { AppOptions } from "./appOptions.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { ALL_CASES, type ImportLock } from "../analysis/importLock.js";
import { settleUnsettledRows } from "../routes/importRowRecovery.js";
import type { RunExclusive } from "../routes/importSettleRows.js";
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

/** What the collect writes on the job as it enters its import section (#2852, #2888). */
export interface ImportingMarks {
  importingUploads: string[] | undefined;
  importingBatchId: string;
}

export function importingMarks(uploads: readonly { storedName: string }[]): ImportingMarks {
  return { importingUploads: uploadStoredNames(uploads), importingBatchId: randomUUID() };
}

/** A row of this collect: from this hunt's stored artifact files, or one of its uploaded reports. */
type CollectFile = (source: string) => boolean;

function collectFile(huntId: string, uploadFiles: readonly unknown[] | undefined): CollectFile {
  const file = huntFilePattern(huntId);
  // Read back from the job file: only strings are names.
  const uploads = new Set((uploadFiles ?? []).filter((n): n is string => typeof n === "string" && !!n));
  return (s) => file.test(s) || uploads.has(s);
}

export interface HuntRecoveryOpts {
  /** The stored names of the uploaded reports the collect imported (#2852). */
  uploadFiles?: readonly string[];
  /** The batch id the collect's failed settle stamped with (#2888): its rows are selected too. */
  batchId?: string;
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
  const ofCollect = collectFile(huntId, opts.uploadFiles);
  // Read back from the job file: only a non-empty string is an id.
  const batchId = typeof opts.batchId === "string" && opts.batchId ? opts.batchId : undefined;
  const recoveryDeps = {
    stateStore: store,
    runStateExclusive: deps.runStateExclusive,
    superTimelineStore: deps.options.superTimelineStore,
    onSuperTimeline: deps.options.onSuperTimeline,
    autoTagImported: deps.autoTagImported,
    demote: deps.demoteForensicForCase,
  };
  return deps.importLock.runPastHolds(caseId, async () => {
    // The shared core (routes/importRowRecovery.ts, #2890): select, stamp, dual-write, tag, demote.
    const settled = await settleUnsettledRows(recoveryDeps, caseId, ofCollect, batchId);
    if (settled === null) return 0; // nothing of this hunt is unsettled: no case-wide demote either
    getServerLogger().warn(
      `[velo-hunt] ${caseId}: settled ${settled} row(s) of hunt ${huntId}'s collect ` +
        `${opts.cause ?? RESTART_CAUSE} (no import record or Undo entry)`,
      { caseId },
    );
    return settled;
  });
}

/** The collect already holds the case's import section, and the lock is not re-entrant. */
const insideSection: Pick<ImportLock, "runPastHolds"> = { runPastHolds: (_caseId, fn) => fn() };

/**
 * #2852: the collect's own settle failed (composition/veloHuntSettle.ts). Settle the rows it did not
 * reach NOW, before the collect lets go of the import section — otherwise the next import's case-wide
 * demote moves them out untagged. Called from INSIDE that section, so it does not take it again.
 * Never throws: the settle may have failed for memory, and a second failure is logged, not raised —
 * and returned as `error`, so the caller can tell the analyst (#2888). `batchId`: see the header.
 */
export async function settleAfterFailedSettle(
  deps: HuntRecoveryDeps,
  caseId: string,
  huntId: string,
  uploadFiles: readonly string[] | undefined,
  batchId?: string,
): Promise<FailedSettleRecovery> {
  try {
    const inside = { ...deps, importLock: insideSection };
    const settled = await settleInterruptedHuntRows(inside, caseId, huntId, {
      uploadFiles,
      batchId,
      cause: "whose own settle failed",
    });
    return { settled };
  } catch (err) {
    const error = (err as Error)?.message ?? String(err);
    getServerLogger().warn(
      `[velo-hunt] ${caseId}: settling hunt ${huntId}'s rows after its settle failed did not work either: ${error}`,
      { caseId },
    );
    return { settled: 0, error };
  }
}

/** What the in-process recovery did: rows settled, and its own failure when it failed too. */
export interface FailedSettleRecovery {
  settled: number;
  error?: string;
}

/**
 * The collect's call after its settle (#2852, #2888): nothing when the settle reported no error;
 * otherwise settle the collect's rows the settle did not reach. Its batch id widens the selection
 * only when the settle ITSELF failed (`seamFailed`) — after a record or Undo failure every row was
 * settled, and re-stamping them would run a second case-wide demote for nothing.
 */
export async function recoverFailedHuntSettle(
  deps: HuntRecoveryDeps,
  caseId: string,
  job: { huntId: string; importingUploads?: readonly string[]; importingBatchId?: string },
  settled: { error?: string; seamFailed?: boolean },
): Promise<FailedSettleRecovery | undefined> {
  if (!settled.error) return undefined;
  const batchId = settled.seamFailed ? job.importingBatchId : undefined;
  return settleAfterFailedSettle(deps, caseId, job.huntId, job.importingUploads, batchId);
}
