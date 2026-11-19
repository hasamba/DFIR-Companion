/**
 * Writes a drop sweep's log lines and status AS FILES FINISH (#2715), not once at the end. A file
 * is moved to `_processed/` or `_failed/` the moment it is done, so a crash or stop mid-sweep used
 * to leave moved files with no `drop-log.txt` line and no status entry.
 *
 * `flush` is called after every file outcome. It appends log lines only for tally entries not yet
 * logged and records the CUMULATIVE tally as the status (the status store replaces its record per
 * sweep, so a cumulative snapshot is the same shape the end-of-sweep summary has always had).
 * Calls are serialized and coalesced: concurrent solo imports share one pending write.
 */
import type { DropStatusStore } from "../analysis/dropStatus.js";
import { appendDropLog, buildSweepLogEntries, formatDropLogLines } from "../analysis/dropLog.js";
import type { SweepTally } from "./dropBatch.js";

export interface SweepRecorderDeps {
  caseId: string;
  dropDir: string;
  statusStore?: DropStatusStore;
  /** The case's PENDING-already-logged set; read at creation, handed back through `setLoggedPending`. */
  loggedPending: ReadonlySet<string>;
  setLoggedPending: (next: Set<string>) => void;
  onDropStatus?: (caseId: string) => void;
  log: (line: string) => void;
}

export interface SweepRecorder {
  /** Persist whatever the tally gained since the last flush. Never rejects. */
  flush: (tally: SweepTally) => Promise<void>;
}

export function createSweepRecorder(d: SweepRecorderDeps): SweepRecorder {
  let logged = { imported: 0, submitted: 0, failed: 0 };
  let loggedPending = d.loggedPending;
  let chain: Promise<void> = Promise.resolve();
  let queued = false;

  async function write(tally: SweepTally): Promise<void> {
    // Snapshot first: the tally keeps growing while the awaits below run.
    const imported = tally.imported.slice(logged.imported);
    const submittedAll = tally.submitted.slice(logged.submitted);
    const failed = tally.failed.slice(logged.failed);
    const snapshot = {
      imported: [...tally.imported],
      failed: [...tally.failed],
      pendingRawInputs: [...tally.pendingRawInputs],
      warned: [...tally.warned],
    };
    logged = {
      imported: logged.imported + imported.length,
      submitted: logged.submitted + submittedAll.length,
      failed: logged.failed + failed.length,
    };
    if (d.statusStore) {
      try {
        await d.statusStore.record(d.caseId, {
          dropPath: d.dropDir,
          imported: snapshot.imported,
          failed: snapshot.failed,
          pendingRawInputs: snapshot.pendingRawInputs,
          warnings: snapshot.warned,
        });
        d.onDropStatus?.(d.caseId);
      } catch (e) {
        d.log(`[drop] status record failed: ${(e as Error).message}`);
      }
    }
    // Async handoffs are in `imported` for the banner but log SUBMITTED, never IMPORTED.
    const submittedPaths = new Set(tally.submitted.map((s) => s.relpath));
    const { entries, nextLoggedPending } = buildSweepLogEntries(
      {
        imported: imported.filter((r) => !submittedPaths.has(r)),
        submitted: submittedAll,
        failed,
        pendingRawInputs: snapshot.pendingRawInputs,
        warned: snapshot.warned,
      },
      loggedPending,
    );
    loggedPending = nextLoggedPending;
    d.setLoggedPending(nextLoggedPending);
    if (entries.length > 0) {
      await appendDropLog(d.dropDir, formatDropLogLines(entries, new Date().toISOString())).catch((e) =>
        d.log(`[drop] log append failed: ${(e as Error).message}`),
      );
    }
  }

  return {
    flush(tally) {
      if (queued) return chain; // the queued write reads the tally when it runs, so it covers this call
      queued = true;
      chain = chain.then(() => {
        queued = false;
        return write(tally);
      });
      return chain.catch(() => undefined);
    },
  };
}
