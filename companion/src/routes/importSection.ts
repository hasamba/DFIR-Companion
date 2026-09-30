import type { ImportLock } from "../analysis/importLock.js";
import type { StateStore } from "../analysis/stateStore.js";
import type { ImportAdmissionHint } from "../analysis/importMemoryGuard.js";
import {
  captureImportBaseline,
  releaseImportBaseline,
  type ImportBaseline,
} from "../analysis/importBaseline.js";

/**
 * The critical section an import route runs inside: the case's import lock, held, plus the state
 * snapshot the import will be diffed against.
 *
 * The two belong together because the snapshot is only meaningful while the lock is held. Taken
 * earlier — when the request is accepted, say — it still describes the state from before the imports
 * QUEUED AHEAD of this one ran, and this import's diff then claims their events as its own: dropping
 * 17 artifact files at once made the last of them report the whole batch, "308 forensic events" for a
 * 2-row registry artifact, against an honest "2 super-timeline events" (the super-timeline counts
 * only what it truly inserted, which is what made the over-attribution visible). Undoing that import
 * would have reverted every file in the batch, since the same snapshot is its undo checkpoint.
 *
 * The job queue is not a substitute: DFIR_JOBS_PER_CASE is an operator setting, and above 1
 * admission stops meaning exclusivity. See analysis/importLock.ts.
 */
export interface ImportSection {
  /**
   * The case as of the moment this import took the case — an outline plus the armed import journal,
   * not a full copy (analysis/importBaseline.ts, #1874). Null when no state store is wired.
   */
  baseline: ImportBaseline | null;
  /** Release the section. Call it from a `finally` — forgetting it wedges the case's imports. */
  release(): void;
}

/**
 * Take the case's import section: wait for the lock, then snapshot inside it. `size` sizes the
 * import for the memory guard (#1874), which may refuse it here — before the snapshot is loaded:
 * a number is the artifact's size in bytes.
 */
export async function beginImportSection(
  importLock: ImportLock,
  caseId: string,
  stateStore?: StateStore,
  size?: number | ImportAdmissionHint,
): Promise<ImportSection> {
  const unlock = await importLock.acquire(caseId, typeof size === "number" ? { incomingBytes: size } : size);
  let baseline: ImportBaseline | null = null;
  try {
    baseline = stateStore ? await captureImportBaseline(stateStore, caseId) : null;
  } catch {
    // Best-effort: no snapshot means no diff and no checkpoint, never a failed import.
  }
  // The journal is disarmed BEFORE the lock goes, so the next section's arm is never undone by it.
  const release = (): void => {
    if (!stateStore || !baseline?.journalToken) return unlock();
    void releaseImportBaseline(stateStore, baseline).finally(unlock);
  };
  return { baseline, release };
}
