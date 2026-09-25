/**
 * "The conclusions are out of date" — what every case change says instead of starting a synthesis.
 *
 * THE RULE (#1599). A synthesis starts only when the analyst turns AI on, presses Re-synthesize (or
 * sends /synthesize), when an import finishes with AI on, or when the last duplicate-host pair is
 * resolved. Screenshot captures count as evidence arriving, like an import. Nothing else starts one.
 *
 * WHY. Eleven other actions used to start a run each: dismissing a finding, changing the scope
 * window or source trust, promoting rows, adding a manual event, applying the whitelist or NSRL,
 * deobfuscating, clearing the Presidio gate, and flipping anonymization — that last one by calling
 * synthesize() directly, with no job and no busy check. On a lab case the anonymization switch and
 * the AI-on catch-up then ran two seven-minute syntheses side by side, and the later one silently
 * overwrote the other. The analyst paid for a run nobody asked for.
 *
 * So those actions persist a marker instead, the header pill reads it back through GET /ai-state
 * ("conclusions out of date — press Re-synthesize"), and the analyst decides when to pay. A real
 * synthesis run clears it (analysis/synthMeta.ts, record()).
 */
import { warnLine } from "../logging/serverLogger.js";
import { SynthMetaStore } from "../analysis/synthMeta.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";

export interface ConclusionsOutOfDateDeps {
  store: CaseStore;
  options: AppOptions;
  /** Cases whose automatic synthesis is running right now (composition/captureAnalysis.ts). */
  synthInFlight: () => ReadonlySet<string>;
}

/** Mark a case's conclusions out of date. Never throws: the change it follows has already landed. */
export type MarkConclusionsOutOfDate = (caseId: string, reason: string) => Promise<void>;

const ACTIVE_JOB = new Set(["queued", "running"]);

export function createConclusionsOutOfDate(deps: ConclusionsOutOfDateDeps): MarkConclusionsOutOfDate {
  const { store, options } = deps;
  const meta = options.synthMetaStore ?? new SynthMetaStore(store);

  /** Is anything already working on this case? Its own terminal status will refresh the pill. */
  function busy(caseId: string): boolean {
    if (deps.synthInFlight().has(caseId)) return true;
    const jobs = options.jobManager?.list(caseId) ?? [];
    return jobs.some((job) => ACTIVE_JOB.has(job.status));
  }

  return async function markConclusionsOutOfDate(caseId: string, reason: string): Promise<void> {
    try {
      await meta.markOutOfDate(caseId, reason);
    } catch (err) {
      // Logged, not thrown: the analyst's change is saved, and failing the request over the marker
      // would tell them it was not. The pill then stays on its last state until the next run.
      warnLine(`[synthesis] ${caseId}: could not mark conclusions out of date: ${(err as Error).message}`);
      return;
    }
    // The dashboard answers a terminal "idle" by re-reading GET /ai-state, which now reports the
    // marker, and by clearing any "…re-synthesizing" status line. Skipped while work is running, so
    // it cannot paint "idle" over a live run.
    if (!busy(caseId)) options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
  };
}
