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
import { isTerminal } from "../analysis/jobRegistry.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";

export interface ConclusionsOutOfDateDeps {
  store: CaseStore;
  options: AppOptions;
  /** Cases whose automatic synthesis is running right now (composition/captureAnalysis.ts). */
  synthInFlight: () => { has(caseId: string): boolean };
}

/** Mark a case's conclusions out of date. Never throws: the change it follows has already landed. */
export type MarkConclusionsOutOfDate = (caseId: string, reason: string) => Promise<void>;

/** Re-read the header pill with no marker written — the same idle refresh, skipped while busy. */
export type RefreshAiStatus = (caseId: string) => void;

/** Builds the idle refresh both the marker and a marker-less change (a cleared Presidio gate) use. */
export function createAiStatusRefresh(deps: Omit<ConclusionsOutOfDateDeps, "store">): RefreshAiStatus {
  const { options } = deps;

  /** Is anything already working on this case? Its own terminal status will refresh the pill. */
  function busy(caseId: string): boolean {
    if (deps.synthInFlight().has(caseId)) return true;
    const jobs = options.jobManager?.list(caseId) ?? [];
    return jobs.some((job) => !isTerminal(job.status));
  }

  // The dashboard answers a terminal "idle" by re-reading GET /ai-state and by clearing any
  // "…re-synthesizing" status line. Skipped while work is running, so it cannot paint "idle" over a
  // live run.
  return function refreshAiStatus(caseId: string): void {
    if (!busy(caseId)) options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
  };
}

export function createConclusionsOutOfDate(deps: ConclusionsOutOfDateDeps): MarkConclusionsOutOfDate {
  const { store, options } = deps;
  const meta = options.synthMetaStore ?? new SynthMetaStore(store);
  const refresh = createAiStatusRefresh(deps);

  return async function markConclusionsOutOfDate(caseId: string, reason: string): Promise<void> {
    try {
      await meta.markOutOfDate(caseId, reason);
    } catch (err) {
      // Logged, not thrown: the analyst's change is saved, and failing the request over the marker
      // would tell them it was not. The pill then stays on its last state until the next run.
      warnLine(`[synthesis] ${caseId}: could not mark conclusions out of date: ${(err as Error).message}`);
      return;
    }
    refresh(caseId); // GET /ai-state now reports the marker
  };
}
