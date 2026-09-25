/**
 * An automatic synthesis kick waits for a RUNNING synthesis instead of superseding it (#1608).
 *
 * WHY. Every synthesis job is registered `exclusive`, so a newer registration aborts the older run
 * and frees the case's slot at once. The older run stops writing at its next stage boundary
 * (analysis/ai/synthesis.ts), but the model call it is inside does not stop being billed: an HTTP
 * provider closes the socket after the upstream has already started generating, and a CLI provider
 * may run on in a child process. Two paid calls, one result.
 *
 * For an AUTOMATIC kick (an import finishing, the last duplicate-host pair resolved, the live or
 * AI-on catch-up run) that trade is never worth it: synthesize() reads the case fresh, so one run
 * started after the current one finishes covers the new evidence too. The analyst's own
 * Re-synthesize still supersedes — they asked for a fresh run now.
 *
 * A QUEUED synthesis (still waiting for the case slot) has made no call yet, so superseding it
 * stays free; only a `running` job makes a kick wait.
 *
 * Kicks that arrive while one is already waiting collapse into it: one follow-up run per case, the
 * newest kick's start function winning.
 */
import type { Job } from "../analysis/jobRegistry.js";

export interface SynthesisDeferralDeps {
  /** The job registry. Absent → no exclusive supersede exists, so nothing ever waits. */
  jobManager?: { list(caseId: string): Job[]; get(jobId: string): Job | undefined };
  /** How long to wait between checks. */
  retryMs: number;
}

interface Waiter {
  start: () => void;
  onCancelled: () => void;
  /** Every running synthesis this waiter has waited on — to notice an analyst Cancel. */
  watched: Set<string>;
}

export interface SynthesisDeferral {
  /** Is a synthesis for this case running right now (its model call may already be paid for)? */
  running(caseId: string): boolean;
  /**
   * Start once no synthesis for the case is running. If one of the runs it waited on ends
   * `cancelled` — the analyst pressed Cancel — `onCancelled` runs instead: a Cancel must not be
   * followed by a fresh run the analyst never asked for.
   */
  defer(caseId: string, start: () => void, onCancelled: () => void): void;
}

export function createSynthesisDeferral(deps: SynthesisDeferralDeps): SynthesisDeferral {
  const waiting = new Map<string, Waiter>();

  function runningIds(caseId: string): string[] {
    const jobs = deps.jobManager?.list(caseId) ?? [];
    return jobs.filter((job) => job.kind === "synthesis" && job.status === "running").map((job) => job.id);
  }

  function running(caseId: string): boolean {
    return runningIds(caseId).length > 0;
  }

  function wasCancelled(waiter: Waiter): boolean {
    return [...waiter.watched].some((id) => deps.jobManager?.get(id)?.status === "cancelled");
  }

  function check(caseId: string): void {
    const waiter = waiting.get(caseId);
    if (!waiter) return;
    const ids = runningIds(caseId);
    ids.forEach((id) => waiter.watched.add(id));
    if (ids.length > 0) {
      wait(caseId);
      return;
    }
    waiting.delete(caseId);
    if (wasCancelled(waiter)) waiter.onCancelled();
    else waiter.start();
  }

  function wait(caseId: string): void {
    const timer = setTimeout(() => check(caseId), deps.retryMs);
    timer.unref?.();
  }

  function defer(caseId: string, start: () => void, onCancelled: () => void): void {
    const existing = waiting.get(caseId);
    if (existing) {
      // Collapse into the waiter already scheduled; the newest kick decides what starts.
      existing.start = start;
      existing.onCancelled = onCancelled;
      runningIds(caseId).forEach((id) => existing.watched.add(id));
      return;
    }
    waiting.set(caseId, { start, onCancelled, watched: new Set(runningIds(caseId)) });
    wait(caseId);
  }

  return { running, defer };
}
