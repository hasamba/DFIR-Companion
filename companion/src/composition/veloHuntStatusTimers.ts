/**
 * The Velociraptor hunt STATUS POLLER's timers — one of the two clocks described in the header of
 * composition/veloHunts.ts, split out of it when that file reached the 800-line ceiling (#770).
 *
 * The DECISION is not here and never was: integrations/velociraptor/huntStatusPoller.ts holds the
 * pure `pollHuntStatusOnce`, which is why that half is unit-tested with no Velociraptor and no
 * network. What lives here is the stateful half around it — the timer map, the self-rescheduling
 * tick, and the restart resume — so the two halves of the same poller now sit in two files instead
 * of one pure module and one 800-line neighbour.
 *
 * Every ~30s it asks Velociraptor what a hunt is ACTUALLY doing, which is what makes a hunt stopped
 * or deleted in the GUI collect promptly instead of waiting out a 4-hour fixed delay. Resumed from
 * disk at startup, so it also self-heals the fixed-delay auto-collect timer a restart destroyed.
 */
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import type { VeloHuntJob } from "../analysis/veloHuntStore.js";
import { pollHuntStatusOnce, type HuntPollDeps } from "../integrations/velociraptor/huntStatusPoller.js";
import { getServerLogger, logLine } from "../logging/serverLogger.js";
import { generationOf, runInCaseScope } from "../storage/caseIncarnation.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";
import { unavailableServerClients } from "./serverSetClients.js";
import { createTickVelo } from "./veloCaseClient.js";
import { failedCollect } from "./veloHuntCompleteness.js";
import { holdImportsDuring } from "./veloHuntRecovery.js";
import { ALL_CASES, type ImportLock } from "../analysis/importLock.js";

export interface VeloHuntStatusTimersDeps {
  store: CaseStore;
  options: AppOptions;
  /**
   * Start a collect for a hunt Velociraptor reports terminal. Injected rather than imported: the
   * collect owns this poller's lifecycle (it stops the poll when it starts), so the dependency runs
   * both ways and only one of the two directions can be a module import.
   */
  startVeloHuntCollect: (caseId: string, huntId: string) => void;
  /** Is a collect of this hunt running in THIS process right now (`collectingNow`, #2403)? */
  isCollecting: (caseId: string, huntId: string) => boolean;
  /**
   * #2851: settle the rows a collect cut off while IMPORTING left in the case
   * (composition/veloHuntRecovery.ts). Optional: without it the restart only marks the job.
   * `uploadFiles`: the uploaded reports' stored names the job recorded (#2852); `batchId`: the batch id
   * its settle stamps with (#2888), so rows stamped before the restart and never tagged are found too.
   */
  settleInterrupted?: (
    caseId: string,
    huntId: string,
    uploadFiles?: readonly string[],
    batchId?: string,
  ) => Promise<unknown>;
  /** #2851 review: holds imports while start-up recovery runs (`holdImportsDuring`). */
  importLock?: Pick<ImportLock, "hold">;
}

export interface VeloHuntStatusTimers {
  scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void;
  pollVeloHuntStatus(caseId: string, huntId: string): Promise<void>;
  stopVeloHuntStatusPoll(caseId: string, huntId: string): void;
  /** Cancel every pending status poll of one case (its server set changed). */
  stopVeloHuntStatusPollsForCase(caseId: string): void;
  /** Re-arm status polling for every non-terminal hunt across all cases (server restart). */
  /**
   * `startup: true` ONLY at server start (#2403): first mark interrupted every hunt stored as
   * "collecting" that no collect in this process owns — it was left by a process that died
   * mid-collect, and its card would say "importing" forever. Reconnect calls this WITHOUT it: a
   * collect running then is real.
   */
  resumeVeloHuntStatusPolls(opts?: { startup?: boolean }): Promise<void>;
}

export const INTERRUPTED_COLLECT_MESSAGE =
  "Interrupted by a server restart while collecting — the results are still on the Velociraptor " +
  "server. Press Collect now to collect them again.";

/**
 * #2849: the sentence for a collect the restart cut off while it was IMPORTING. Each artifact is in
 * the case as soon as its import returns and nothing takes it out at a restart, while the import
 * record and the Undo entry are written once, after the last one — so "collect them again" alone
 * reads as an untouched case. The job stores no per-artifact progress, so it names no artifact.
 */
export const INTERRUPTED_IMPORT_MESSAGE =
  "Interrupted by a server restart while importing — some of this collect's rows may already be " +
  "in the case, with no import record and no Undo entry. The results are still on the Velociraptor " +
  "server. Press Collect now to collect them again; its count covers only rows not already in the case.";

export function createVeloHuntStatusTimers(deps: VeloHuntStatusTimersDeps): VeloHuntStatusTimers {
  const { store, options, startVeloHuntCollect, isCollecting } = deps;
  // Every tick resolves the case's server set again, so a set edit applies on the next poll.
  const tickVelo = createTickVelo(
    () => options.serverClients ?? unavailableServerClients,
    logLine,
    "velo-hunt-status",
  );

  // Keyed `caseId huntId`, self-rescheduling setTimeout (not setInterval, so a slow poll can't
  // overlap itself), .unref()'d so a pending poll never blocks process exit. Interval from
  // DFIR_VELO_HUNT_POLL_S (default 30s, clamped 5-300). Mirrors the live-monitor scheduling.
  // #1866: keyed by (case, generation, hunt id) and cleared on delete, so a deleted case's poll
  // chain never re-arms or cancels a same-id successor's hunt poll.
  const veloStatusTimers = new CaseKeyedMap<NodeJS.Timeout>(
    () => store.casesRoot,
    (timer) => clearTimeout(timer),
  );

  // One status-poll tick: load the job, poll (pure pollHuntStatusOnce), persist + broadcast only on
  // an actual status change, then either reschedule, trigger an immediate collect, or stop. Never
  // throws (pollHuntStatusOnce itself never throws; store I/O failures are best-effort).
  async function pollVeloHuntStatus(caseId: string, huntId: string): Promise<void> {
    const huntStore = options.veloHuntStore;
    if (!huntStore) {
      veloStatusTimers.delete(caseId, huntId);
      return;
    }
    let job: VeloHuntJob | null = null;
    try {
      job = await huntStore.get(caseId, huntId);
    } catch (err) {
      logLine(`[velo-hunt-status] failed to load hunt ${huntId} for status poll: ${(err as Error).message}`);
    }
    if (!job) {
      veloStatusTimers.delete(caseId, huntId);
      return;
    }
    // No client for this case right now: skip this tick and keep polling, so it resumes once the
    // case's server set is fixed.
    const client = tickVelo(caseId);
    if (!client) {
      if (veloStatusTimers.has(caseId, huntId)) scheduleVeloHuntStatusPoll(caseId, huntId);
      return;
    }

    const pollDeps: HuntPollDeps = { getState: (id) => client.huntStatus(id), log: logLine };
    const outcome = await pollHuntStatusOnce(job, pollDeps);
    // #2403: the answer is only good if nothing moved the hunt on while this poll waited — most of all
    // a collect, which stops the timer but cannot stop a poll already on the network. A stale poll
    // neither writes its status nor acts on it.
    const startedFrom = job.status;
    const stale = (cur: VeloHuntJob): boolean =>
      cur.status !== startedFrom || cur.collectPhase !== undefined || isCollecting(caseId, huntId);
    let wasStale = false;
    try {
      const stored = await huntStore.update(caseId, huntId, (cur) => {
        if (stale(cur)) {
          wasStale = true;
          return null;
        }
        return outcome.job.status === cur.status ? null : { ...cur, status: outcome.job.status };
      });
      if (!stored) wasStale = true; // forgotten while the poll waited
    } catch {
      /* best-effort, as before: a failed write does not stop the poll */
    }
    // Stale: leave the timers alone. A collect already stopped them, a forgotten hunt's next tick ends
    // itself, and an overlapping poll that DID record the change owns the re-arm it just made.
    if (wasStale) return;
    if (outcome.job.status !== startedFrom) options.onVeloHunt?.(caseId);

    if (outcome.action === "reschedule") {
      if (veloStatusTimers.has(caseId, huntId)) scheduleVeloHuntStatusPoll(caseId, huntId);
    } else if (outcome.action === "collect") {
      veloStatusTimers.delete(caseId, huntId);
      startVeloHuntCollect(caseId, huntId); // clears the fixed-delay timer + status poll itself
    } else {
      veloStatusTimers.delete(caseId, huntId);
    }
  }

  // Arm (or re-arm) a hunt's status-poll timer for one interval out. Clears any existing timer first
  // so start is idempotent. Clamped 5s..300s so a bad env value can't busy-loop or stall forever.
  function scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const existing = veloStatusTimers.get(caseId, huntId);
    if (existing) clearTimeout(existing);
    const seconds = Math.min(300, Math.max(5, Number(process.env.DFIR_VELO_HUNT_POLL_S) || 30));
    // #1855: the chain of polls runs as work of the case incarnation that armed it.
    const poll = () => void pollVeloHuntStatus(caseId, huntId);
    const timer = runInCaseScope(store.casesRoot, caseId, () => setTimeout(poll, seconds * 1000));
    timer.unref?.();
    veloStatusTimers.set(caseId, timer, huntId);
  }

  function stopVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const timer = veloStatusTimers.get(caseId, huntId);
    if (timer) clearTimeout(timer);
    veloStatusTimers.delete(caseId, huntId);
  }

  function stopVeloHuntStatusPollsForCase(caseId: string): void {
    veloStatusTimers.forget(caseId); // clears each timer, then drops the entries
  }

  // Re-arm status polling for every non-terminal hunt job across all cases (server restart). As a
  // side effect this also self-heals the pre-existing "fixed-delay auto-collect timer is lost on
  // restart" gap: a resumed status poll will detect STOPPED/ARCHIVED on its own and trigger the
  // collect even though the original setTimeout is gone. Best-effort per case.
  async function resumeVeloHuntStatusPolls(opts: { startup?: boolean } = {}): Promise<void> {
    const huntStore = options.veloHuntStore;
    if (!huntStore) return;
    let settling: Promise<void>[] = [];
    if (opts.startup) {
      const sweep = recoverInterruptedCollects();
      holdImportsDuring(deps.importLock, ALL_CASES, sweep); // armed before this function's first await
      settling = await sweep;
    }
    let cases: Awaited<ReturnType<typeof store.listCases>> = [];
    try {
      cases = await store.listCases();
    } catch {
      return;
    }
    let resumed = 0;
    for (const c of cases) {
      try {
        for (const job of await huntStore.list(c.caseId)) {
          if (job.status === "running" || job.status === "unreachable") {
            // #1866: armed as work of the incarnation just listed.
            runInCaseScope(
              store.casesRoot,
              c.caseId,
              () => scheduleVeloHuntStatusPoll(c.caseId, job.huntId),
              generationOf(c),
            );
            resumed++;
          }
        }
      } catch {
        /* skip this case */
      }
    }
    if (resumed > 0)
      logLine(
        `[velo-hunt-status] resumed status polling for ${resumed} hunt(s) across ${cases.length} case(s)`,
      );
    await Promise.all(settling); // each catches its own failure; polls were armed without waiting
  }

  /**
   * #2851: started only AFTER the job is marked, so a settle that dies (often the same out-of-memory
   * kill) is not tried again at every start; the #2849 sentence still tells the analyst. Detached
   * from the sweep — the server serves and the polls re-arm meanwhile — and run as work of the case
   * incarnation just listed. Never rejects: a failure is logged with the case and hunt id.
   */
  function settleInterruptedImport(
    caseId: string,
    huntId: string,
    generation: string,
    marks: Pick<VeloHuntJob, "importingUploads" | "importingBatchId">,
  ): Promise<void> {
    const settle = deps.settleInterrupted;
    if (!settle) return Promise.resolve();
    const run = () => settle(caseId, huntId, marks.importingUploads, marks.importingBatchId);
    const settled = runInCaseScope(store.casesRoot, caseId, run, generation);
    holdImportsDuring(deps.importLock, caseId, settled); // set while the all-case hold is still up
    return settled.then(
      () => undefined,
      (err: unknown) =>
        getServerLogger().warn(
          `[velo-hunt] ${caseId}: settling hunt ${huntId}'s interrupted import failed: ${(err as Error)?.message ?? String(err)}`,
          { caseId },
        ),
    );
  }

  async function recoverInterruptedCollects(): Promise<Promise<void>[]> {
    const settling: Promise<void>[] = [];
    const huntStore = options.veloHuntStore;
    if (!huntStore) return settling;
    let cases: Awaited<ReturnType<typeof store.listCases>> = [];
    try {
      cases = await store.listCases();
    } catch {
      return settling;
    }
    let marked = 0;
    for (const c of cases) {
      try {
        const jobs = await huntStore.list(c.caseId);
        for (const { huntId } of jobs.filter((j) => j.status === "collecting")) {
          if (isCollecting(c.caseId, huntId)) continue;
          // #1866: as work of the incarnation just listed. The predicate is re-checked under the
          // store lock, so a collect started during this sweep is never overwritten.
          // #2849: chosen HERE from the stored phase, not inside failedCollect — the in-process
          // failure path also sees "importing" when the first artifact is refused and nothing was kept.
          let message: string | undefined;
          const stored = await runInCaseScope(
            store.casesRoot,
            c.caseId,
            () =>
              huntStore.update(c.caseId, huntId, (cur) => {
                if (cur.status !== "collecting" || isCollecting(c.caseId, huntId)) return null;
                message =
                  cur.collectPhase === "importing" ? INTERRUPTED_IMPORT_MESSAGE : INTERRUPTED_COLLECT_MESSAGE;
                return failedCollect(cur, message);
              }),
            generationOf(c),
          );
          if (stored?.status === "error" && message !== undefined && stored.error === message) {
            marked++;
            options.onVeloHunt?.(c.caseId);
            if (message === INTERRUPTED_IMPORT_MESSAGE)
              settling.push(settleInterruptedImport(c.caseId, huntId, generationOf(c), stored));
          }
        }
      } catch {
        /* skip this case */
      }
    }
    if (marked > 0)
      logLine(
        `[velo-hunt] ${marked} hunt collect(s) were interrupted by the restart — marked for Collect now`,
      );
    return settling;
  }

  return {
    scheduleVeloHuntStatusPoll,
    pollVeloHuntStatus,
    stopVeloHuntStatusPoll,
    stopVeloHuntStatusPollsForCase,
    resumeVeloHuntStatusPolls,
  };
}
