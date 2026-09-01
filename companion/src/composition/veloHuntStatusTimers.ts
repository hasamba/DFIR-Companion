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
import { logLine } from "../logging/serverLogger.js";

export interface VeloHuntStatusTimersDeps {
  store: CaseStore;
  options: AppOptions;
  /**
   * Start a collect for a hunt Velociraptor reports terminal. Injected rather than imported: the
   * collect owns this poller's lifecycle (it stops the poll when it starts), so the dependency runs
   * both ways and only one of the two directions can be a module import.
   */
  startVeloHuntCollect: (caseId: string, huntId: string) => void;
}

export interface VeloHuntStatusTimers {
  scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void;
  pollVeloHuntStatus(caseId: string, huntId: string): Promise<void>;
  stopVeloHuntStatusPoll(caseId: string, huntId: string): void;
  /** Re-arm status polling for every non-terminal hunt across all cases (server restart). */
  resumeVeloHuntStatusPolls(): Promise<void>;
}

export function createVeloHuntStatusTimers(deps: VeloHuntStatusTimersDeps): VeloHuntStatusTimers {
  const { store, options, startVeloHuntCollect } = deps;

  // Keyed `caseId huntId`, self-rescheduling setTimeout (not setInterval, so a slow poll can't
  // overlap itself), .unref()'d so a pending poll never blocks process exit. Interval from
  // DFIR_VELO_HUNT_POLL_S (default 30s, clamped 5-300). Mirrors the live-monitor scheduling.
  const veloStatusTimers = new Map<string, NodeJS.Timeout>();
  const statusKey = (caseId: string, huntId: string): string => `${caseId} ${huntId}`;

  // One status-poll tick: load the job, poll (pure pollHuntStatusOnce), persist + broadcast only on
  // an actual status change, then either reschedule, trigger an immediate collect, or stop. Never
  // throws (pollHuntStatusOnce itself never throws; store I/O failures are best-effort).
  async function pollVeloHuntStatus(caseId: string, huntId: string): Promise<void> {
    const huntStore = options.veloHuntStore;
    const client = options.velociraptorClient;
    if (!huntStore || !client) {
      veloStatusTimers.delete(statusKey(caseId, huntId));
      return;
    }
    let job: VeloHuntJob | null = null;
    try {
      job = await huntStore.get(caseId, huntId);
    } catch (err) {
      logLine(`[velo-hunt-status] failed to load hunt ${huntId} for status poll: ${(err as Error).message}`);
    }
    if (!job) {
      veloStatusTimers.delete(statusKey(caseId, huntId));
      return;
    }

    const pollDeps: HuntPollDeps = { getState: (id) => client.huntStatus(id), log: logLine };
    const outcome = await pollHuntStatusOnce(job, pollDeps);
    if (outcome.job.status !== job.status) {
      try {
        await huntStore.upsert(caseId, outcome.job);
      } catch {
        /* best-effort */
      }
      options.onVeloHunt?.(caseId);
    }

    if (outcome.action === "reschedule") {
      if (veloStatusTimers.has(statusKey(caseId, huntId))) scheduleVeloHuntStatusPoll(caseId, huntId);
    } else if (outcome.action === "collect") {
      veloStatusTimers.delete(statusKey(caseId, huntId));
      startVeloHuntCollect(caseId, huntId); // clears the fixed-delay timer + status poll itself
    } else {
      veloStatusTimers.delete(statusKey(caseId, huntId));
    }
  }

  // Arm (or re-arm) a hunt's status-poll timer for one interval out. Clears any existing timer first
  // so start is idempotent. Clamped 5s..300s so a bad env value can't busy-loop or stall forever.
  function scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const key = statusKey(caseId, huntId);
    const existing = veloStatusTimers.get(key);
    if (existing) clearTimeout(existing);
    const seconds = Math.min(300, Math.max(5, Number(process.env.DFIR_VELO_HUNT_POLL_S) || 30));
    const timer = setTimeout(() => {
      void pollVeloHuntStatus(caseId, huntId);
    }, seconds * 1000);
    timer.unref?.();
    veloStatusTimers.set(key, timer);
  }

  function stopVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const key = statusKey(caseId, huntId);
    const timer = veloStatusTimers.get(key);
    if (timer) clearTimeout(timer);
    veloStatusTimers.delete(key);
  }

  // Re-arm status polling for every non-terminal hunt job across all cases (server restart). As a
  // side effect this also self-heals the pre-existing "fixed-delay auto-collect timer is lost on
  // restart" gap: a resumed status poll will detect STOPPED/ARCHIVED on its own and trigger the
  // collect even though the original setTimeout is gone. Best-effort per case.
  async function resumeVeloHuntStatusPolls(): Promise<void> {
    const huntStore = options.veloHuntStore;
    if (!huntStore || !options.velociraptorClient) return;
    let cases: { caseId: string }[] = [];
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
            scheduleVeloHuntStatusPoll(c.caseId, job.huntId);
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
  }

  return {
    scheduleVeloHuntStatusPoll,
    pollVeloHuntStatus,
    stopVeloHuntStatusPoll,
    resumeVeloHuntStatusPolls,
  };
}
