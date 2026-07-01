import type { VeloHuntJob, VeloHuntStatus } from "../../analysis/veloHuntStore.js";

// Pure core of the Velociraptor hunt STATUS poller. Independent of the existing fixed-delay
// auto-collect timer (server.ts's veloHuntTimers): every tick asks Velociraptor for the hunt's
// real state so a hunt deleted/stopped in Velociraptor is reflected promptly instead of waiting
// out the fixed delay. Reading is injected, so this whole decision core is unit-tested with no
// Velociraptor binary and no network.

// Read a hunt's live state from Velociraptor. Returns null when Velociraptor has no record of the
// hunt at all (deleted) rather than an empty-state object. A present-but-unrecognized state string
// (state-vocabulary drift — a future Velociraptor version, a typo) is NOT rejected: it's treated as
// "still running" (logged, not silently absorbed) so an operator can spot it without the poller itself
// getting stuck.
export type HuntStateReader = (huntId: string) => Promise<{ state: string } | null>;

export interface HuntPollDeps {
  getState: HuntStateReader;
  log?: (msg: string) => void;
}

export type HuntPollOutcome =
  | { action: "reschedule"; job: VeloHuntJob }   // still running (or recovered from unreachable) — poll again later
  | { action: "collect"; job: VeloHuntJob }      // Velociraptor reports STOPPED/ARCHIVED — collect now, stop polling
  | { action: "stop"; job: VeloHuntJob };         // deleted, or already terminal — stop polling, nothing more to do

// A job in any of these statuses owns its own next transition elsewhere (an import in flight, or
// already finished/failed/confirmed-gone) — the status poller has nothing useful left to check.
const TERMINAL_STATUSES: readonly VeloHuntStatus[] = ["collecting", "imported", "error", "deleted"];

// Velociraptor hunt states that mean "done collecting, ready to import" (case-insensitive).
const DONE_STATES = new Set(["STOPPED", "ARCHIVED"]);

// One poll cycle. NEVER throws: a getState failure is captured into the returned job's status
// ("unreachable") + logged, and polling continues (transient — a network blip or a Velociraptor
// restart shouldn't be read as "deleted"). A confirmed "hunt not found" response is the only way a
// job reaches "deleted".
export async function pollHuntStatusOnce(job: VeloHuntJob, deps: HuntPollDeps): Promise<HuntPollOutcome> {
  if (TERMINAL_STATUSES.includes(job.status)) return { action: "stop", job };

  try {
    const result = await deps.getState(job.huntId);
    if (!result) return { action: "stop", job: { ...job, status: "deleted" } };
    const state = result.state.toUpperCase();
    if (DONE_STATES.has(state)) return { action: "collect", job };
    if (state !== "RUNNING" && state !== "PAUSED") {
      deps.log?.(`[velo-hunt-status] hunt ${job.huntId} reported unrecognized state "${result.state}" — treating as still running`);
    }
    return { action: "reschedule", job: { ...job, status: "running" } };
  } catch (err) {
    deps.log?.(`[velo-hunt-status] poll failed for hunt ${job.huntId}: ${(err as Error).message}`);
    return { action: "reschedule", job: { ...job, status: "unreachable" } };
  }
}
