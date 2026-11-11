import { loadPendingHostDuplicates } from "../analysis/hostScopeLoad.js";
import { milestoneEvent, type NotificationEvent } from "../analysis/notifications.js";
import type { AppOptions } from "./appOptions.js";
import { currentGeneration, runInGenerationScope } from "../storage/caseIncarnation.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";

/**
 * When the import-time "Analysis on hold" check runs (#2584).
 *
 * The check (captureAnalysis.ts, notifyHostDuplicates) reads every host name the super-timeline
 * holds. That read is memoized until the rows change (#1881), but every import changes them, so a
 * check after every import was a whole super-timeline scan per file: O(n²) over a large drop, and,
 * because nothing awaits it, it overlapped the NEXT import — holding the SQLite reader threads and
 * the main thread while that import waited. On the SANS 504 S3 lab (3,872 small CloudTrail files)
 * it was the largest per-file cost growing with the case.
 *
 * So the import kicks are coalesced per case:
 *  - a check runs once the case has had no kick for the quiet period — a burst costs one check,
 *    after its last file;
 *  - a drop that never goes quiet is still checked once the oldest unchecked kick is the maximum
 *    wait old, so a long drop is not silent until it ends;
 *  - one check per case at a time: a kick that lands during a check is checked by a later run,
 *    timed by the same two deadlines (never back-to-back scans);
 *  - per case incarnation (CaseKeyedMap): a deleted case's pending check never runs and its running
 *    check delivers nothing, and a same-id successor starts clean;
 *  - timers are unref'd, and dispose() (server shutdown) cancels everything pending and drops the
 *    result of anything running.
 *
 * The AI-synthesis gate itself is untouched: synthesize() still consults the real gate on every run.
 */

/** No kick for this long → the case's check runs. */
export const HOST_DUPLICATE_NOTIFY_QUIET_MS = 2_000;
/** The oldest unchecked kick waits at most this long, quiet or not (a check still in flight aside). */
export const HOST_DUPLICATE_NOTIFY_MAX_WAIT_MS = 60_000;

export interface HostDuplicateNotifierDeps {
  casesRoot: () => string;
  /** Derive the hold notification for the case, or null when nothing is held. Runs in the case's scope. */
  check: (caseId: string) => Promise<NotificationEvent | null>;
  /** Send it. Called only while the case and the notifier are both still live. */
  deliver: (event: NotificationEvent) => void;
  quietMs?: number;
  maxWaitMs?: number;
  now?: () => number;
}

export interface HostDuplicateNotifier {
  /** Note that the case changed. Call from inside the case's scope, as resynthesizeInBackground does. */
  kick(caseId: string): void;
  /** Stop for good: clear every timer, ignore later kicks, deliver nothing still running. */
  dispose(): void;
}

interface SlotConfig {
  quietMs: number;
  maxWaitMs: number;
  now: () => number;
  casesRoot: () => string;
  /** Run the check and deliver its result unless the notifier or this slot is gone meanwhile. */
  run: (slot: CaseCheckSlot) => Promise<void>;
  /** The slot has nothing left to check: drop it from the map. */
  idle: (slot: CaseCheckSlot) => void;
}

/** One case incarnation's coalescing state: its deadlines, its timer and whether a check is running. */
class CaseCheckSlot {
  /** The oldest kick no check has started after yet; null when every kick is covered. */
  private pendingSince: number | null = null;
  private lastKickAt = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private running = false;
  private gone = false;

  constructor(
    readonly caseId: string,
    readonly generation: string,
    private readonly config: SlotConfig,
  ) {}

  get live(): boolean {
    return !this.gone;
  }

  kick(): void {
    const at = this.config.now();
    this.pendingSince ??= at;
    this.lastKickAt = at;
    if (!this.running) this.arm();
  }

  /** The case was deleted, or the notifier stopped: nothing pending runs, nothing running delivers. */
  forget(): void {
    this.gone = true;
    this.clearTimer();
  }

  private clearTimer(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private arm(): void {
    this.clearTimer();
    if (this.pendingSince === null || this.gone) return;
    const { quietMs, maxWaitMs, now } = this.config;
    const due = Math.min(this.lastKickAt + quietMs, this.pendingSince + maxWaitMs);
    const timer = setTimeout(() => void this.fire(), Math.max(0, due - now()));
    timer.unref?.();
    this.timer = timer;
  }

  private async fire(): Promise<void> {
    this.timer = null;
    if (this.gone || this.running) return;
    this.running = true;
    this.pendingSince = null;
    try {
      await this.config.run(this);
    } finally {
      this.running = false;
    }
    if (this.gone) return;
    if (this.pendingSince !== null)
      this.arm(); // kicked while the check ran
    else this.config.idle(this);
  }
}

export function createHostDuplicateNotifier(deps: HostDuplicateNotifierDeps): HostDuplicateNotifier {
  let disposed = false;
  const slots = new CaseKeyedMap<CaseCheckSlot>(deps.casesRoot, (slot) => slot.forget());
  const inScope = <T>(slot: CaseCheckSlot, fn: () => T): T =>
    runInGenerationScope(deps.casesRoot(), slot.caseId, slot.generation, fn);

  async function run(slot: CaseCheckSlot): Promise<void> {
    let event: NotificationEvent | null = null;
    try {
      event = await inScope(slot, () => deps.check(slot.caseId));
    } catch {
      return; // a side channel: a failed check is never an import failure
    }
    if (!event || disposed || !slot.live) return;
    try {
      deps.deliver(event);
    } catch {
      /* notifications never break an import */
    }
  }

  function idle(slot: CaseCheckSlot): void {
    inScope(slot, () => {
      if (slots.get(slot.caseId) === slot) slots.delete(slot.caseId);
    });
  }

  const config: SlotConfig = {
    quietMs: deps.quietMs ?? HOST_DUPLICATE_NOTIFY_QUIET_MS,
    maxWaitMs: deps.maxWaitMs ?? HOST_DUPLICATE_NOTIFY_MAX_WAIT_MS,
    now: deps.now ?? (() => Date.now()),
    casesRoot: deps.casesRoot,
    run,
    idle,
  };

  return {
    kick(caseId: string): void {
      if (disposed) return;
      let slot = slots.get(caseId);
      if (!slot) {
        slot = new CaseCheckSlot(caseId, currentGeneration(deps.casesRoot(), caseId), config);
        slots.set(caseId, slot);
      }
      slot.kick();
    },
    dispose(): void {
      disposed = true;
      for (const slot of slots.values()) slot.forget();
      slots.clear();
    },
  };
}

type HoldStores = Pick<
  AppOptions,
  | "stateStore"
  | "assetOverridesStore"
  | "hostDuplicateDismissalStore"
  | "velociraptorClientStore"
  | "superTimelineStore"
>;

/**
 * The "Analysis on hold" push for a case waiting on a merge decision, or null when none is pending.
 * The gate itself lives in synthesize(), but a case with AI disabled never reaches it — and that case
 * still needs to be told, so the same derivation runs here. Throws on a store failure; the notifier
 * swallows it (a notification is a side channel and never breaks an import).
 *
 * The per-channel `milestone` toggle defaults to TRUE because this may be the only push a blocked
 * case produces. An analyst can still opt a channel out; the dashboard badge remains the local
 * source of truth even when notifications are disabled or delivery fails.
 */
export async function hostDuplicateHoldEvent(
  options: HoldStores,
  caseId: string,
): Promise<NotificationEvent | null> {
  const dismissals = options.hostDuplicateDismissalStore;
  if (!dismissals || !options.stateStore || !options.assetOverridesStore) return null;
  const pending = await loadPendingHostDuplicates(
    {
      state: options.stateStore,
      assetOverrides: options.assetOverridesStore,
      dismissals,
      ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
      ...(options.superTimelineStore ? { superTimeline: options.superTimelineStore } : {}),
    },
    caseId,
  );
  if (!pending.length) return null;
  return milestoneEvent(
    caseId,
    `Analysis on hold: ${pending.length} possible duplicate host${pending.length === 1 ? "" : "s"}`,
    pending.map((p) => `• ${p.other} and ${p.canonical} may be the same machine`),
    new Date().toISOString(),
  );
}
