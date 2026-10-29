import type { TriggerType } from "./types.js";

// Chrome lets an extension call captureVisibleTab about twice per second. One link click fires both
// a click and a navigation trigger, which was enough to hit that limit (#2255). A gap of 600 ms
// between captures keeps every burst under it.
export const AUTO_CAPTURE_MIN_GAP_MS = 600;

const RATE_LIMIT_MARKER = "MAX_CAPTURE_VISIBLE_TAB_CALLS_PER_SECOND";

export type Sleep = (ms: number) => Promise<void>;

const defaultSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * True for triggers the browser fires on its own (timer, tab switch, navigation, click). These
 * may be dropped or skipped silently. A manual or one-off capture is analyst-initiated: it is
 * never dropped and still reports why it could not run.
 */
export function isAutomaticTrigger(trigger: TriggerType, oneOff: boolean): boolean {
  return !oneOff && trigger !== "manual";
}

/** True when captureVisibleTab failed only because Chrome's per-second quota was exceeded. */
export function isCaptureRateLimitError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const message = (error as { message?: unknown }).message;
  return typeof message === "string" && message.includes(RATE_LIMIT_MARKER);
}

/**
 * Single-flight gate with a minimum gap between capture starts.
 *
 * - Automatic: runs only when nothing is in flight or waiting AND the gap since the last start
 *   has passed; otherwise it returns `skipped` at once without running the task.
 * - Manual: never dropped. It queues behind any in-flight capture, waits out the rest of the gap,
 *   then runs.
 */
export class CaptureGate {
  private tail: Promise<void> = Promise.resolve();
  private pending = 0;
  private lastStart = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly minGapMs: number = AUTO_CAPTURE_MIN_GAP_MS,
    private readonly now: () => number = () => Date.now(),
    private readonly sleep: Sleep = defaultSleep,
  ) {}

  run<T>(automatic: boolean, task: () => Promise<T>, skipped: T): Promise<T> {
    if (automatic && (this.pending > 0 || this.now() - this.lastStart < this.minGapMs)) {
      return Promise.resolve(skipped);
    }
    return this.enqueue(task, !automatic);
  }

  private enqueue<T>(task: () => Promise<T>, waitForGap: boolean): Promise<T> {
    this.pending += 1;
    const result = this.tail
      .then(async () => {
        if (waitForGap) {
          const wait = this.minGapMs - (this.now() - this.lastStart);
          if (wait > 0) await this.sleep(wait);
        }
        this.lastStart = this.now();
        return task();
      })
      .finally(() => { this.pending -= 1; });
    this.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

/** What the gated part of a capture produced: a snapshot to upload, or a final answer (#2255). */
export type SnapshotOutcome<S, R> = { snapshot: S } | { result: R };

/**
 * Take the tab snapshot through the gate, then upload it OUTSIDE the gate (#2255).
 *
 * The gate used to wrap the whole capture, upload and queue drain included, so a slow or stalled
 * companion held it for the whole network round trip and every automatic screenshot in that time
 * was dropped — never captured, never queued. Only the snapshot (tab lookup + captureVisibleTab)
 * needs the single-flight and the minimum gap; uploads may overlap one another (each is its own
 * POST, failed ones are enqueued independently, and the queue guards its own drain).
 */
export async function captureThroughGate<S, R>(
  gate: CaptureGate,
  automatic: boolean,
  takeSnapshot: () => Promise<SnapshotOutcome<S, R>>,
  upload: (snapshot: S) => Promise<R>,
  skipped: R,
): Promise<R> {
  const outcome = await gate.run<SnapshotOutcome<S, R>>(automatic, takeSnapshot, { result: skipped });
  return "snapshot" in outcome ? upload(outcome.snapshot) : outcome.result;
}
