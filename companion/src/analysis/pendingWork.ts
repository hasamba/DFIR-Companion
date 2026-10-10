// #1915 (review follow-up): count the uncancellable work a request has started, so admission control
// (composition/heavyReadGate.ts) can keep the request's slot until that work settles, even after its
// client has gone.
//
// Freeing a slot the moment the socket closes let a burst of disconnecting clients start a new
// handler per slot while every abandoned one kept its whole-case load queued in
// analysis/wholeCaseLoadLimit.ts: 60 disconnects left 58 loads queued while the gate reported none.
//
// A tracker is AMBIENT (AsyncLocalStorage): the gate runs the request's handlers inside it, and work
// registered anywhere below — at any depth, after any await — is counted on it. Nothing else has to
// pass it along, so a route that forgets to pass its abort signal is still covered.
//
// Work registered outside a tracker (a background job, a test) runs exactly as before.

import { AsyncLocalStorage } from "node:async_hooks";

const trackers = new AsyncLocalStorage<WorkTracker>();

export class WorkTracker {
  private count = 0;
  private readonly idleChecks: Array<() => void> = [];

  /** Units of tracked work started and not yet settled. */
  get pending(): number {
    return this.count;
  }

  /** Runs `fn` with this tracker ambient: tracked work it starts, at any depth, is counted here. */
  run<T>(fn: () => T): T {
    return trackers.run(this, fn);
  }

  /** Counts one unit of work; the returned function ends it (idempotent). */
  begin(): () => void {
    this.count++;
    let ended = false;
    return () => {
      if (ended) return;
      ended = true;
      this.count--;
      if (this.count === 0) this.idleChecks.splice(0).forEach((check) => check());
    };
  }

  /**
   * Calls `onIdle` once nothing is pending. Checked after a macrotask, so the continuations of work
   * that just settled (an abandoned handler noticing its client is gone) run first.
   */
  whenIdle(onIdle: () => void): void {
    const check = (): void => {
      setImmediate(() => {
        if (this.count === 0) onIdle();
        else this.idleChecks.push(check);
      });
    };
    check();
  }
}

/** Runs `work`, counted on the ambient tracker (if any) until it settles. */
export async function trackedWork<T>(work: () => Promise<T>): Promise<T> {
  const tracker = trackers.getStore();
  if (!tracker) return work();
  const end = tracker.begin();
  try {
    return await work();
  } finally {
    end();
  }
}
