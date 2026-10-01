// #1915: a cap on how many whole-case loads materialise at once, across every case in the process.
//
// A whole-case load (StateStore.load) copies every forensic row of the case out of SQLite onto the
// main thread. The dashboard opens with about ten report projections at once, and each one used to
// load its own copy: a 70k-event case took the server from 0.5 GB to 6.3 GB, and 50 concurrent reads
// were OOM-killed. Loads past the cap now wait their turn, in arrival order, instead of running
// together.
//
// This bounds the loads IN PROGRESS, not total memory: what a caller builds from a loaded state after
// its load returns is not counted.
//
// A permit is RE-ENTRANT: code already running under a permit (reports/stateLoadGate.ts takes one for
// a whole report projection) does not take a second one when it calls StateStore.load. Without that,
// two holders each waiting for a second permit would deadlock. A permit is released in `finally`,
// and work a holder leaves running after its release takes its own permit.

import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Two, to match the two SQLite read workers (caseSqliteWorkerPool.ts): two cases can still load in
 * parallel, while a burst for one case is shared by reports/stateLoadGate.ts.
 */
export const MAX_CONCURRENT_WHOLE_CASE_LOADS = 2;

interface Permit {
  held: boolean;
}

export class LoadLimiter {
  private running = 0;
  private readonly queue: Array<() => void> = [];
  private readonly permits = new AsyncLocalStorage<Permit>();

  constructor(private readonly max: number) {
    if (!Number.isInteger(max) || max < 1)
      throw new Error(`load limit must be a positive integer, got ${max}`);
  }

  /** Loads running now. */
  get active(): number {
    return this.running;
  }

  /** Loads waiting for a permit. */
  get waiting(): number {
    return this.queue.length;
  }

  async run<T>(load: () => Promise<T>): Promise<T> {
    if (this.permits.getStore()?.held) return load();
    await this.acquire();
    const permit: Permit = { held: true };
    try {
      return await this.permits.run(permit, load);
    } finally {
      permit.held = false;
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.running < this.max) {
      this.running++;
      return Promise.resolve();
    }
    // The permit passes straight from the releasing load to the next waiter (running is unchanged),
    // so a newcomer can never take it out of turn.
    return new Promise((resolve) => this.queue.push(resolve));
  }

  private release(): void {
    const next = this.queue.shift();
    if (next) next();
    else this.running--;
  }
}

/** The one limiter every StateStore.load in this process goes through. */
export const wholeCaseLoads = new LoadLimiter(MAX_CONCURRENT_WHOLE_CASE_LOADS);
