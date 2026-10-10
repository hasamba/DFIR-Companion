// #1915: concurrent requests for the same case's report projection share one load.
//
// The dashboard opens with about ten report projections of one case at once (swimlane, timeline
// gaps, IOC sources, anomalies, ...). Each used to run its own whole-case load and filter. They now
// share one — but never one that may be older than the request:
//
//   - A load is joinable only while it is QUEUED: waiting for the case's previous load to end, or for
//     a permit from the process-wide limiter (analysis/wholeCaseLoadLimit.ts).
//   - Once it holds a permit it starts reading and is never joined again. It may have read the case
//     before an edit a new caller already saw finish, and handing that result out would put a
//     pre-edit view in a report (an integrity bug, not a performance one). The next caller queues a
//     new load, which starts when this one ends.
//
// So every caller receives data read after it arrived, and one case costs at most one reading and one
// queued load, whatever the burst size. Nothing is kept here once a load settles (the slim report
// state is kept, keyed on an exact case revision, by reportLiteCache.ts, #2057). A failed load fails only
// its own callers; the queued load still makes its own fresh attempt.
//
// The load runs under the permit, which is re-entrant, so the StateStore.load inside it does not take
// a second one (no nested waits, no deadlock). A `read` must not call back into the same coalescer
// for the same case: it would wait for itself.
//
// The result is SHARED between callers: no caller may modify it (CLAUDE.md §5).
// tests/reports/filteredStateImmutable.test.ts runs every report projection over a deep-frozen state.

// Each caller may pass its request's abort signal (#1915 reopened). Leaving only stops THAT caller's
// wait; a load another caller still waits for is never cancelled. A QUEUED load whose every caller
// has left is dropped before it reads (analysis/abortable.ts JoinedSignal), and the next caller opens
// a fresh one. A caller with no signal pins the load: it can then never be cancelled.

import { wholeCaseLoads, type LoadLimiter } from "../analysis/wholeCaseLoadLimit.js";
import { JoinedSignal, abortError, untilAborted } from "../analysis/abortable.js";

interface Cohort<T> {
  promise: Promise<T>;
  joiners: JoinedSignal;
}

interface CaseLoads<T> {
  reading?: Promise<T>;
  queued?: Cohort<T>;
}

const ignore = (): void => undefined;

export class CaseLoadCoalescer<T> {
  private readonly cases = new Map<string, CaseLoads<T>>();

  constructor(private readonly limiter: LoadLimiter = wholeCaseLoads) {}

  /** Cases with a load reading or queued (0 when idle: nothing is kept after a load settles). */
  get size(): number {
    return this.cases.size;
  }

  load(caseId: string, read: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (signal?.aborted) return Promise.reject(abortError());
    const entry = this.cases.get(caseId) ?? this.open(caseId);
    const cohort = entry.queued ?? this.queue(caseId, entry, read);
    cohort.joiners.join(signal);
    return untilAborted(cohort.promise, signal);
  }

  private queue(caseId: string, entry: CaseLoads<T>, read: () => Promise<T>): Cohort<T> {
    const previous = entry.reading;
    // Every caller left while it was still queued: stop handing it out, so a newcomer starts afresh.
    const joiners = new JoinedSignal(() => {
      if (entry.queued === cohort) entry.queued = undefined;
    });
    const promise: Promise<T> = (async () => {
      // Always yields at least once, so `promise` is assigned before the callback below can run.
      await previous?.then(ignore, ignore);
      return this.limiter.run(() => {
        // Holding a permit: from here this load reads the case and stops being joinable.
        entry.queued = undefined;
        entry.reading = promise;
        return read();
      }, joiners.signal);
    })();
    const cohort: Cohort<T> = { promise, joiners };
    entry.queued = cohort;
    const settle = (): void => {
      if (entry.queued === cohort) entry.queued = undefined;
      if (entry.reading === promise) entry.reading = undefined;
      if (!entry.queued && !entry.reading && this.cases.get(caseId) === entry) {
        this.cases.delete(caseId);
      }
    };
    promise.then(settle, settle);
    return cohort;
  }

  private open(caseId: string): CaseLoads<T> {
    const entry: CaseLoads<T> = {};
    this.cases.set(caseId, entry);
    return entry;
  }
}
