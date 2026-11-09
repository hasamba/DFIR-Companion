// Small pure helpers for the durable job manager (jobManager.ts), split out to keep it under the
// file-size ratchet (#384). No state lives here.

import type { Job, JobPriority, JobTable } from "./jobRegistry.js";

export type Deferred = {
  promise: Promise<void>;
  resolve: () => void;
  reject: (error: Error) => void;
  /**
   * Whether resolve/reject has already been called. Read SYNCHRONOUSLY by the supersede path to
   * answer "has this job's ledger INSERT landed yet" — a question a Promise cannot answer without
   * awaiting, and awaiting is what the supersede cannot do (register() is synchronous).
   */
  settled: () => boolean;
};

export function deferred(): Deferred {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  // Cancelling a job that never started REJECTS these (see cancel()), possibly before anyone waits:
  // resume() attaches runResumedJob's handler only after the ledger write. Unhandled, Node makes that
  // rejection fatal. This keep-alive swallows nothing — .catch() returns a NEW promise, and every
  // real awaiter of `ready` still sees the AbortError.
  promise.catch(() => {});
  let done = false;
  return {
    promise,
    resolve: () => {
      done = true;
      resolve();
    },
    reject: (error: Error) => {
      done = true;
      reject(error);
    },
    settled: () => done,
  };
}

export function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export function abortError(): Error {
  const error = new Error("job cancelled before it started");
  error.name = "AbortError";
  return error;
}

function priorityRank(priority: JobPriority): number {
  if (priority === "high") return 2;
  if (priority === "normal") return 1;
  return 0;
}

/** The next queued job global and per-case capacity admit: priority, then queue order, then id. */
export function nextAdmissibleJob(
  table: JobTable,
  globalConcurrency: number,
  perCaseConcurrency: number,
  isHeld: (caseId: string | null) => boolean = () => false, // a case held without a row (caseHolds.ts)
): Job | undefined {
  const running = table.jobs.filter((job) => job.status === "running");
  if (running.length >= globalConcurrency) return undefined;
  const runningByScope = new Map<string, number>();
  for (const job of running) {
    const scope = job.caseId ?? "global";
    runningByScope.set(scope, (runningByScope.get(scope) ?? 0) + 1);
  }
  return table.jobs
    .filter((job) => {
      if (job.status !== "queued" || isHeld(job.caseId)) return false;
      return (runningByScope.get(job.caseId ?? "global") ?? 0) < perCaseConcurrency;
    })
    .sort(
      (a, b) =>
        priorityRank(b.priority) - priorityRank(a.priority) ||
        a.queuedAt.localeCompare(b.queuedAt) ||
        a.id.localeCompare(b.id),
    )[0];
}

// A transition applied in memory whose ledger write failed (#2409). The row keeps its old status on
// disk until a restart, where restore() turns a queued/running row into `interrupted` — so a job
// that ended during a ledger outage may offer Resume then.
export function ledgerWriteFailure(job: Job, ledgerStatus: string, failure: Error): Error {
  return new Error(
    `job ${job.id} is ${job.status} but the job ledger write failed (${failure.message}); ` +
      `the ledger still shows it ${ledgerStatus} until restart`,
  );
}

/** Run a side-channel callback (a WebSocket push, an error report); its own failure is swallowed. */
export function callQuietly(fn: () => void): void {
  try {
    fn();
  } catch {
    // The caller's operation must not fail because a listener did.
  }
}
