// Background-job manager (#225) — impure wrapper around the pure jobRegistry.
//
// Owns the live in-memory JobTable, one AbortController per cancellable running job, a monotonic id
// counter and clock (injectable for tests), and the onJob WS-broadcast hook. Routes and the server
// closure call register/progress/finish/fail/cancel; the pure transitions do the bookkeeping.
//
// A cancellable job hands its caller an AbortSignal to thread into the AI provider / enrichment
// fetch (which already combine it with their own timeout via AbortSignal.any). Cancelling aborts
// that signal and marks the job cancelled — synthesis/enrichment only persist state on SUCCESS, so
// an aborted job leaves the investigation untouched by construction.

import {
  emptyJobTable,
  createJob,
  progressJob,
  finishJob,
  failJob,
  cancelJob,
  getJob,
  listJobs,
  capJobs,
  isTerminal,
  type Job,
  type JobKind,
  type JobTable,
} from "./jobRegistry.js";

export interface JobManagerOptions {
  // Fired on every job transition so the server can WS-broadcast job_changed to the case's clients.
  onJob?: (caseId: string) => void;
  // Ring-buffer cap on retained jobs (oldest terminal evicted first). Default 100.
  max?: number;
  // Injectable clock (tests pass a deterministic one). Defaults to wall-clock ISO.
  now?: () => string;
}

export interface RegisterInput {
  caseId: string;
  kind: JobKind;
  label?: string;
  detail?: string;
  cancellable?: boolean;
  // Cancel any other non-terminal job of the same kind for this case before starting this one —
  // e.g. two synthesis runs for the same case racing serves no purpose; the newer supersedes.
  exclusive?: boolean;
}

export interface RegisteredJob {
  jobId: string;
  // Present only for cancellable jobs — thread into the abortable network call.
  signal?: AbortSignal;
}

export type CancelResult =
  | { ok: true; job: Job }
  | { ok: false; reason: "unknown" | "terminal" | "not-cancellable" };

export class JobManager {
  private table: JobTable = emptyJobTable();
  private controllers = new Map<string, AbortController>();
  private counter = 0;
  private readonly onJob?: (caseId: string) => void;
  private readonly max: number;
  private readonly now: () => string;

  constructor(opts: JobManagerOptions = {}) {
    this.onJob = opts.onJob;
    this.max = opts.max ?? 100;
    this.now = opts.now ?? (() => new Date().toISOString());
  }

  register(input: RegisterInput): RegisteredJob {
    if (input.exclusive) {
      for (const j of listJobs(this.table, { caseId: input.caseId })) {
        if (j.kind === input.kind && !isTerminal(j.status)) this.cancel(j.id);
      }
    }
    const jobId = `job_${++this.counter}`;
    this.table = capJobs(
      createJob(this.table, {
        id: jobId,
        caseId: input.caseId,
        kind: input.kind,
        label: input.label,
        detail: input.detail,
        cancellable: input.cancellable ?? false,
        now: this.now(),
      }),
      this.max,
    );
    let signal: AbortSignal | undefined;
    if (input.cancellable) {
      const controller = new AbortController();
      this.controllers.set(jobId, controller);
      signal = controller.signal;
    }
    this.emit(input.caseId);
    return { jobId, signal };
  }

  progress(jobId: string, done: number, total: number, detail?: string): void {
    const before = getJob(this.table, jobId);
    this.table = progressJob(this.table, jobId, { done, total }, detail);
    if (before) this.emit(before.caseId);
  }

  finish(jobId: string): void {
    this.terminalTransition(jobId, (t) => finishJob(t, jobId, this.now()));
  }

  fail(jobId: string, error: unknown): void {
    const msg = error instanceof Error ? error.message : String(error);
    this.terminalTransition(jobId, (t) => failJob(t, jobId, msg, this.now()));
  }

  // Cancel a running cancellable job: abort its signal + mark cancelled. Idempotent-safe — the pure
  // guard rejects a re-terminate, and we surface why for the route (409 terminal / 422 not cancellable).
  cancel(jobId: string): CancelResult {
    const job = getJob(this.table, jobId);
    if (!job) return { ok: false, reason: "unknown" };
    if (isTerminal(job.status)) return { ok: false, reason: "terminal" };
    if (!job.cancellable) return { ok: false, reason: "not-cancellable" };
    this.controllers.get(jobId)?.abort();
    this.terminalTransition(jobId, (t) => cancelJob(t, jobId, this.now()));
    return { ok: true, job: getJob(this.table, jobId)! };
  }

  list(caseId?: string): Job[] {
    return listJobs(this.table, caseId ? { caseId } : {});
  }

  // Is any non-terminal job of this kind still running for the case? Callers use this to avoid
  // announcing a stale "idle" status after their own (superseded) job was cancelled out from under
  // them by a newer exclusive registration — see aiSynthesis.ts / scheduleSynthesis.
  hasActive(caseId: string, kind: JobKind): boolean {
    return listJobs(this.table, { caseId }).some((j) => j.kind === kind && !isTerminal(j.status));
  }

  get(jobId: string): Job | undefined {
    return getJob(this.table, jobId);
  }

  private terminalTransition(jobId: string, apply: (t: JobTable) => JobTable): void {
    const job = getJob(this.table, jobId);
    if (!job || isTerminal(job.status)) return;
    this.table = apply(this.table);
    this.controllers.delete(jobId); // release the controller once terminal
    this.emit(job.caseId);
  }

  private emit(caseId: string): void {
    try {
      this.onJob?.(caseId);
    } catch {
      /* a broadcast failure must never break the triggering operation */
    }
  }
}
