// Durable background-job manager (#380).
//
// The pure registry owns state transitions. This wrapper persists each transition before
// broadcasting it, admits queued work under global/per-case limits, and turns orphaned queued or
// running rows into recoverable interrupted jobs during startup.

import { randomUUID } from "node:crypto";
import { sanitizeManifestValue } from "./analysisRunHash.js";
import { manifestValueSchema, type ManifestValue } from "./analysisRunTypes.js";
import type { JobLedgerStore } from "./jobLedgerStore.js";
import {
  emptyJobTable,
  createJob,
  startJob,
  checkpointJob,
  progressJob,
  warnJob,
  finishJob,
  failJob,
  cancelJob,
  interruptJob,
  requeueJob,
  allowJobCancellation,
  getJob,
  findJobByIdempotencyKey,
  listJobs,
  capJobs,
  capJobsByScope,
  dropJob,
  dropCaseJobs,
  isTerminal,
  type Job,
  type JobFailure,
  type JobKind,
  type JobPriority,
  type JobResourceBudget,
  type JobTable,
} from "./jobRegistry.js";

export interface JobManagerOptions {
  onJob?: (caseId: string | null) => void;
  onError?: (error: Error) => void;
  ledger?: JobLedgerStore;
  max?: number;
  globalConcurrency?: number;
  perCaseConcurrency?: number;
  now?: () => string;
  id?: () => string;
}

export interface RegisterInput {
  caseId?: string;
  kind: JobKind;
  label?: string;
  detail?: string;
  cancellable?: boolean;
  exclusive?: boolean;
  priority?: JobPriority;
  parentJobId?: string;
  idempotencyKey?: string;
  parameters?: Record<string, ManifestValue>;
  runManifestId?: string;
  maxRetries?: number;
  resourceBudget?: JobResourceBudget;
  resumable?: boolean;
}

export interface RegisteredJob {
  jobId: string;
  signal?: AbortSignal;
  /** Resolves once the queued row itself is committed, before it necessarily starts. */
  durable: Promise<void>;
  /** Resolves only after the queued/running row is durable and capacity admits the work. */
  ready: Promise<void>;
  /** True when an idempotency key returned an existing job instead of creating work. */
  reused: boolean;
}

export type CancelResult =
  { ok: true; job: Job } | { ok: false; reason: "unknown" | "terminal" | "not-cancellable" };

export type ResumeResult =
  | { ok: true; job: Job }
  | {
      ok: false;
      reason: "unknown" | "not-interrupted" | "not-resumable" | "retry-exhausted";
    };

export interface FailureOptions {
  code?: string;
  retryable?: boolean;
}

export interface CheckpointInput {
  done: number;
  total: number;
  detail?: string;
  cursor?: unknown;
}

type Deferred = {
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

type ResumeHandler = (job: Job, signal?: AbortSignal) => Promise<void>;
type ResumeHandlerOptions = {
  cancellable?: (job: Job) => boolean;
};
type ResumeHandlerRegistration = {
  handler: ResumeHandler;
  options: ResumeHandlerOptions;
};

function deferred(): Deferred {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  // Cancelling a job that never started REJECTS these (see cancel()), and the reject can land
  // before anyone is waiting: resume() publishes its admission into this.admissions and only
  // attaches runResumedJob's handler after the ledger write returns. A rejection with no handler
  // at that moment is an unhandled rejection, which Node makes fatal — one cancel would take the
  // whole server down mid-investigation. This keep-alive handler makes the rejection safe to
  // observe late, or never. It swallows nothing: .catch() returns a NEW promise and the original
  // still rejects, so every real awaiter of `ready` still sees the AbortError.
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

function abortError(): Error {
  const error = new Error("job cancelled before it started");
  error.name = "AbortError";
  return error;
}

function priorityRank(priority: JobPriority): number {
  if (priority === "high") return 2;
  if (priority === "normal") return 1;
  return 0;
}

export class JobManager {
  private table: JobTable = emptyJobTable();
  /**
   * Answers "which model runs this job" for every registration. Installed rather than constructed
   * because runtimeStores.ts builds this manager before the pipeline exists; createApp holds both.
   * Unset in a minimal wiring, and every job then simply carries no model.
   */
  private modelFor?: (input: RegisterInput) => string | undefined;
  private readonly controllers = new Map<string, AbortController>();
  private readonly admissions = new Map<string, Deferred>();
  private readonly durabilities = new Map<string, Deferred>();
  private readonly budgetTimers = new Map<string, NodeJS.Timeout>();
  private readonly resumeHandlers = new Map<JobKind, ResumeHandlerRegistration>();
  private readonly onJob?: (caseId: string | null) => void;
  private readonly onError?: (error: Error) => void;
  private readonly ledger?: JobLedgerStore;
  private readonly max: number;
  private readonly globalConcurrency: number;
  private readonly perCaseConcurrency: number;
  private readonly now: () => string;
  private readonly id: () => string;
  private readonly initialization: Promise<void>;
  private initializationError: Error | null = null;
  private scheduling: Promise<void> = Promise.resolve();

  constructor(opts: JobManagerOptions = {}) {
    this.onJob = opts.onJob;
    this.onError = opts.onError;
    this.ledger = opts.ledger;
    this.max = Math.max(1, Math.floor(opts.max ?? 100));
    this.globalConcurrency = Math.max(
      1,
      Math.floor(opts.globalConcurrency ?? (opts.ledger ? 4 : Number.MAX_SAFE_INTEGER)),
    );
    this.perCaseConcurrency = Math.max(
      1,
      Math.floor(opts.perCaseConcurrency ?? (opts.ledger ? 1 : Number.MAX_SAFE_INTEGER)),
    );
    this.now = opts.now ?? (() => new Date().toISOString());
    let sequence = 0;
    this.id = opts.id ?? (opts.ledger ? () => `job_${randomUUID()}` : () => `job_${++sequence}`);
    this.initialization = this.restore().catch((error: unknown) => {
      this.initializationError = error instanceof Error ? error : new Error(String(error));
      this.reportError(this.initializationError);
    });
  }

  async ready(): Promise<void> {
    await this.initialization;
    if (this.initializationError) throw this.initializationError;
  }

  /** Install the "which model runs this job" resolver. Called once, by createApp. */
  useModelResolver(resolve: (input: RegisterInput) => string | undefined): void {
    this.modelFor = resolve;
  }

  register(input: RegisterInput): RegisteredJob {
    const caseId = input.caseId ?? null;
    const existing = this.reusedRegistration(input, caseId);
    if (existing) return existing;
    this.supersedeExclusiveJobs(input, caseId);
    const jobId = this.appendQueuedJob(input, caseId);
    return this.prepareRegistration(jobId, input);
  }

  private reusedRegistration(input: RegisterInput, caseId: string | null): RegisteredJob | undefined {
    if (!input.idempotencyKey) return undefined;
    const existing = findJobByIdempotencyKey(this.table, caseId, input.idempotencyKey);
    if (!existing) return undefined;
    const controller = this.controllers.get(existing.id);
    return {
      jobId: existing.id,
      ...(controller ? { signal: controller.signal } : {}),
      ready: this.admissions.get(existing.id)?.promise ?? Promise.resolve(),
      durable: this.durabilities.get(existing.id)?.promise ?? Promise.resolve(),
      reused: true,
    };
  }

  private supersedeExclusiveJobs(input: RegisterInput, caseId: string | null): void {
    if (!input.exclusive) return;
    for (const job of listJobs(this.table, { caseId })) {
      if (job.kind === input.kind && !isTerminal(job.status)) {
        this.dropForExclusiveRegistration(job);
      }
    }
  }

  private appendQueuedJob(input: RegisterInput, caseId: string | null): string {
    const jobId = this.id();
    const parameters = input.parameters
      ? (sanitizeManifestValue(input.parameters) as Record<string, ManifestValue>)
      : undefined;
    // Asked once, here: the model a job runs is pinned when the work is queued, not re-read while
    // the row is drawn. See composition/jobModel.ts.
    const model = this.modelFor?.(input);
    this.table = this.limitTable(
      createJob(this.table, {
        id: jobId,
        caseId,
        kind: input.kind,
        ...(input.label !== undefined ? { label: input.label } : {}),
        ...(model ? { model } : {}),
        ...(input.detail !== undefined ? { detail: input.detail } : {}),
        ...(input.priority ? { priority: input.priority } : {}),
        ...(input.parentJobId ? { parentJobId: input.parentJobId } : {}),
        ...(input.idempotencyKey ? { idempotencyKey: input.idempotencyKey } : {}),
        ...(parameters ? { parameters } : {}),
        ...(input.runManifestId ? { runManifestId: input.runManifestId } : {}),
        ...(input.maxRetries !== undefined ? { maxRetries: input.maxRetries } : {}),
        ...(input.resourceBudget ? { resourceBudget: input.resourceBudget } : {}),
        resumable: input.resumable ?? false,
        cancellable: input.cancellable ?? false,
        status: "queued",
        now: this.now(),
      }),
    );
    return jobId;
  }

  private prepareRegistration(jobId: string, input: RegisterInput): RegisteredJob {
    if (input.cancellable || input.resourceBudget?.maxRuntimeMs) {
      this.controllers.set(jobId, new AbortController());
    }
    const admission = deferred();
    const durability = deferred();
    this.admissions.set(jobId, admission);
    this.durabilities.set(jobId, durability);

    if (!this.ledger) {
      durability.resolve();
      this.startInMemoryWhenPossible();
    } else {
      void this.persistNewAndSchedule(jobId).catch((error: unknown) => {
        const normalized = error instanceof Error ? error : new Error(String(error));
        durability.reject(normalized);
        admission.reject(normalized);
        this.reportError(normalized);
      });
    }
    return {
      jobId,
      ...(this.controllers.get(jobId) ? { signal: this.controllers.get(jobId)!.signal } : {}),
      ready: admission.promise,
      durable: durability.promise,
      reused: false,
    };
  }

  progress(jobId: string, done: number, total: number, detail?: string): void {
    const before = getJob(this.table, jobId);
    this.table = progressJob(this.table, jobId, { done, total }, detail, this.now());
    const updated = getJob(this.table, jobId);
    if (!before || !updated || updated === before) return;
    if (!this.ledger) {
      this.emit(updated.caseId);
      return;
    }
    void this.persistUpdate(updated)
      .then(() => this.emit(updated.caseId))
      .catch((error: unknown) => this.reportError(error instanceof Error ? error : new Error(String(error))));
  }

  async checkpoint(jobId: string, input: CheckpointInput): Promise<void> {
    await this.ready();
    const before = getJob(this.table, jobId);
    if (!before || before.status !== "running") return;
    this.table = checkpointJob(
      this.table,
      jobId,
      {
        progress: { done: input.done, total: input.total },
        ...(input.detail !== undefined ? { detail: input.detail } : {}),
        ...(input.cursor !== undefined
          ? {
              cursor: sanitizeManifestValue(manifestValueSchema.parse(input.cursor)),
            }
          : {}),
      },
      this.now(),
    );
    const updated = getJob(this.table, jobId);
    if (!updated || updated === before) return;
    await this.persistUpdate(updated);
    this.emit(updated.caseId);
  }

  async warn(jobId: string, warning: string): Promise<void> {
    await this.ready();
    const before = getJob(this.table, jobId);
    if (!before || isTerminal(before.status)) return;
    this.table = warnJob(this.table, jobId, warning, this.now());
    const updated = getJob(this.table, jobId);
    if (!updated || updated === before) return;
    await this.persistUpdate(updated);
    this.emit(updated.caseId);
  }

  async finish(jobId: string): Promise<void> {
    await this.terminalTransition(jobId, (table, now) => finishJob(table, jobId, now));
  }

  async fail(jobId: string, error: unknown, options: FailureOptions = {}): Promise<void> {
    const message = error instanceof Error ? error.message : String(error);
    await this.terminalTransition(jobId, (table, now) => {
      const failure: JobFailure = {
        code: options.code ?? "job_failed",
        message,
        retryable: options.retryable ?? false,
        at: now,
      };
      return failJob(table, jobId, failure, now);
    });
  }

  async cancel(jobId: string): Promise<CancelResult> {
    await this.ready();
    const job = getJob(this.table, jobId);
    if (!job) return { ok: false, reason: "unknown" };
    if (isTerminal(job.status)) return { ok: false, reason: "terminal" };
    if (!job.cancellable) return { ok: false, reason: "not-cancellable" };

    this.controllers.get(jobId)?.abort();
    this.clearBudgetTimer(jobId);
    this.table = cancelJob(this.table, jobId, this.now());
    const cancelled = getJob(this.table, jobId)!;
    await this.persistUpdate(cancelled);
    this.admissions.get(jobId)?.reject(abortError());
    this.admissions.delete(jobId);
    this.durabilities.delete(jobId);
    this.controllers.delete(jobId);
    this.emit(cancelled.caseId);
    await this.scheduleQueued();
    return { ok: true, job: cancelled };
  }

  // Called once a case's folder is gone: its jobs must not outlive it. The table is keyed by case
  // id alone, so any row left behind is inherited wholesale by the next case that claims the id —
  // and every one of them still offers a live Resume, which would replay the deleted case's import
  // into the new one and persist it there. Anything still in flight is aborted first; the work
  // functions themselves land on a table that no longer holds the row, and every registry
  // transition ignores an unknown id, so their late checkpoints and completions are no-ops.
  //
  // No ledger write: the case's jobs.sqlite lives inside the case folder and was deleted with it.
  async forgetCase(caseId: string): Promise<void> {
    await this.ready();
    const doomed = listJobs(this.table, { caseId });
    if (doomed.length === 0) return;
    for (const job of doomed) {
      this.controllers.get(job.id)?.abort();
      this.clearBudgetTimer(job.id);
      this.admissions.get(job.id)?.reject(abortError());
      this.admissions.delete(job.id);
      this.durabilities.delete(job.id);
      this.controllers.delete(job.id);
    }
    this.table = dropCaseJobs(this.table, caseId);
    this.emit(caseId);
    await this.scheduleQueued();
  }

  registerResumeHandler(kind: JobKind, handler: ResumeHandler, options: ResumeHandlerOptions = {}): void {
    this.resumeHandlers.set(kind, { handler, options });
  }

  async resume(jobId: string): Promise<ResumeResult> {
    await this.ready();
    const job = getJob(this.table, jobId);
    if (!job) return { ok: false, reason: "unknown" };
    if (job.status !== "interrupted" && job.status !== "failed") {
      return { ok: false, reason: "not-interrupted" };
    }
    if (job.status === "failed" && !job.failure?.retryable) {
      return { ok: false, reason: "not-resumable" };
    }
    if (!job.resumable) return { ok: false, reason: "not-resumable" };
    const registration = this.resumeHandlers.get(job.kind);
    if (!registration) return { ok: false, reason: "not-resumable" };
    if (job.attempt >= job.maxRetries + 1) {
      return { ok: false, reason: "retry-exhausted" };
    }

    this.table = requeueJob(this.table, jobId, this.now());
    if (registration.options.cancellable?.(job)) {
      this.table = allowJobCancellation(this.table, jobId);
    }
    const queued = getJob(this.table, jobId)!;
    if (queued.cancellable || queued.resourceBudget?.maxRuntimeMs) {
      this.controllers.set(jobId, new AbortController());
    }
    const admission = deferred();
    const durability = deferred();
    this.admissions.set(jobId, admission);
    this.durabilities.set(jobId, durability);
    await this.persistUpdate(queued);
    // SUPERSEDED WHILE THAT WRITE WAS IN FLIGHT. dropForExclusiveRegistration only deletes the
    // ledger row itself when durability has settled; otherwise it defers to the insert in
    // persistNewAndSchedule, and a resume never goes near one — the row it requeues has been on
    // disk since the run that was interrupted. So this await is the only place left that can clean
    // up, and skipping it strands a `queued` row for a job nothing points at: the next restore()
    // reloads it as `interrupted` and offers Resume on work a newer run already took over.
    //
    // Only a supersede (or forgetCase) can remove the row here — capJobsByScope evicts terminal
    // rows only, and this one is queued — so a missing row means the resume lost the race.
    if (!getJob(this.table, jobId)) {
      await this.ledger?.delete(queued);
      return { ok: false, reason: "unknown" };
    }
    durability.resolve();
    this.emit(queued.caseId);
    void this.scheduleQueued();
    void this.runResumedJob(jobId, registration.handler, admission.promise);
    return { ok: true, job: queued };
  }

  list(caseId?: string): Job[] {
    return listJobs(this.table, caseId !== undefined ? { caseId } : {});
  }

  hasActive(caseId: string, kind: JobKind): boolean {
    return listJobs(this.table, { caseId }).some((job) => job.kind === kind && !isTerminal(job.status));
  }

  get(jobId: string): Job | undefined {
    return getJob(this.table, jobId);
  }

  async drain(): Promise<void> {
    await this.ready();
    await this.scheduling;
  }

  private async restore(): Promise<void> {
    const jobs = this.ledger ? await this.ledger.listAll() : [];
    const registeredDuringRestore = [...this.table.jobs];
    this.table = {
      jobs: [...jobs, ...registeredDuringRestore].sort((a, b) => a.queuedAt.localeCompare(b.queuedAt)),
    };
    for (const job of jobs) {
      if (job.status !== "queued" && job.status !== "running") continue;
      this.table = interruptJob(this.table, job.id, this.now());
      const interrupted = getJob(this.table, job.id)!;
      await this.ledger?.update(interrupted);
    }
    if (this.ledger) {
      for (const caseId of new Set(jobs.map((job) => job.caseId))) {
        await this.ledger.prune(caseId, this.max);
      }
      this.table = capJobsByScope(this.table, this.max);
    }
  }

  private async persistNewAndSchedule(jobId: string): Promise<void> {
    await this.ready();
    const job = getJob(this.table, jobId);
    if (!job || !this.ledger) return;
    const result = await this.ledger.insert(job);
    if (!result.inserted) {
      throw new Error(
        `job idempotency conflict for ${job.id}; the supported job writer model is single-process`,
      );
    }
    // Superseded WHILE this insert was in flight. dropForExclusiveRegistration ran synchronously
    // against a job with no ledger row yet, so it left the DELETE to whoever created one — this
    // await, which has just returned holding the only reference to a row nothing points at any
    // more. Skipped, it is reloaded as `cancelled` by the next restore().
    if (!getJob(this.table, jobId)) {
      await this.ledger.delete(job);
      return;
    }
    this.durabilities.get(jobId)?.resolve();
    this.emit(job.caseId);
    await this.scheduleQueued();
  }

  // A SUPERSEDE, not a cancellation — the row is REMOVED rather than marked cancelled.
  //
  // Every `exclusive` caller registers a "the case changed, re-derive it" kick whose newest
  // registration subsumes all the older ones, so a superseded job is a queue entry that was
  // replaced, not a result. Marking it `cancelled` claimed otherwise: that is the exact status the
  // ✕ Cancel button produces, and a multi-file import mints one kick per file — so an eleven-file
  // import filled the jobs popover with eleven "cancelled" rows the analyst never cancelled, and
  // pushed the still-queued imports the badge was counting past the end of the list.
  //
  // Removal changes nothing about scheduling: `cancelled` was terminal too, so the case's
  // concurrency slot was already freed at this same point.
  private dropForExclusiveRegistration(job: Job): void {
    if (!job.cancellable) return;
    // WHO DELETES THE LEDGER ROW depends on whether the INSERT has already landed, because
    // register() supersedes synchronously and cannot wait to find out. Settled durability means the
    // row is on disk and this path owns the DELETE. Unsettled means the insert is still in flight
    // (or has not started), and persistNewAndSchedule owns it — it re-reads the table after its
    // insert returns and deletes the row it finds superseded. Either way the ledger loses the row,
    // which is what matters: restore() is the one place it would ever be read again, and it would
    // come back as a `cancelled` job the analyst never cancelled.
    const durability = this.durabilities.get(job.id);
    const inLedger = durability?.settled() === true;
    this.controllers.get(job.id)?.abort();
    this.clearBudgetTimer(job.id);
    this.table = dropJob(this.table, job.id);
    this.admissions.get(job.id)?.reject(abortError());
    // The row is gone, so it can never become durable. Rejecting says so; leaving it pending would
    // hang anyone who awaits `durable` (routes/import.ts does) for the life of the process.
    durability?.reject(abortError());
    this.admissions.delete(job.id);
    this.durabilities.delete(job.id);
    this.controllers.delete(job.id);
    this.emit(job.caseId);
    if (!inLedger) return;
    void (this.ledger?.delete(job) ?? Promise.resolve())
      .then(() => this.scheduleQueued())
      .catch((error: unknown) => this.reportError(error instanceof Error ? error : new Error(String(error))));
  }

  private startInMemoryWhenPossible(): void {
    while (true) {
      const next = this.nextAdmissible();
      if (!next) break;
      this.table = startJob(this.table, next.id, this.now());
      this.armRuntimeBudget(getJob(this.table, next.id)!);
      this.admissions.get(next.id)?.resolve();
      this.emit(next.caseId);
    }
  }

  private scheduleQueued(): Promise<void> {
    this.scheduling = this.scheduling
      .catch((error: unknown) => this.reportError(error instanceof Error ? error : new Error(String(error))))
      .then(async () => {
        while (true) {
          const next = this.nextAdmissible();
          if (!next) break;
          this.table = startJob(this.table, next.id, this.now());
          const started = getJob(this.table, next.id)!;
          try {
            await this.persistUpdate(started);
          } catch (error) {
            // The start is already applied in memory, so a failed ledger write cannot simply
            // propagate: the job would stay "running" to every reader, its admission would never
            // settle (runResumedJob's await hangs for good), and nextAdmissible would keep counting
            // it against perCaseConcurrency — the case would never admit another job until a
            // restart. Fail it in memory instead and hand the error to whoever waits on the
            // admission. Then keep going rather than stopping the pass: the failed job is terminal
            // so nextAdmissible cannot pick it again (no spin), and every other queued job still
            // gets its chance — breaking here would strand them until some later registration or
            // terminal transition happened to schedule another pass. The failure is retryable, so
            // if the ledger is genuinely down each job fails visibly and can be resumed.
            const normalized = error instanceof Error ? error : new Error(String(error));
            this.table = failJob(
              this.table,
              next.id,
              {
                code: "ledger_write_failed",
                message: normalized.message,
                retryable: true,
                at: this.now(),
              },
              this.now(),
            );
            this.clearBudgetTimer(next.id);
            this.admissions.get(next.id)?.reject(normalized);
            this.admissions.delete(next.id);
            this.durabilities.delete(next.id);
            this.controllers.delete(next.id);
            this.emit(next.caseId);
            this.reportError(normalized);
            continue;
          }
          this.armRuntimeBudget(started);
          this.admissions.get(next.id)?.resolve();
          this.emit(started.caseId);
        }
      });
    return this.scheduling;
  }

  private nextAdmissible(): Job | undefined {
    const running = this.table.jobs.filter((job) => job.status === "running");
    if (running.length >= this.globalConcurrency) return undefined;
    const runningByScope = new Map<string, number>();
    for (const job of running) {
      const scope = job.caseId ?? "global";
      runningByScope.set(scope, (runningByScope.get(scope) ?? 0) + 1);
    }
    return this.table.jobs
      .filter((job) => {
        if (job.status !== "queued") return false;
        return (runningByScope.get(job.caseId ?? "global") ?? 0) < this.perCaseConcurrency;
      })
      .sort(
        (a, b) =>
          priorityRank(b.priority) - priorityRank(a.priority) ||
          a.queuedAt.localeCompare(b.queuedAt) ||
          a.id.localeCompare(b.id),
      )[0];
  }

  private async terminalTransition(
    jobId: string,
    apply: (table: JobTable, now: string) => JobTable,
  ): Promise<void> {
    await this.ready();
    const job = getJob(this.table, jobId);
    if (!job || isTerminal(job.status)) return;
    this.table = apply(this.table, this.now());
    const terminal = getJob(this.table, jobId)!;
    await this.persistUpdate(terminal);
    this.clearBudgetTimer(jobId);
    this.controllers.delete(jobId);
    this.admissions.delete(jobId);
    this.durabilities.delete(jobId);
    this.emit(terminal.caseId);
    await this.scheduleQueued();
  }

  private async persistUpdate(job: Job): Promise<void> {
    if (!this.ledger) return;
    await this.ledger.update(job);
    await this.ledger.prune(job.caseId, this.max);
    this.table = this.limitTable(this.table);
  }

  private limitTable(table: JobTable): JobTable {
    return this.ledger ? capJobsByScope(table, this.max) : capJobs(table, this.max);
  }

  private async runResumedJob(
    jobId: string,
    handler: ResumeHandler,
    admission: Promise<void>,
  ): Promise<void> {
    try {
      await admission;
      const job = getJob(this.table, jobId);
      if (!job || job.status !== "running") return;
      await handler(job, this.controllers.get(jobId)?.signal);
      await this.finish(jobId);
    } catch (error) {
      const job = getJob(this.table, jobId);
      if (!job || isTerminal(job.status)) return;
      await this.fail(jobId, error, {
        code: "resume_failed",
        retryable: true,
      });
    }
  }

  private armRuntimeBudget(job: Job): void {
    const maxRuntimeMs = job.resourceBudget?.maxRuntimeMs;
    if (!maxRuntimeMs) return;
    this.clearBudgetTimer(job.id);
    const timer = setTimeout(() => {
      this.controllers.get(job.id)?.abort();
      void this.fail(job.id, new Error(`job exceeded its ${maxRuntimeMs} ms runtime budget`), {
        code: "runtime_budget_exceeded",
        retryable: false,
      }).catch((error: unknown) =>
        this.reportError(error instanceof Error ? error : new Error(String(error))),
      );
    }, maxRuntimeMs);
    timer.unref();
    this.budgetTimers.set(job.id, timer);
  }

  private clearBudgetTimer(jobId: string): void {
    const timer = this.budgetTimers.get(jobId);
    if (timer) clearTimeout(timer);
    this.budgetTimers.delete(jobId);
  }

  private emit(caseId: string | null): void {
    try {
      this.onJob?.(caseId);
    } catch {
      // A WebSocket failure must never break the evidence operation that triggered the transition.
    }
  }

  private reportError(error: Error): void {
    try {
      this.onError?.(error);
    } catch {
      // Error reporting is a side channel. The original operation still receives its own failure.
    }
  }
}
