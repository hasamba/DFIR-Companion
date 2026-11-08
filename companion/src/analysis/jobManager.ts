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
  abortError,
  deferred,
  ledgerWriteFailure,
  nextAdmissibleJob,
  toError,
  type Deferred,
} from "./jobManagerSupport.js";
import {
  modelIdentityFields,
  servedStampTarget,
  withModelLabels,
  type JobListItem,
  type JobModelIdentity,
} from "./jobServedModel.js";
import type { ServedModelRegistry } from "./servedModels.js";
import { StoppingJobs, staleScopeRegistration } from "./stoppingJobs.js";
import {
  emptyJobTable,
  createJob,
  startJob,
  checkpointJob,
  progressJob,
  warnJob,
  finishJob,
  stampServedModel,
  pinJobModel,
  failJob,
  cancelJob,
  holdJob,
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
  files?: string[];
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
  // A signal for the served-model stamp (#1601) WITHOUT cancel (#1629); only case deletion aborts it.
  modelCallSignal?: boolean;
  /** The model that will run this job, when the caller knows better than the resolver (a replay). */
  model?: { model: string; provider: string };
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
      /** ledger-write-failed: the requeue could not be recorded; nothing changed, Resume stays offered. */
      reason: "unknown" | "not-interrupted" | "not-resumable" | "retry-exhausted" | "ledger-write-failed";
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

type ResumeHandler = (job: Job, signal?: AbortSignal) => Promise<void>;
type ResumeHandlerOptions = {
  cancellable?: (job: Job) => boolean;
};
type ResumeHandlerRegistration = {
  handler: ResumeHandler;
  options: ResumeHandlerOptions;
};

export class JobManager {
  private table: JobTable = emptyJobTable();
  /**
   * Answers "which model runs this job" for every registration. Installed rather than constructed
   * because runtimeStores.ts builds this manager before the pipeline exists; createApp holds both.
   * Unset in a minimal wiring, and every job then simply carries no model.
   */
  private modelFor?: (input: RegisterInput) => JobModelIdentity;
  private servedModels?: { registry: ServedModelRegistry; unsubscribe: () => void };
  private readonly controllers = new Map<string, AbortController>();
  private readonly admissions = new Map<string, Deferred>();
  private readonly durabilities = new Map<string, Deferred>();
  private readonly budgetTimers = new Map<string, NodeJS.Timeout>();
  private readonly resumeHandlers = new Map<JobKind, ResumeHandlerRegistration>();
  // Resumes whose requeue is still being written (#2409): the row stays interrupted/failed in memory
  // until it lands; an exclusive registration of the same kind marks the attempt superseded.
  private readonly resuming = new Map<string, { superseded: boolean; cancellable: boolean }>();
  private readonly stopping = new StoppingJobs(); // a deleted case's work still winding down (#1831)
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
      this.initializationError = toError(error);
      this.reportError(this.initializationError);
    });
  }

  async ready(): Promise<void> {
    await this.initialization;
    if (this.initializationError) throw this.initializationError;
  }

  /** Install the "which model runs this job" resolver. Called once, by createApp. */
  useModelResolver(resolve: (input: RegisterInput) => JobModelIdentity): void {
    this.modelFor = resolve;
  }

  /** Stamp each job with the concrete model its call ran on (#1601). Replaces any earlier binding. */
  useServedModels(registry: ServedModelRegistry): void {
    this.servedModels?.unsubscribe();
    const unsubscribe = registry.subscribe((event) => {
      const job = servedStampTarget(event, this.controllers, (id) => getJob(this.table, id));
      if (job) this.publishPatch(job, stampServedModel(this.table, job.id, event.resolvedModel, this.now()));
    });
    this.servedModels = { registry, unsubscribe };
  }

  /** Name the model of a job that learns it just before a model runs (#1629); a pin is kept. */
  pinModel(jobId: string, input: Pick<RegisterInput, "kind" | "parameters">): void {
    const job = getJob(this.table, jobId);
    if (!job || !this.modelFor) return;
    const fields = modelIdentityFields(this.modelFor(input));
    this.publishPatch(job, pinJobModel(this.table, jobId, fields, this.now()));
  }

  /**
   * Adopt a patched table; when `before` changed, persist its new row and tell the dashboard.
   * Fire-and-forget is safe for ordering (#2409): ledger.update posts to the single ledger worker
   * synchronously, and that worker handles messages one at a time in arrival order, so a progress
   * write can never land after a terminal write issued later. progressJob ignores non-running rows.
   */
  private publishPatch(before: Job, table: JobTable): void {
    this.table = table;
    const updated = getJob(table, before.id);
    if (!updated || updated === before) return;
    if (!this.ledger) return this.emit(updated.caseId);
    void this.persistUpdate(updated)
      .then(() => this.emit(updated.caseId))
      .catch((error: unknown) => this.reportError(toError(error)));
  }

  register(input: RegisterInput): RegisteredJob {
    const caseId = input.caseId ?? null;
    // #1866: old work (a deleted / replaced case's scope) never touches a successor's jobs.
    const existing = staleScopeRegistration(caseId) ?? this.reusedRegistration(input, caseId);
    if (existing) return existing;
    this.supersedeExclusiveJobs(input, caseId);
    const jobId = this.appendQueuedJob(input, caseId);
    this.stopping.adopt(caseId, jobId);
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
      if (job.kind !== input.kind) continue;
      if (!isTerminal(job.status)) this.dropForExclusiveRegistration(job);
      else this.supersedeResumeInFlight(job);
    }
  }

  private appendQueuedJob(input: RegisterInput, caseId: string | null): string {
    const jobId = this.id();
    const parameters = input.parameters
      ? (sanitizeManifestValue(input.parameters) as Record<string, ManifestValue>)
      : undefined;
    // Asked once, here: the model a job runs is pinned when the work is queued, not re-read while
    // the row is drawn. See composition/jobModel.ts.
    const model = modelIdentityFields(input.model ?? this.modelFor?.(input));
    this.table = this.limitTable(
      createJob(this.table, {
        id: jobId,
        caseId,
        kind: input.kind,
        ...(input.label !== undefined ? { label: input.label } : {}),
        ...model,
        ...(input.detail !== undefined ? { detail: input.detail } : {}),
        ...(input.files ? { files: input.files } : {}),
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
    if (input.cancellable || input.modelCallSignal || input.resourceBudget?.maxRuntimeMs) {
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
        const normalized = toError(error);
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
    if (before)
      this.publishPatch(before, progressJob(this.table, jobId, { done, total }, detail, this.now()));
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

  async hold(jobId: string, reason: string): Promise<void> {
    await this.terminalTransition(jobId, (table, now) => holdJob(table, jobId, reason, now));
  }
  async cancel(jobId: string): Promise<CancelResult> {
    await this.ready();
    const job = getJob(this.table, jobId);
    if (!job) return { ok: false, reason: "unknown" };
    if (isTerminal(job.status)) return { ok: false, reason: "terminal" };
    if (!job.cancellable) return { ok: false, reason: "not-cancellable" };
    this.stopping.aborted(job); // its row turns terminal now; its work may run on (#1831)
    this.controllers.get(jobId)?.abort();
    this.clearBudgetTimer(jobId);
    this.table = cancelJob(this.table, jobId, this.now());
    const cancelled = getJob(this.table, jobId)!;
    // The work is already aborted and the row cancelled in memory, so a failed write is reported
    // and the clean-up and scheduling below still run (#2409): a throw here used to strand the
    // job's slot bookkeeping and stop the queue, and escaped the cancel route unhandled.
    const failure = await this.tryPersist(cancelled);
    this.admissions.get(jobId)?.reject(abortError());
    this.admissions.delete(jobId);
    this.durabilities.delete(jobId);
    this.controllers.delete(jobId);
    this.emit(cancelled.caseId);
    if (failure) this.reportError(ledgerWriteFailure(cancelled, job.status, failure));
    await this.scheduleQueued();
    return { ok: true, job: cancelled };
  }

  // Called once a case's folder is gone: its rows would otherwise be inherited by the next case
  // with the id, each with a live Resume. In-flight work is aborted, but it may still be running:
  // it stays in `stopping` until it reports its end, and the id cannot be reused until then (#1831).
  // No ledger write: the case's jobs.sqlite lives inside the case folder and was deleted with it.
  async forgetCase(caseId: string): Promise<void> {
    await this.ready();
    const doomed = listJobs(this.table, { caseId });
    if (doomed.length === 0) return;
    this.stopping.add(caseId, doomed);
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

  /** True while a deleted case's aborted work has not yet reported its end (#1831). */
  isStopping(caseId: string): boolean {
    return this.stopping.has(caseId);
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

    if (this.resuming.has(jobId)) return { ok: false, reason: "not-interrupted" };

    const repin = this.modelFor
      ? modelIdentityFields(
          this.modelFor({ kind: job.kind, ...(job.parameters ? { parameters: job.parameters } : {}) }),
        )
      : undefined;
    const now = this.now();
    const requeue = (table: JobTable): JobTable => {
      const requeued = requeueJob(table, jobId, now, repin);
      return registration.options.cancellable?.(job) ? allowJobCancellation(requeued, jobId) : requeued;
    };
    const queued = getJob(requeue(this.table), jobId)!;

    // WRITE FIRST, then apply (#2409). Until the queued row is on disk the in-memory row stays
    // interrupted/failed, so the scheduler cannot admit it and a cancel or supersede cannot see a
    // half-resumed job. A failed write therefore changes nothing in memory: no phantom `queued`
    // row that a later pass would start with no handler attached and hold the case's slot forever.
    const attempt = { superseded: false, cancellable: queued.cancellable };
    this.resuming.set(jobId, attempt);
    try {
      await this.ledger?.update(queued);
    } catch (error) {
      this.reportError(new Error(`job ${jobId} resume was not recorded: ${toError(error).message}`));
      return { ok: false, reason: "ledger-write-failed" };
    } finally {
      this.resuming.delete(jobId);
    }
    if (this.ledger) await this.pruneLedger(queued.caseId);

    // SUPERSEDED (or the case forgotten) WHILE THAT WRITE WAS IN FLIGHT. The row it wrote is a
    // `queued` job nothing points at: left, the next restore() reloads it as `interrupted` and
    // offers Resume on work a newer run already took over. Erase it and say the resume lost.
    if (attempt.superseded || !getJob(this.table, jobId)) {
      await this.ledger?.delete(queued).catch((error: unknown) => this.reportError(toError(error)));
      return { ok: false, reason: "unknown" };
    }
    this.table = requeue(this.table);
    if (queued.cancellable || queued.resourceBudget?.maxRuntimeMs) {
      this.controllers.set(jobId, new AbortController());
    }
    const admission = deferred();
    const durability = deferred();
    this.admissions.set(jobId, admission);
    this.durabilities.set(jobId, durability);
    durability.resolve();
    this.emit(queued.caseId);
    void this.scheduleQueued();
    void this.runResumedJob(jobId, registration.handler, admission.promise);
    return { ok: true, job: getJob(this.table, jobId)! };
  }

  list(caseId?: string): JobListItem[] {
    const jobs = listJobs(this.table, caseId !== undefined ? { caseId } : {});
    const registry = this.servedModels?.registry;
    return withModelLabels(jobs, this.table.jobs, registry && ((p, a) => registry.lastFor(p, a)));
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

  // A SUPERSEDE, not a cancellation — the row is REMOVED rather than marked cancelled. Every
  // `exclusive` caller registers a "the case changed, re-derive it" kick whose newest registration
  // subsumes the older ones, so a superseded job was replaced, not cancelled: an eleven-file import
  // used to fill the jobs popover with eleven "cancelled" rows the analyst never cancelled.
  // Removal changes nothing about scheduling: the case's concurrency slot is freed here either way.
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
    this.stopping.aborted(job);
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
      .catch((error: unknown) => this.reportError(toError(error)));
  }

  /** A resume still writing its requeue: drop the row now; resume() erases what it wrote (#2409). */
  private supersedeResumeInFlight(job: Job): void {
    const attempt = this.resuming.get(job.id);
    if (!attempt?.cancellable) return;
    attempt.superseded = true;
    this.table = dropJob(this.table, job.id);
    this.emit(job.caseId);
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
      .catch((error: unknown) => this.reportError(toError(error)))
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
            const normalized = toError(error);
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
    return nextAdmissibleJob(this.table, this.globalConcurrency, this.perCaseConcurrency);
  }

  private async terminalTransition(
    jobId: string,
    apply: (table: JobTable, now: string) => JobTable,
  ): Promise<void> {
    await this.ready();
    this.stopping.settle(jobId); // the work reported its end, even for a row forgetCase dropped
    const job = getJob(this.table, jobId);
    if (!job || isTerminal(job.status)) return;
    this.table = apply(this.table, this.now());
    const terminal = getJob(this.table, jobId)!;
    // Memory is already terminal. A failed write must not skip the clean-up or the scheduling
    // pass, or queued work waits for an unrelated event (#2409). It is reported, not thrown: the
    // work itself ended as recorded, and callers treat a throwing finish() as a failed import.
    const failure = await this.tryPersist(terminal);
    this.clearBudgetTimer(jobId);
    this.controllers.delete(jobId);
    this.admissions.delete(jobId);
    this.durabilities.delete(jobId);
    this.emit(terminal.caseId);
    if (failure) this.reportError(ledgerWriteFailure(terminal, job.status, failure));
    await this.scheduleQueued();
  }

  private async tryPersist(job: Job): Promise<Error | undefined> {
    try {
      await this.persistUpdate(job);
      return undefined;
    } catch (error) {
      return toError(error);
    }
  }

  private async persistUpdate(job: Job): Promise<void> {
    if (!this.ledger) return;
    await this.ledger.update(job);
    await this.pruneLedger(job.caseId);
  }

  // Retention, not the transition: once update() landed, a failed prune must not make the caller
  // treat the transition itself as unrecorded (#2409). Reported; the next write prunes again.
  private async pruneLedger(caseId: string | null): Promise<void> {
    try {
      await this.ledger?.prune(caseId, this.max);
    } catch (error) {
      this.reportError(toError(error));
    }
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
      this.stopping.settle(jobId); // the handler ended, even when its row is gone or terminal
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
      }).catch((error: unknown) => this.reportError(toError(error)));
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
