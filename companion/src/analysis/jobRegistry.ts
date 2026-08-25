// Durable background-job model (#380) — pure core.
//
// The impure manager persists every transition in SQLite and owns AbortControllers. This module
// only validates records and returns immutable state transitions, which keeps recovery, retry and
// cancellation behavior deterministic under unit tests.

import { z } from "zod";
import type { ManifestValue } from "./analysisRunTypes.js";

export const JOB_KINDS = ["import", "synthesis", "enrichment", "deep-pass", "mcp"] as const;
export type JobKind = (typeof JOB_KINDS)[number];

export const JOB_STATUSES = ["queued", "running", "succeeded", "failed", "cancelled", "interrupted"] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];
export type JobPriority = "low" | "normal" | "high";

export interface JobProgress {
  done: number;
  total: number;
}

export interface JobCheckpoint {
  sequence: number;
  at: string;
  progress: JobProgress;
  detail?: string;
  cursor?: ManifestValue;
}

export interface JobFailure {
  code: string;
  message: string;
  retryable: boolean;
  at: string;
}

export interface JobResourceBudget {
  maxRuntimeMs?: number;
  maxCostUsd?: number;
  maxInputTokens?: number;
}

export interface Job {
  id: string;
  caseId: string | null;
  kind: JobKind;
  label?: string;
  /**
   * The AI model driving this job, when one does. Set at registration from the provider that will
   * actually run the work, NOT read from env at render time: a job outlives a Settings change, and
   * a row that renamed its own model after the fact would misattribute every finished run.
   * Unset for jobs no model runs (enrichment, a deterministic import, a Velociraptor collect).
   */
  model?: string;
  status: JobStatus;
  priority: JobPriority;
  parentJobId?: string;
  idempotencyKey?: string;
  parameters?: Record<string, ManifestValue>;
  runManifestId?: string;
  progress?: JobProgress;
  detail?: string;
  queuedAt: string;
  startedAt?: string;
  updatedAt: string;
  endedAt?: string;
  error?: string;
  failure?: JobFailure;
  warnings: string[];
  lastCheckpoint?: JobCheckpoint;
  throughputPerSecond?: number;
  etaAt?: string;
  attempt: number;
  maxRetries: number;
  resourceBudget?: JobResourceBudget;
  resumable: boolean;
  cancellable: boolean;
  cancelRequestedAt?: string;
}

export interface JobTable {
  jobs: Job[];
}

export const TERMINAL_STATUSES: readonly JobStatus[] = ["succeeded", "failed", "cancelled", "interrupted"];

export function isTerminal(status: JobStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

export function emptyJobTable(): JobTable {
  return { jobs: [] };
}

export interface CreateJobInput {
  id: string;
  caseId: string | null;
  kind: JobKind;
  label?: string;
  model?: string;
  detail?: string;
  priority?: JobPriority;
  parentJobId?: string;
  idempotencyKey?: string;
  parameters?: Record<string, ManifestValue>;
  runManifestId?: string;
  resourceBudget?: JobResourceBudget;
  attempt?: number;
  maxRetries?: number;
  resumable?: boolean;
  cancellable?: boolean;
  status?: "queued" | "running";
  now: string;
}

export function createJob(table: JobTable, input: CreateJobInput): JobTable {
  const status = input.status ?? "running";
  const job: Job = {
    id: input.id,
    caseId: input.caseId,
    kind: input.kind,
    ...(input.label !== undefined ? { label: input.label } : {}),
    ...(input.model !== undefined ? { model: input.model } : {}),
    ...(input.detail !== undefined ? { detail: input.detail } : {}),
    status,
    priority: input.priority ?? "normal",
    ...(input.parentJobId ? { parentJobId: input.parentJobId } : {}),
    ...(input.idempotencyKey ? { idempotencyKey: input.idempotencyKey } : {}),
    ...(input.parameters ? { parameters: input.parameters } : {}),
    ...(input.runManifestId ? { runManifestId: input.runManifestId } : {}),
    queuedAt: input.now,
    ...(status === "running" ? { startedAt: input.now } : {}),
    updatedAt: input.now,
    warnings: [],
    attempt: input.attempt ?? 1,
    maxRetries: input.maxRetries ?? 0,
    ...(input.resourceBudget ? { resourceBudget: input.resourceBudget } : {}),
    resumable: input.resumable ?? false,
    cancellable: input.cancellable ?? false,
  };
  return { jobs: [...table.jobs, job] };
}

function patchJob(table: JobTable, id: string, patch: (job: Job) => Job): JobTable {
  let changed = false;
  const jobs = table.jobs.map((job) => {
    if (job.id !== id) return job;
    const next = patch(job);
    changed = changed || next !== job;
    return next;
  });
  return changed ? { jobs } : table;
}

export function startJob(table: JobTable, id: string, now: string): JobTable {
  return patchJob(table, id, (job) =>
    job.status !== "queued" ? job : { ...job, status: "running", startedAt: now, updatedAt: now },
  );
}

function validProgress(progress: JobProgress): JobProgress {
  const total = Math.max(0, Math.floor(progress.total));
  const done = Math.max(0, Math.min(total, Math.floor(progress.done)));
  return { done, total };
}

function progressMetrics(
  job: Job,
  progress: JobProgress,
  now: string,
): Pick<Job, "throughputPerSecond" | "etaAt"> {
  if (!job.startedAt || progress.done <= 0 || progress.total <= progress.done) return {};
  const elapsedMs = Date.parse(now) - Date.parse(job.startedAt);
  if (!Number.isFinite(elapsedMs) || elapsedMs <= 0) return {};
  const throughputPerSecond = progress.done / (elapsedMs / 1000);
  if (!Number.isFinite(throughputPerSecond) || throughputPerSecond <= 0) return {};
  const remainingMs = ((progress.total - progress.done) / throughputPerSecond) * 1000;
  return {
    throughputPerSecond,
    etaAt: new Date(Date.parse(now) + remainingMs).toISOString(),
  };
}

export function checkpointJob(
  table: JobTable,
  id: string,
  input: {
    progress: JobProgress;
    detail?: string;
    cursor?: ManifestValue;
  },
  now: string,
): JobTable {
  return patchJob(table, id, (job) => {
    if (job.status !== "running") return job;
    const progress = validProgress(input.progress);
    if (
      job.lastCheckpoint &&
      progress.total === job.lastCheckpoint.progress.total &&
      progress.done < job.lastCheckpoint.progress.done
    )
      return job;
    const checkpoint: JobCheckpoint = {
      sequence: (job.lastCheckpoint?.sequence ?? 0) + 1,
      at: now,
      progress,
      ...(input.detail !== undefined ? { detail: input.detail } : {}),
      ...(input.cursor !== undefined ? { cursor: input.cursor } : {}),
    };
    const metrics = progressMetrics(job, progress, now);
    return {
      ...job,
      progress,
      ...(input.detail !== undefined ? { detail: input.detail } : {}),
      throughputPerSecond: metrics.throughputPerSecond,
      etaAt: metrics.etaAt,
      lastCheckpoint: checkpoint,
      updatedAt: now,
    };
  });
}

export function warnJob(table: JobTable, id: string, warning: string, now: string): JobTable {
  const normalized = warning.trim();
  if (!normalized) return table;
  return patchJob(table, id, (job) =>
    isTerminal(job.status) || job.warnings.includes(normalized)
      ? job
      : {
          ...job,
          warnings: [...job.warnings, normalized],
          updatedAt: now,
        },
  );
}

export function progressJob(
  table: JobTable,
  id: string,
  progress: JobProgress,
  detail?: string,
  now?: string,
): JobTable {
  return patchJob(table, id, (job) => {
    if (job.status !== "running") return job;
    const nextProgress = validProgress(progress);
    if (job.progress && nextProgress.done < job.progress.done) return job;
    const metrics = now ? progressMetrics(job, nextProgress, now) : {};
    return {
      ...job,
      progress: nextProgress,
      ...(detail !== undefined ? { detail } : {}),
      ...(now
        ? {
            throughputPerSecond: metrics.throughputPerSecond,
            etaAt: metrics.etaAt,
            updatedAt: now,
          }
        : {}),
    };
  });
}

function terminate(
  table: JobTable,
  id: string,
  status: Extract<JobStatus, "succeeded" | "failed" | "cancelled" | "interrupted">,
  now: string,
  extra: Partial<Job> = {},
): JobTable {
  return patchJob(table, id, (job) =>
    isTerminal(job.status)
      ? job
      : {
          ...job,
          ...extra,
          status,
          updatedAt: now,
          endedAt: now,
          etaAt: undefined,
          ...(status === "cancelled" ? { cancelRequestedAt: now } : {}),
        },
  );
}

export function finishJob(table: JobTable, id: string, now: string): JobTable {
  return terminate(table, id, "succeeded", now);
}

export function failJob(table: JobTable, id: string, failure: JobFailure | string, now: string): JobTable {
  const normalized: JobFailure =
    typeof failure === "string"
      ? { code: "job_failed", message: failure, retryable: false, at: now }
      : failure;
  return terminate(table, id, "failed", now, {
    error: normalized.message,
    failure: normalized,
  });
}

export function cancelJob(table: JobTable, id: string, now: string): JobTable {
  return terminate(table, id, "cancelled", now);
}

export function interruptJob(table: JobTable, id: string, now: string): JobTable {
  return terminate(table, id, "interrupted", now, {
    error: "server restarted before this job reached a terminal state",
    failure: {
      code: "server_restart",
      message: "server restarted before this job reached a terminal state",
      retryable: true,
      at: now,
    },
  });
}

export function requeueJob(table: JobTable, id: string, now: string): JobTable {
  return patchJob(table, id, (job) => {
    if (job.status !== "interrupted" && job.status !== "failed") return job;
    return {
      ...job,
      status: "queued",
      queuedAt: now,
      updatedAt: now,
      attempt: job.attempt + 1,
      startedAt: undefined,
      endedAt: undefined,
      error: undefined,
      failure: undefined,
      progress: job.lastCheckpoint?.progress,
      detail: job.lastCheckpoint?.detail ?? job.detail,
      throughputPerSecond: undefined,
      etaAt: undefined,
      cancelRequestedAt: undefined,
    };
  });
}

export function allowJobCancellation(table: JobTable, id: string): JobTable {
  return patchJob(table, id, (job) => (job.cancellable ? job : { ...job, cancellable: true }));
}

export function getJob(table: JobTable, id: string): Job | undefined {
  return table.jobs.find((job) => job.id === id);
}

export function findJobByIdempotencyKey(
  table: JobTable,
  caseId: string | null,
  key: string,
): Job | undefined {
  return table.jobs.find((job) => job.caseId === caseId && job.idempotencyKey === key);
}

export function listJobs(table: JobTable, opts: { caseId?: string | null } = {}): Job[] {
  const filtered =
    opts.caseId !== undefined ? table.jobs.filter((job) => job.caseId === opts.caseId) : table.jobs;
  return [...filtered].sort((a, b) => b.queuedAt.localeCompare(a.queuedAt) || b.id.localeCompare(a.id));
}

// Removes one row outright rather than moving it to a terminal status. For a SUPERSEDE: a newer
// exclusive registration subsumes this job's work, so what is left is not a result the analyst can
// act on — it is a queue entry that was replaced. Marking it `cancelled` said the opposite, because
// that is the same status the ✕ Cancel button produces, and a multi-file import minted one per file.
export function dropJob(table: JobTable, jobId: string): JobTable {
  const remaining = table.jobs.filter((job) => job.id !== jobId);
  return remaining.length === table.jobs.length ? table : { jobs: remaining };
}

// Removes a case's rows outright rather than moving them to a terminal status: the case they
// describe no longer exists, so there is nothing left for a reader to act on. Jobs are keyed by
// case id alone, so a survivor would silently re-attach to the next case that claims the id.
export function dropCaseJobs(table: JobTable, caseId: string): JobTable {
  const remaining = table.jobs.filter((job) => job.caseId !== caseId);
  return remaining.length === table.jobs.length ? table : { jobs: remaining };
}

export function capJobs(table: JobTable, max: number): JobTable {
  if (max <= 0 || table.jobs.length <= max) return table;
  const over = table.jobs.length - max;
  const evict = new Set<string>();
  for (const job of table.jobs) {
    if (evict.size >= over) break;
    if (isTerminal(job.status)) evict.add(job.id);
  }
  return evict.size ? { jobs: table.jobs.filter((job) => !evict.has(job.id)) } : table;
}

export function capJobsByScope(table: JobTable, max: number): JobTable {
  if (max <= 0) return table;
  let bounded = table;
  const scopes = new Set(table.jobs.map((job) => job.caseId));
  for (const scope of scopes) {
    const scoped = bounded.jobs.filter((job) => job.caseId === scope);
    const kept = new Set(capJobs({ jobs: scoped }, max).jobs.map((job) => job.id));
    bounded = {
      jobs: bounded.jobs.filter((job) => job.caseId !== scope || kept.has(job.id)),
    };
  }
  return bounded;
}

const manifestValueSchema: z.ZodType<ManifestValue> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number(),
    z.string(),
    z.array(manifestValueSchema),
    z.record(z.string(), manifestValueSchema),
  ]),
);
const progressSchema = z.object({
  done: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
});

export const jobSchema: z.ZodType<Job> = z.object({
  id: z.string().min(1).max(160),
  caseId: z.string().min(1).nullable(),
  kind: z.enum(JOB_KINDS),
  label: z.string().optional(),
  model: z.string().min(1).max(200).optional(),
  status: z.enum(JOB_STATUSES),
  priority: z.enum(["low", "normal", "high"]),
  parentJobId: z.string().optional(),
  idempotencyKey: z.string().min(1).max(300).optional(),
  parameters: z.record(z.string(), manifestValueSchema).optional(),
  runManifestId: z.string().optional(),
  progress: progressSchema.optional(),
  detail: z.string().optional(),
  queuedAt: z.string().datetime(),
  startedAt: z.string().datetime().optional(),
  updatedAt: z.string().datetime(),
  endedAt: z.string().datetime().optional(),
  error: z.string().optional(),
  failure: z
    .object({
      code: z.string().min(1),
      message: z.string(),
      retryable: z.boolean(),
      at: z.string().datetime(),
    })
    .optional(),
  warnings: z.array(z.string()),
  lastCheckpoint: z
    .object({
      sequence: z.number().int().positive(),
      at: z.string().datetime(),
      progress: progressSchema,
      detail: z.string().optional(),
      cursor: manifestValueSchema.optional(),
    })
    .optional(),
  throughputPerSecond: z.number().nonnegative().optional(),
  etaAt: z.string().datetime().optional(),
  attempt: z.number().int().positive(),
  maxRetries: z.number().int().nonnegative(),
  resourceBudget: z
    .object({
      maxRuntimeMs: z.number().int().positive().optional(),
      maxCostUsd: z.number().nonnegative().optional(),
      maxInputTokens: z.number().int().positive().optional(),
    })
    .optional(),
  resumable: z.boolean(),
  cancellable: z.boolean(),
  cancelRequestedAt: z.string().datetime().optional(),
});
