// Background-job registry (#225) — pure core.
//
// The Companion runs heavy operations (imports, LLM synthesis, threat-intel enrichment) off the
// HTTP response cycle. Historically their only trace was a transient "AI status" WS ping, so a
// stuck synthesis or a runaway enrichment could not be listed or stopped. This module models each
// such operation as a trackable Job with a stable id, status, progress and error, so the dashboard
// can render a Jobs panel and offer a Cancel button.
//
// Everything here is PURE and I/O-free (immutable transitions returning new objects; ids and
// timestamps are injected by the caller) so it unit-tests deterministically — the impure side
// (AbortControllers, WS broadcast, monotonic ids/clock) lives in jobManager.ts. Nothing is
// persisted: an in-flight job is meaningless after a restart, so the table is in-memory only.

export type JobKind = "import" | "synthesis" | "enrichment";
export type JobStatus = "queued" | "running" | "done" | "error" | "cancelled";

export interface Job {
  id: string;
  caseId: string;
  kind: JobKind;
  label?: string; // human-friendly subject, e.g. the import filename
  status: JobStatus;
  progress?: { done: number; total: number };
  detail?: string; // human-readable current step
  startedAt: string; // ISO
  endedAt?: string; // ISO, set on any terminal transition
  error?: string;
  // Only AI/network jobs can be aborted mid-flight (synthesis, enrichment, CSV/log import). A
  // deterministic import parses synchronously and is already done before a cancel could arrive.
  cancellable: boolean;
}

export interface JobTable {
  jobs: Job[];
}

export const TERMINAL_STATUSES: readonly JobStatus[] = ["done", "error", "cancelled"];

export function isTerminal(status: JobStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

export function emptyJobTable(): JobTable {
  return { jobs: [] };
}

export interface CreateJobInput {
  id: string;
  caseId: string;
  kind: JobKind;
  label?: string;
  detail?: string;
  cancellable?: boolean;
  now: string; // injected ISO timestamp
}

// Append a new RUNNING job. (We skip a distinct "queued" phase — the impure layer starts work
// immediately; "queued" stays in the type for a future real pool but is unused here.)
export function createJob(table: JobTable, input: CreateJobInput): JobTable {
  const job: Job = {
    id: input.id,
    caseId: input.caseId,
    kind: input.kind,
    label: input.label,
    detail: input.detail,
    status: "running",
    startedAt: input.now,
    cancellable: input.cancellable ?? false,
  };
  return { jobs: [...table.jobs, job] };
}

// Immutably replace the job with matching id via an updater. Unknown id → table unchanged.
function patchJob(table: JobTable, id: string, patch: (job: Job) => Job): JobTable {
  let changed = false;
  const jobs = table.jobs.map((j) => {
    if (j.id !== id) return j;
    changed = true;
    return patch(j);
  });
  return changed ? { jobs } : table;
}

export function progressJob(
  table: JobTable,
  id: string,
  progress: { done: number; total: number },
  detail?: string,
): JobTable {
  return patchJob(table, id, (j) =>
    isTerminal(j.status) ? j : { ...j, progress, ...(detail !== undefined ? { detail } : {}) },
  );
}

// Mark a job terminal. A no-op if the job is already terminal (so a late finish can't clobber a
// prior cancel, and a double-cancel is harmless).
function terminate(table: JobTable, id: string, status: JobStatus, now: string, extra: Partial<Job> = {}): JobTable {
  return patchJob(table, id, (j) => (isTerminal(j.status) ? j : { ...j, ...extra, status, endedAt: now }));
}

export function finishJob(table: JobTable, id: string, now: string): JobTable {
  return terminate(table, id, "done", now);
}

export function failJob(table: JobTable, id: string, error: string, now: string): JobTable {
  return terminate(table, id, "error", now, { error });
}

export function cancelJob(table: JobTable, id: string, now: string): JobTable {
  return terminate(table, id, "cancelled", now);
}

export function getJob(table: JobTable, id: string): Job | undefined {
  return table.jobs.find((j) => j.id === id);
}

// Newest first (by insertion order — ids are monotonic), optionally filtered by case.
export function listJobs(table: JobTable, opts: { caseId?: string } = {}): Job[] {
  const filtered = opts.caseId ? table.jobs.filter((j) => j.caseId === opts.caseId) : table.jobs;
  return [...filtered].reverse();
}

// Ring-buffer cap: when over the limit, evict the OLDEST terminal jobs (never a running one, so an
// in-flight job is never dropped from the registry). Insertion order is preserved.
export function capJobs(table: JobTable, max: number): JobTable {
  if (max <= 0 || table.jobs.length <= max) return table;
  const over = table.jobs.length - max;
  const evict = new Set<Job>();
  for (const j of table.jobs) {
    if (evict.size >= over) break;
    if (isTerminal(j.status)) evict.add(j);
  }
  if (evict.size === 0) return table;
  return { jobs: table.jobs.filter((j) => !evict.has(j)) };
}
