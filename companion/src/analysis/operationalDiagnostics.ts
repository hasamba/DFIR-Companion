import type { Job } from "./jobRegistry.js";
import {
  OPERATIONAL_DEFAULT_RETENTION_MS,
  type AiMetric,
  type CapacityMetric,
  type ExportMetric,
  type ImportMetric,
  type OperationalMetric,
  type QueryMetric,
  type WebSocketMetric,
} from "./operationalMetrics.js";

const JOB_STALL_MS = 5 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface SlowOperation {
  name: string;
  durationMs: number;
  remediation: string;
}

export interface OperationalDiagnostics {
  enabled: boolean;
  retentionDays: number;
  sampleCount: number;
  imports: { runs: number; rowsRead: number; accepted: number; rejected: number; promoted: number };
  queries: { count: number; p50Ms: number; p95Ms: number; unindexed: number };
  jobs: { queued: number; running: number; retries: number; stalled: number; throughputPerSecond: number };
  ai: {
    calls: number;
    failures: number;
    retries: number;
    rateLimits: number;
    p50Ms: number;
    p95Ms: number;
    inputTokens: number;
    outputTokens: number;
    costUsd: number;
  };
  exports: { count: number; failures: number; p95Ms: number; outputBytes: number };
  websocket: {
    active: number;
    connects: number;
    reconnects: number;
    disconnects: number;
    rejects: number;
    dropped: number;
  };
  capacity: {
    databaseBytes: number;
    diskFreeBytes: number;
    rssBytes: number;
    heapUsedBytes: number;
    growthBytesPerDay: number | null;
    projectedDaysRemaining: number | null;
  };
  slowest: { importer: SlowOperation | null; query: SlowOperation | null; job: SlowOperation | null };
  warnings: string[];
}

export function percentile(values: readonly number[], p: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const rank = Math.max(0, Math.ceil(Math.min(1, Math.max(0, p)) * sorted.length) - 1);
  return sorted[rank] ?? 0;
}

function activeJobDuration(job: Job, now: number): number {
  const start = Date.parse(job.startedAt ?? job.queuedAt);
  const end = Date.parse(job.endedAt ?? "") || now;
  return Number.isFinite(start) ? Math.max(0, end - start) : 0;
}

function slowestJob(jobs: readonly Job[], now: number): SlowOperation | null {
  const slowest = [...jobs].sort(
    (left, right) => activeJobDuration(right, now) - activeJobDuration(left, now),
  )[0];
  if (!slowest) return null;
  const stalled =
    !["succeeded", "failed", "cancelled", "interrupted"].includes(slowest.status) &&
    now - Date.parse(slowest.updatedAt) >= JOB_STALL_MS;
  return {
    name: slowest.kind,
    durationMs: activeJobDuration(slowest, now),
    remediation: stalled
      ? "Open Jobs, inspect the last checkpoint, then retry or cancel the stalled work."
      : "Review this job type's progress and concurrency before starting more heavy work.",
  };
}

function capacityDiagnostics(samples: readonly CapacityMetric[]): OperationalDiagnostics["capacity"] {
  const ordered = [...samples].sort((left, right) => left.at.localeCompare(right.at));
  const latest = ordered[ordered.length - 1];
  const first = ordered[0];
  let growthBytesPerDay: number | null = null;
  let projectedDaysRemaining: number | null = null;
  if (first && latest && first !== latest) {
    const elapsed = Date.parse(latest.at) - Date.parse(first.at);
    const growth = latest.databaseBytes - first.databaseBytes;
    if (elapsed > 0 && growth > 0) {
      growthBytesPerDay = growth / (elapsed / DAY_MS);
      projectedDaysRemaining = latest.diskFreeBytes / growthBytesPerDay;
    }
  }
  return {
    databaseBytes: latest?.databaseBytes ?? 0,
    diskFreeBytes: latest?.diskFreeBytes ?? 0,
    rssBytes: latest?.rssBytes ?? 0,
    heapUsedBytes: latest?.heapUsedBytes ?? 0,
    growthBytesPerDay,
    projectedDaysRemaining,
  };
}

function importDiagnostics(
  imports: readonly ImportMetric[],
  promotions: readonly Extract<OperationalMetric, { type: "import_promotion" }>[],
): OperationalDiagnostics["imports"] {
  return {
    runs: imports.length,
    rowsRead: imports.reduce((sum, sample) => sum + sample.rowsRead, 0),
    accepted: imports.reduce((sum, sample) => sum + sample.accepted, 0),
    rejected: imports.reduce((sum, sample) => sum + sample.rejected, 0),
    promoted:
      imports.reduce((sum, sample) => sum + sample.promoted, 0) +
      promotions.reduce((sum, sample) => sum + sample.promoted, 0),
  };
}

function queryDiagnostics(queries: readonly QueryMetric[]): OperationalDiagnostics["queries"] {
  const durations = queries.map((sample) => sample.durationMs);
  return {
    count: queries.length,
    p50Ms: percentile(durations, 0.5),
    p95Ms: percentile(durations, 0.95),
    unindexed: queries.filter((sample) => sample.index === "none").length,
  };
}

function jobDiagnostics(jobs: readonly Job[], now: number): OperationalDiagnostics["jobs"] {
  const active = jobs.filter((job) => job.status === "queued" || job.status === "running");
  return {
    queued: jobs.filter((job) => job.status === "queued").length,
    running: jobs.filter((job) => job.status === "running").length,
    retries: jobs.reduce((sum, job) => sum + Math.max(0, job.attempt - 1), 0),
    stalled: active.filter((job) => now - Date.parse(job.updatedAt) >= JOB_STALL_MS).length,
    throughputPerSecond: active.reduce((sum, job) => sum + (job.throughputPerSecond ?? 0), 0),
  };
}

function aiDiagnostics(samples: readonly AiMetric[], retries: number): OperationalDiagnostics["ai"] {
  const durations = samples.map((sample) => sample.durationMs);
  return {
    calls: samples.length,
    failures: samples.filter((sample) => !sample.success).length,
    retries,
    rateLimits: samples.filter((sample) => sample.errorKind === "rate_limit").length,
    p50Ms: percentile(durations, 0.5),
    p95Ms: percentile(durations, 0.95),
    inputTokens: samples.reduce((sum, sample) => sum + sample.inputTokens, 0),
    outputTokens: samples.reduce((sum, sample) => sum + sample.outputTokens, 0),
    costUsd: samples.reduce((sum, sample) => sum + sample.costUsd, 0),
  };
}

function exportDiagnostics(samples: readonly ExportMetric[]): OperationalDiagnostics["exports"] {
  return {
    count: samples.length,
    failures: samples.filter((sample) => !sample.success).length,
    p95Ms: percentile(
      samples.map((sample) => sample.durationMs),
      0.95,
    ),
    outputBytes: samples.reduce((sum, sample) => sum + sample.outputBytes, 0),
  };
}

function websocketDiagnostics(samples: readonly WebSocketMetric[]): OperationalDiagnostics["websocket"] {
  return {
    active: 0,
    connects: samples.filter((sample) => sample.event === "connect").length,
    reconnects: samples.filter((sample) => sample.event === "reconnect").length,
    disconnects: samples.filter((sample) => sample.event === "disconnect").length,
    rejects: samples.filter((sample) => sample.event === "reject").length,
    dropped: samples.filter((sample) => sample.event === "error" || sample.event === "reap").length,
  };
}

function slowOperations(
  imports: readonly ImportMetric[],
  queries: readonly QueryMetric[],
  jobs: readonly Job[],
  now: number,
): OperationalDiagnostics["slowest"] {
  const importer = [...imports].sort((left, right) => right.durationMs - left.durationMs)[0];
  const query = [...queries].sort((left, right) => right.durationMs - left.durationMs)[0];
  return {
    importer: importer
      ? {
          name: importer.importer,
          durationMs: importer.durationMs,
          remediation:
            importer.rejected > importer.accepted
              ? "Review this parser's rejection reasons and source format before re-importing."
              : "Split very large artifacts or reduce competing background work.",
        }
      : null,
    query: query
      ? {
          name: query.operation,
          durationMs: query.durationMs,
          remediation:
            query.index === "none"
              ? "Use an indexed filter such as time, host, source, severity, IOC, or technique."
              : "Narrow the time range or page size before repeating this query.",
        }
      : null,
    job: slowestJob(jobs, now),
  };
}

function diagnosticWarnings(
  capacity: OperationalDiagnostics["capacity"],
  jobs: OperationalDiagnostics["jobs"],
  queries: readonly QueryMetric[],
): string[] {
  const warnings: string[] = [];
  if (capacity.projectedDaysRemaining !== null && capacity.projectedDaysRemaining <= 14) {
    warnings.push(
      `Projected case growth could exhaust disk in ${capacity.projectedDaysRemaining.toFixed(1)} day(s); free space or move cases now.`,
    );
  }
  if (jobs.stalled)
    warnings.push(`${jobs.stalled} background job(s) have not advanced for at least five minutes.`);
  if (queries.some((sample) => sample.index === "none"))
    warnings.push("One or more timeline queries did not use an index.");
  return warnings;
}

export function summarizeOperationalMetrics(
  samples: readonly OperationalMetric[],
  jobs: readonly Job[] = [],
  now = Date.now(),
  retentionMs = OPERATIONAL_DEFAULT_RETENTION_MS,
): OperationalDiagnostics {
  const imports = samples.filter((sample): sample is ImportMetric => sample.type === "import");
  const promotions = samples.filter((sample) => sample.type === "import_promotion");
  const queries = samples.filter((sample): sample is QueryMetric => sample.type === "query");
  const ai = samples.filter((sample): sample is AiMetric => sample.type === "ai");
  const exports = samples.filter((sample): sample is ExportMetric => sample.type === "export");
  const websocket = samples.filter((sample): sample is WebSocketMetric => sample.type === "websocket");
  const capacity = capacityDiagnostics(
    samples.filter((sample): sample is CapacityMetric => sample.type === "capacity"),
  );
  const jobSummary = jobDiagnostics(jobs, now);
  return {
    enabled: true,
    retentionDays: retentionMs / DAY_MS,
    sampleCount: samples.length,
    imports: importDiagnostics(imports, promotions),
    queries: queryDiagnostics(queries),
    jobs: jobSummary,
    ai: aiDiagnostics(ai, samples.filter((sample) => sample.type === "ai_retry").length),
    exports: exportDiagnostics(exports),
    websocket: websocketDiagnostics(websocket),
    capacity,
    slowest: slowOperations(imports, queries, jobs, now),
    warnings: diagnosticWarnings(capacity, jobSummary, queries),
  };
}

export function disabledOperationalDiagnostics(
  retentionMs = OPERATIONAL_DEFAULT_RETENTION_MS,
): OperationalDiagnostics {
  return { ...summarizeOperationalMetrics([], [], Date.now(), retentionMs), enabled: false };
}
