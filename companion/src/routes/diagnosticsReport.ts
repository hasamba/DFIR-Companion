import { join } from "node:path";
import { readFile, stat } from "node:fs/promises";
import { getDiskStats, getDiskWarningLevel, diskWarnEnvThresholds } from "../analysis/diskWarn.js";
import {
  buildAiDiagnostics,
  summarizeImportAttempts,
  countByKind,
  buildDiagnosticsText,
  summarizeImporterHealth,
  type DiagnosticsReport,
} from "../analysis/diagnostics.js";
import { getAppVersion } from "../version.js";
import type { RouteContext } from "./context.js";
import {
  disabledOperationalDiagnostics,
  summarizeOperationalMetrics,
} from "../analysis/operationalDiagnostics.js";
import { buildSupportBundle, type SupportBundle } from "../analysis/supportBundle.js";

/**
 * The Health/Diagnostics report (#118), built once for two callers: `GET /diagnostics` (the page and
 * the copy-to-clipboard text) and `POST /diagnostics/support-bundle` (#1735), which puts the same
 * text in the redacted zip. It lived inline in the GET handler; the bundle must regenerate it
 * server-side rather than accept the page's copy, so a client can never inject text into the zip.
 */
export interface DiagnosticsPayload {
  report: DiagnosticsReport;
  text: string;
  support: SupportBundle;
  supportFilename: string;
  supportPreview: string;
}

export async function buildDiagnosticsPayload(ctx: RouteContext): Promise<DiagnosticsPayload> {
  const { store, options } = ctx;
  const buffers = ctx.captureBuffers();
  const synthInFlight = ctx.synthInFlight();
  const importerRegistry = ctx.importerRegistry();
  const appStartedAt = ctx.appStartedAt;
  const recentAiErrors = ctx.recentAiErrors;
  const recentImportFailures = ctx.recentImportFailures;
  const thresholds = diskWarnEnvThresholds();
  let disk: DiagnosticsReport["disk"];
  try {
    const stats = await getDiskStats(store.casesRoot);
    disk = { ...stats, level: getDiskWarningLevel(stats.usedPct, thresholds), thresholds };
  } catch {
    // statfs can fail on exotic mounts — report zeros rather than 500 the whole page.
    disk = {
      totalBytes: 0,
      freeBytes: 0,
      usedPct: 0,
      level: getDiskWarningLevel(0, thresholds),
      thresholds,
    };
  }

  const cases = await store.listCases();
  const archived = cases.filter((c) => c.status === "archived").length;
  const open = cases.filter((c) => c.status !== "closed" && c.status !== "archived").length;

  // Queue: in-memory capture buffers + synthesis in-flight + on-disk failure markers.
  let bufferedCaptures = 0;
  let casesBuffering = 0;
  let oldestBufferedAtMs: number | null = null;
  for (const buf of buffers.values()) {
    if (buf.length === 0) continue;
    casesBuffering++;
    bufferedCaptures += buf.length;
    for (const c of buf) {
      const t = Date.parse(c.timestamp);
      if (Number.isFinite(t))
        oldestBufferedAtMs = oldestBufferedAtMs == null ? t : Math.min(oldestBufferedAtMs, t);
    }
  }
  // Cases whose last analysis window failed (pending_analysis.json on disk).
  const pendingChecks = await Promise.all(
    cases.map(async (c) => {
      try {
        await stat(join(store.stateDir(c.caseId), "pending_analysis.json"));
        return 1;
      } catch {
        return 0;
      }
    }),
  );
  const pendingAnalysisCases = pendingChecks.reduce<number>((a, b) => a + b, 0);

  // Import attempts: count the per-case imports.jsonl audit lines (durable; survives restart).
  const importTimestamps: number[] = [];
  await Promise.all(
    cases.map(async (c) => {
      try {
        const log = await readFile(store.importsLogPath(c.caseId), "utf8");
        for (const line of log.split("\n")) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try {
            const rec = JSON.parse(trimmed) as { importedAt?: string };
            const ms = Date.parse(rec.importedAt ?? "");
            if (Number.isFinite(ms)) importTimestamps.push(ms);
          } catch {
            /* skip a malformed audit line */
          }
        }
      } catch {
        /* no imports for this case */
      }
    }),
  );

  const now = Date.now();
  const ai = buildAiDiagnostics(process.env);
  const metrics = options.operationalMetrics;
  const databaseBytes = options.stateStore
    ? (
        await Promise.all(
          cases.map(async (item) => {
            try {
              return (await stat(options.stateStore!.databasePath(item.caseId))).size;
            } catch {
              return 0;
            }
          }),
        )
      ).reduce((sum, bytes) => sum + bytes, 0)
    : 0;
  const memory = process.memoryUsage();
  await metrics?.record({
    type: "capacity",
    databaseBytes,
    diskFreeBytes: disk.freeBytes,
    diskTotalBytes: disk.totalBytes,
    rssBytes: memory.rss,
    heapUsedBytes: memory.heapUsed,
  });
  const baseOperational = metrics?.enabled
    ? summarizeOperationalMetrics(
        await metrics.snapshot(),
        options.jobManager?.list() ?? [],
        now,
        metrics.retentionMs,
      )
    : disabledOperationalDiagnostics(metrics?.retentionMs);
  const operational = {
    ...baseOperational,
    websocket: {
      ...baseOperational.websocket,
      active: Math.max(0, options.liveConnectionCount?.() ?? 0),
    },
  };
  const report: DiagnosticsReport = {
    generatedAt: new Date(now).toISOString(),
    uptimeMs: now - appStartedAt,
    operational,
    disk,
    cases: { count: cases.length, open, closed: cases.length - open - archived, archived },
    queue: {
      bufferedCaptures,
      casesBuffering,
      oldestBufferedAgeMs: oldestBufferedAtMs == null ? null : Math.max(0, now - oldestBufferedAtMs),
      synthInFlight: synthInFlight.size,
      pendingAnalysisCases,
    },
    ai: { ...ai, recentErrors: recentAiErrors.slice(0, 20), errorCounts: countByKind(recentAiErrors) },
    importers: {
      attempts: summarizeImportAttempts(importTimestamps, now),
      recentFailures: recentImportFailures.slice(0, 20),
      customImporters: importerRegistry.importers.size,
      perImporter: summarizeImporterHealth(importerRegistry.meta, ctx.importerRunStats),
      loadErrors: importerRegistry.errors,
    },
    backups: options.backupManager
      ? await (async () => {
          const { retain, maxBytes } = options.backupManager!.config;
          let totalCount = 0;
          let totalBytes = 0;
          // Cases whose backups still exceed the per-case byte budget after pruning — only
          // possible when every survivor is exempt (the newest backup, the newest
          // pre-synthesis one). Reported so the budget shown is the budget enforced (#295).
          let overBudgetCases = 0;
          await Promise.all(
            cases.map(async (c) => {
              try {
                const s = await options.backupManager!.summary(c.caseId);
                totalCount += s.count;
                totalBytes += s.totalBytes;
                if (maxBytes > 0 && s.totalBytes > maxBytes) overBudgetCases++;
              } catch {
                /* best-effort */
              }
            }),
          );
          return { enabled: true, totalCount, totalBytes, retain, maxBytes, overBudgetCases };
        })()
      : { enabled: false, totalCount: 0, totalBytes: 0, retain: 0, maxBytes: 0, overBudgetCases: 0 },
    // Reported from the last completed sweep, never computed here: re-hashing every artifact
    // is far too heavy for a route the dashboard polls (#231).
    evidenceIntegrity: options.integrityMonitor?.status() ?? {
      enabled: false,
      intervalMs: 0,
      verifyOnOpen: false,
      onOpenThrottleMs: 0,
      lastRunAt: null,
      lastDurationMs: null,
      casesVerified: 0,
      artifacts: 0,
      failedArtifacts: 0,
      chainBreaks: 0,
      problemCaseIds: [],
    },
  };
  const support = buildSupportBundle({
    generatedAt: report.generatedAt,
    version: options.appVersion ?? getAppVersion(),
    uptimeMs: report.uptimeMs,
    disk: {
      totalBytes: disk.totalBytes,
      freeBytes: disk.freeBytes,
      usedPct: disk.usedPct,
      level: disk.level,
    },
    cases: report.cases,
    queue: {
      queued: operational.jobs.queued,
      running: operational.jobs.running,
      stalled: operational.jobs.stalled,
    },
    ai: { configured: ai.configured, local: ai.local, errorsByKind: report.ai.errorCounts },
    operational,
  });
  return {
    report,
    text: buildDiagnosticsText(report),
    support,
    supportFilename: `dfir-companion-support-${report.generatedAt.slice(0, 10)}.json`,
    supportPreview: JSON.stringify(support, null, 2),
  };
}
