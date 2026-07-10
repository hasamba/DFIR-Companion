import type { Express, Request, Response } from "express";
import { join, relative } from "node:path";
import { readFile, stat, readdir, mkdir } from "node:fs/promises";
import { isLogLevel } from "../logging/logger.js";
import { getDiskStats, getDiskWarningLevel, diskWarnEnvThresholds } from "../analysis/diskWarn.js";
import {
  buildAiDiagnostics, summarizeImportAttempts, countByKind, aggregateCaseSizes, buildDiagnosticsText,
  type DiagnosticsReport, type ScannedFile,
} from "../analysis/diagnostics.js";
import {
  buildPreflightReport, buildPreflightText,
  type PreflightItem, type PreflightReport,
} from "../analysis/preflight.js";
import { getAppVersion } from "../version.js";
import {
  resolveUpdateMode, buildUpdateStatus, DEFAULT_UPDATE_REPO, type UpdateMode,
} from "../analysis/updateCheck.js";
import { performUpdateCheck } from "../analysis/updateCheckRun.js";
import { HUNT_PLATFORMS } from "../analysis/huntPlatforms.js";
import { ProviderError } from "../providers/provider.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { RouteContext } from "./context.js";

// Recursively collect files (path relative to `baseDir`, size in bytes) under `dir` for the
// diagnostics size scan (#118). Best-effort: unreadable dirs/files are skipped, never thrown.
// `budget.n` bounds the total files visited so a pathological case can't run unbounded.
async function walkCaseFiles(
  dir: string,
  baseDir: string,
  caseId: string,
  out: ScannedFile[],
  budget: { n: number },
): Promise<void> {
  if (budget.n <= 0) return;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (budget.n <= 0) return;
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      await walkCaseFiles(full, baseDir, caseId, out, budget);
    } else if (e.isFile()) {
      budget.n--;
      try {
        const st = await stat(full);
        out.push({ caseId, path: relative(baseDir, full), bytes: st.size });
      } catch {
        /* unreadable file — skip */
      }
    }
  }
}

/**
 * System/operational routes: health, log-level, disk-stats, diagnostics/*, update-check/*.
 *
 * Reference template for the router-split domains. Conventions established here:
 * - Handlers are moved VERBATIM out of createApp — only free variables are rebound to `ctx`.
 * - Destructure the STABLE ctx fields/helpers once at the top if you like, but CALL LIVE
 *   ACCESSORS (ctx.importerRegistry(), ctx.irisClient(), …) INSIDE each handler so the current
 *   binding is re-read per request; never hoist them to this registration scope (see RouteContext).
 * - Keep domain-local helpers (e.g. walkCaseFiles, currentUpdateMode, the preflight cache) private
 *   to this file — module scope for stateless helpers, closure scope for per-app state.
 */
export function registerSystemRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, serverLogger, hasAiProvider } = ctx;

  // Lightweight reachability check used by the extension's connection status.
  // aiEnabled tells the dashboard whether an AI provider is configured at all.
  app.get("/health", (_req: Request, res: Response) => {
    const irisClient = ctx.irisClient();
    const dropWatchEnabled = ctx.dropWatchEnabled();
    const importerRegistry = ctx.importerRegistry();
    res.status(200).json({ ok: true, service: "dfir-companion", aiEnabled: hasAiProvider(), enrichEnabled: (options.enrichmentProviders?.length ?? 0) > 0, customerExposureEnabled: (options.customerExposureProviders?.length ?? 0) > 0, velociraptorEnabled: !!options.velociraptorClient, irisEnabled: !!irisClient, timesketchEnabled: !!options.timesketchClient, notionEnabled: !!options.notionClient, clickupEnabled: !!options.clickupClient, notificationsEnabled: !!options.notificationStore, notifyEmailEnabled: !!options.notifyEmailEnabled, pushEnabled: !!options.pushTokenStore || !!(options.pushToken && options.pushToken.trim()), pushTokenGlobal: !!(options.pushToken && options.pushToken.trim()), huntPlatforms: options.huntPlatforms ?? [...HUNT_PLATFORMS], logLevel: serverLogger.getLevel(), kevEnabled: !!options.kevStore, secondOpinionEnabled: !!options.secondOpinionEnabled, dropEnabled: dropWatchEnabled && !!options.dropStatusStore, toolsEnabled: !!options.toolRunner, customImporters: importerRegistry.importers.size, updateCheckLocked: resolveUpdateMode(options.updateCheckEnv, undefined).locked, geoMapTileUrl: process.env.DFIR_GEOMAP_TILE_URL || "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" });
  });

  // ── Update check (opt-in "newer release available" notice; NEVER downloads) ──────────────
  const updateRepo = options.updateRepo ?? DEFAULT_UPDATE_REPO;
  const updateAppVersion = options.appVersion ?? getAppVersion();
  const updateEnv = options.updateCheckEnv;
  const updateFetch = options.updateFetch ?? fetch;

  async function currentUpdateMode(): Promise<UpdateMode> {
    const stored = options.updateCheckStore ? (await options.updateCheckStore.load()).enabled : undefined;
    return resolveUpdateMode(updateEnv, stored);
  }

  app.get("/update-check", async (_req: Request, res: Response) => {
    try {
      const mode = await currentUpdateMode();
      const result = options.updateCheckStore ? (await options.updateCheckStore.load()).result : undefined;
      res.status(200).json(buildUpdateStatus(mode, updateAppVersion, result));
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/update-check/settings", async (req: Request, res: Response) => {
    try {
      if (!options.updateCheckStore) return res.status(404).json({ error: "update-check store not configured — restart the server" });
      if ((await currentUpdateMode()).locked) return res.status(423).json({ error: "update checks are disabled by DFIR_UPDATE_CHECK=0" });
      const enabled = (req.body as { enabled?: unknown })?.enabled;
      if (typeof enabled !== "boolean") return res.status(400).json({ error: "enabled must be a boolean" });
      await options.updateCheckStore.setEnabled(enabled);
      const mode = await currentUpdateMode();
      const result = (await options.updateCheckStore.load()).result;
      return res.status(200).json(buildUpdateStatus(mode, updateAppVersion, result));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/update-check/run", async (_req: Request, res: Response) => {
    try {
      if (!options.updateCheckStore) return res.status(404).json({ error: "update-check store not configured — restart the server" });
      const mode = await currentUpdateMode();
      if (mode.locked) return res.status(423).json({ error: "update checks are disabled by DFIR_UPDATE_CHECK=0" });
      if (!mode.enabled) return res.status(400).json({ error: "enable update checks first" });
      const result = await performUpdateCheck({ store: options.updateCheckStore, repo: updateRepo, fetchFn: updateFetch, now: Date.now() });
      return res.status(200).json(buildUpdateStatus(mode, updateAppVersion, result));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Read / change the live log verbosity (debug | info | warn | error). The dashboard's
  // Settings → Logging control flips this at runtime — no server restart — and it takes
  // effect immediately across the server AND the analysis pipeline (they share one logger).
  app.get("/log-level", (_req: Request, res: Response) => {
    res.status(200).json({ level: serverLogger.getLevel(), levels: ["debug", "info", "warn", "error"] });
  });
  app.post("/log-level", (req: Request, res: Response) => {
    const level = (req.body as { level?: unknown })?.level;
    if (!isLogLevel(level)) {
      return res.status(400).json({ error: "level must be one of: debug, info, warn, error" });
    }
    const previous = serverLogger.getLevel();
    serverLogger.setLevel(level);
    serverLogger.info(`[log] level changed ${previous} -> ${level}`);
    return res.status(200).json({ level: serverLogger.getLevel() });
  });

  app.get("/disk-stats", async (_req: Request, res: Response) => {
    try {
      const stats = await getDiskStats(store.casesRoot);
      const thresholds = diskWarnEnvThresholds();
      const level = getDiskWarningLevel(stats.usedPct, thresholds);
      return res.status(200).json({ ...stats, level, thresholds });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Health / Diagnostics (#118) ──────────────────────────────────────────────────────────
  // Operator-facing system state to troubleshoot ingestion / AI problems without digging through
  // logs. Fast by design — NO recursive directory scan here (per-case sizes are the separate
  // compute-on-demand /diagnostics/sizes endpoint), so this stays well under the <2s budget. All
  // AI config is REDACTED (buildAiDiagnostics never reads an API key), so the JSON + the
  // copy-to-clipboard text blob are safe to share.
  app.get("/diagnostics", async (_req: Request, res: Response) => {
    try {
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
        disk = { totalBytes: 0, freeBytes: 0, usedPct: 0, level: getDiskWarningLevel(0, thresholds), thresholds };
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
          if (Number.isFinite(t)) oldestBufferedAtMs = oldestBufferedAtMs == null ? t : Math.min(oldestBufferedAtMs, t);
        }
      }
      // Cases whose last analysis window failed (pending_analysis.json on disk).
      const pendingChecks = await Promise.all(cases.map(async (c) => {
        try { await stat(join(store.stateDir(c.caseId), "pending_analysis.json")); return 1; } catch { return 0; }
      }));
      const pendingAnalysisCases = pendingChecks.reduce<number>((a, b) => a + b, 0);

      // Import attempts: count the per-case imports.jsonl audit lines (durable; survives restart).
      const importTimestamps: number[] = [];
      await Promise.all(cases.map(async (c) => {
        try {
          const log = await readFile(store.importsLogPath(c.caseId), "utf8");
          for (const line of log.split("\n")) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            try {
              const rec = JSON.parse(trimmed) as { importedAt?: string };
              const ms = Date.parse(rec.importedAt ?? "");
              if (Number.isFinite(ms)) importTimestamps.push(ms);
            } catch { /* skip a malformed audit line */ }
          }
        } catch { /* no imports for this case */ }
      }));

      const now = Date.now();
      const ai = buildAiDiagnostics(process.env);
      const report: DiagnosticsReport = {
        generatedAt: new Date(now).toISOString(),
        uptimeMs: now - appStartedAt,
        casesRoot: store.casesRoot,
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
        },
        backups: options.backupManager
          ? await (async () => {
              let totalCount = 0;
              let totalBytes = 0;
              await Promise.all(cases.map(async (c) => {
                try {
                  const s = await options.backupManager!.summary(c.caseId);
                  totalCount += s.count;
                  totalBytes += s.totalBytes;
                } catch { /* best-effort */ }
              }));
              return { enabled: true, totalCount, totalBytes, retain: options.backupManager!.config.retain };
            })()
          : { enabled: false, totalCount: 0, totalBytes: 0, retain: 0 },
      };
      return res.status(200).json({ report, text: buildDiagnosticsText(report) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-case sizes + top-N largest evidence files. SEPARATE from /diagnostics because it walks the
  // whole cases tree (compute-on-demand, behind the dashboard's "Compute sizes" button) so the
  // default diagnostics load stays cheap. Bounded to DFIR_DIAG_MAX_FILES files (default 100k).
  app.get("/diagnostics/sizes", async (req: Request, res: Response) => {
    try {
      const topN = Math.min(50, Math.max(1, Number(req.query.top) || 10));
      const budget = { n: Number(process.env.DFIR_DIAG_MAX_FILES) || 100_000 };
      const cases = await store.listCases();
      const files: ScannedFile[] = [];
      for (const c of cases) {
        if (budget.n <= 0) break;
        const dir = store.caseDir(c.caseId);
        await walkCaseFiles(dir, dir, c.caseId, files, budget);
      }
      const report = aggregateCaseSizes(files, topN);
      return res.status(200).json({ ...report, truncated: budget.n <= 0, scannedFiles: files.length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Lightweight live AI connectivity test (validates auth + timeout against the CURRENT config).
  // Makes ONE tiny request. 501 when no provider is configured; a reachable-but-failing provider
  // returns 200 { ok:false, kind, error } so the dashboard renders the actionable error inline.
  app.post("/diagnostics/ai-test", async (_req: Request, res: Response) => {
    const provider = options.aiTestProvider?.();
    if (!provider) {
      return res.status(501).json({ ok: false, error: "AI provider not configured — set DFIR_AI_PROVIDER / DFIR_AI_MODEL / DFIR_AI_KEY in Settings → AI, then restart the server" });
    }
    const startedAt = Date.now();
    try {
      // The OpenAI/OpenRouter providers always send response_format: json_object, and OpenAI's JSON
      // mode REQUIRES the literal word "json" somewhere in the messages (a 400 otherwise). So the probe
      // asks for a tiny JSON object — both messages mention "json" — which also exercises the real
      // request shape (auth + json_object + parse) across every provider, not just bare connectivity.
      const result = await provider.analyze({
        systemPrompt: "You are a connectivity probe. Reply ONLY with the JSON object {\"ok\":true} and nothing else.",
        userPrompt: "Return the JSON object {\"ok\":true}.",
        images: [],
      });
      const latencyMs = Date.now() - startedAt;
      const reply = (result.rawText ?? "").trim().slice(0, 120);
      serverLogger.info(`[diagnostics] AI test ok provider=${provider.name} latency=${latencyMs}ms`);
      return res.status(200).json({ ok: true, provider: provider.name, latencyMs, reply });
    } catch (err) {
      const latencyMs = Date.now() - startedAt;
      const kind = err instanceof ProviderError ? err.kind : "other";
      serverLogger.info(`[diagnostics] AI test failed provider=${provider.name} kind=${kind}: ${(err as Error).message}`);
      return res.status(200).json({ ok: false, provider: provider.name, latencyMs, kind, error: (err as Error).message });
    }
  });

  // ── Startup pre-flight (#179) ─────────────────────────────────────────────────────────
  // Results are cached for PREFLIGHT_TTL_MS so opening the dashboard repeatedly is cheap.
  // A POST re-runs the checks immediately (the "Re-run" button in Settings → Diagnostics).
  // The user can disable checks entirely via POST /diagnostics/preflight/control { disabled:true }
  // (persisted in {casesRoot}/preflight/control.json so the setting survives restarts).
  const PREFLIGHT_TTL_MS = 30_000;
  let preflightCache: { report: PreflightReport; at: number } | null = null;

  const preflightControlPath = join(store.casesRoot, "preflight", "control.json");
  async function readPreflightDisabled(): Promise<boolean> {
    try {
      const raw = await readFile(preflightControlPath, "utf-8");
      return !!(JSON.parse(raw)?.disabled);
    } catch {
      return false;
    }
  }
  async function writePreflightControl(ctrl: { disabled: boolean }): Promise<void> {
    await mkdir(join(store.casesRoot, "preflight"), { recursive: true });
    await atomicWrite(preflightControlPath, JSON.stringify(ctrl, null, 2));
  }

  async function runPreflightChecks(): Promise<PreflightReport> {
    const allProviders = ctx.enrichmentProviders();
    const enrichHealth = ctx.enrichHealth();
    // Honour the persistent disable flag — return an empty disabled report immediately.
    if (await readPreflightDisabled()) {
      const report = buildPreflightReport([], new Date().toISOString(), 0, true);
      preflightCache = { report, at: Date.now() };
      return report;
    }

    const startedAt = Date.now();
    const items: PreflightItem[] = [];

    // 1. AI provider — CRITICAL: without it, analysis and synthesis don't work.
    const aiProvider = options.aiTestProvider?.();
    if (!aiProvider) {
      items.push({ name: "AI provider", ok: false, critical: true, detail: "not configured — set DFIR_AI_PROVIDER / DFIR_AI_MODEL / DFIR_AI_KEY in .env, then restart" });
    } else {
      try {
        await aiProvider.analyze({
          systemPrompt: "You are a connectivity probe. Reply ONLY with the JSON object {\"ok\":true} and nothing else.",
          userPrompt: "Return the JSON object {\"ok\":true}.",
          images: [],
        });
        items.push({ name: "AI provider", ok: true, critical: true, detail: `${aiProvider.name} reachable` });
      } catch (err) {
        const kind = err instanceof ProviderError ? err.kind : "other";
        items.push({ name: "AI provider", ok: false, critical: true, detail: `${aiProvider.name} ${kind}: ${(err as Error).message}` });
      }
    }

    // 2. Enrichment providers — non-critical (opt-in). A provider is only in allProviders when
    //    it's configured (keyed providers are registered only when their DFIR_*_KEY is set), so
    //    presence here == "configured". Local self-hosted instances (MISP/YETI/OpenCTI) implement
    //    probe() — we verify they're reachable + auth works. External SaaS (VirusTotal, AbuseIPDB,
    //    CrowdStrike, Hunting.ch, Shodan, …) have NO probe(): we deliberately do NOT call them at
    //    startup (OPSEC: no automatic third-party traffic, no wasted API quota) and only confirm
    //    they're configured.
    for (const p of allProviders) {
      if (p.probe) {
        const h = await enrichHealth.check(p).catch(() => ({ ok: false as const, detail: "probe error" }));
        items.push({
          name: `Enrichment: ${p.name}`,
          ok: h.ok,
          critical: false,
          detail: h.detail ?? (h.ok ? "reachable" : "unreachable"),
        });
      } else {
        items.push({
          name: `Enrichment: ${p.name}`,
          ok: true,
          critical: false,
          detail: "configured (no live check)",
        });
      }
    }

    // 3. Velociraptor — non-critical (hunt-only feature).
    if (options.velociraptorClient) {
      try {
        await options.velociraptorClient.listClients();
        items.push({ name: "Velociraptor", ok: true, critical: false, detail: "API reachable" });
      } catch (err) {
        items.push({ name: "Velociraptor", ok: false, critical: false, detail: (err as Error).message });
      }
    }

    const report = buildPreflightReport(items, new Date().toISOString(), Date.now() - startedAt);
    preflightCache = { report, at: Date.now() };
    return report;
  }

  app.get("/diagnostics/preflight", async (_req: Request, res: Response) => {
    if (preflightCache && Date.now() - preflightCache.at < PREFLIGHT_TTL_MS) {
      return res.status(200).json({ report: preflightCache.report, text: buildPreflightText(preflightCache.report) });
    }
    try {
      const report = await runPreflightChecks();
      return res.status(200).json({ report, text: buildPreflightText(report) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Force a fresh run — used by the "Re-run" button in Settings → Diagnostics.
  app.post("/diagnostics/preflight", async (_req: Request, res: Response) => {
    preflightCache = null;
    try {
      const report = await runPreflightChecks();
      return res.status(200).json({ report, text: buildPreflightText(report) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Read / toggle the persistent disable flag.
  app.get("/diagnostics/preflight/control", async (_req: Request, res: Response) => {
    const disabled = await readPreflightDisabled().catch(() => false);
    return res.status(200).json({ disabled });
  });
  app.post("/diagnostics/preflight/control", async (req: Request, res: Response) => {
    const { disabled } = req.body as { disabled?: boolean };
    if (typeof disabled !== "boolean") return res.status(400).json({ error: "disabled must be boolean" });
    await writePreflightControl({ disabled });
    preflightCache = null;
    return res.status(200).json({ disabled });
  });

  // Hand the run function to startServer so it can fire it after app.listen().
  options.onPreflightReady?.(runPreflightChecks);
}
