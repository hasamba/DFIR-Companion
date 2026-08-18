import express, { type Express } from "express";
// Patch Express 4's router so async route handlers that throw or reject are forwarded to the
// terminal error middleware (see the end of createApp) instead of hanging the client connection
// or surfacing an UnhandledPromiseRejection. Side-effect-only import; must load before any route
// is registered, so it stays at the top with express itself.
import "express-async-errors";
import { config as loadDotenv } from "dotenv";
import { isAbsolute, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "./storage/caseStore.js";
import { expandHome } from "./storage/expandHome.js";
import type { RouteContext } from "./routes/context.js";
import { loadOrCreateInstanceSecret } from "./analysis/instanceSecret.js";
import { ImportLock } from "./analysis/importLock.js";
import { resolveEnvFilePath } from "./settings/envManager.js";
import type { ForensicEvent } from "./analysis/stateTypes.js";
import { autoTagNewEvents } from "./analysis/taggerAuto.js";
import { parseAllowedOrigins, parseAllowedHosts, parseAllowedHostSuffixes } from "./http/originGuard.js";
import { readPublicAsset, isSeaRuntime } from "./serverAssets.js";
import type { PreflightReport } from "./analysis/preflight.js";
import { logLine, warnLine, getServerLogger } from "./logging/serverLogger.js";
import { installUnhandledRejectionNet } from "./logging/unhandledRejectionNet.js";
import { installUncaughtExceptionNet } from "./logging/uncaughtExceptionNet.js";
import {
  mountRequestPipeline,
  createUnlockStateReader,
  mountTerminalHandlers,
} from "./composition/httpStack.js";
import { registerAllRoutes } from "./composition/routeRegistry.js";
import { createRuntimeStores } from "./composition/runtimeStores.js";
import { startMaintenanceTasks, startPostListenTasks } from "./composition/maintenanceTasks.js";
import { buildAiRuntime } from "./composition/aiRuntime.js";
import { buildAppOptions } from "./composition/appWiring.js";
import { createDiagnosticsRings } from "./composition/diagnosticsRings.js";
import { createCaseAppliers } from "./composition/caseAppliers.js";
import { createEnrichmentEngine } from "./composition/enrichment.js";
import { createCaptureAnalysis } from "./composition/captureAnalysis.js";
import { createImportIngest } from "./composition/importIngest.js";
import { createExternalTools } from "./composition/externalTools.js";
import { createDropFolder } from "./composition/dropFolder.js";
import { createVeloMonitors } from "./composition/veloMonitors.js";
import { createVeloHunts } from "./composition/veloHunts.js";
import { createVeloExternalIngest } from "./composition/veloExternalIngest.js";
import { createSettingsReload } from "./composition/settingsReload.js";
import { createCaseNotifier } from "./composition/caseNotifier.js";
import { createOcrIndexer } from "./composition/ocrIndexer.js";
import { createAiControlCache } from "./composition/aiControlCache.js";
import { buildIrisClient, buildTimesketchClient } from "./composition/integrationClients.js";

// Re-exported so the five push scripts (scripts/push-*.ts, scripts/import-iris.ts) and the wiring
// tests keep importing them from `src/server.js` — the extraction moved the definitions, not the
// public surface (#384).
export { tlsFetchFor } from "./composition/tlsFetch.js";
export {
  buildClickUpClient,
  buildIrisClient,
  buildJiraClient,
  buildMispPushClient,
  buildNotionClient,
  buildServiceNowClient,
  buildTimesketchClient,
  clickupOptions,
  irisPushOptions,
  jiraOptions,
  mispPushOptions,
  notionPushOptions,
  servicenowOptions,
  timesketchPushOptions,
} from "./composition/integrationClients.js";

// Server logging. A single shared Logger tees every line to the console AND to log files (a global
// session log + per-case logs). The binding moved to logging/serverLogger.ts (#384) so that
// src/composition/ can warn without importing server.ts — see that file for why. Re-exported here
// because tests and the settings-reload path reach for these at `src/server.js`.
export { setServerLogger, getServerLogger } from "./logging/serverLogger.js";

// `AppOptions` (the createApp injection bag) and the AI-status event shape moved to
// composition/appOptions.ts (#416). 417 lines of pure type surface, plus the ~70-module import
// block that existed only to name it. Re-exported here so routes/context.ts,
// routes/presidioApproval.ts and the tests keep importing them from `src/server.js` — the
// definitions moved, the public surface did not, exactly as #384 did above.
export type { AiStatus, AiPhase, AiStatusEvent, AppOptions } from "./composition/appOptions.js";
import type { AppOptions } from "./composition/appOptions.js";

export function createApp(store: CaseStore, options: AppOptions = {}): Express {
  const app = express();
  // Signs/verifies case-unlock cookies (issue: case password protection). Persisted next to
  // the cases root so "remember on this computer" survives a server restart.
  const instanceSecret = loadOrCreateInstanceSecret(store.casesRoot);
  const hasAiProvider = (): boolean => options.aiConfigured ?? Boolean(options.pipeline?.hasAiProvider());
  // Serialize the load->save critical section for a case's investigation state so concurrent
  // mutations (a manual event/IOC add while background enrichment or re-synthesis saves)
  // cannot clobber each other (lost update). No-op when no StateLock is wired (tests).
  const runStateExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> =>
    options.stateLock ? options.stateLock.runExclusive(caseId, fn) : fn();
  // One import writer per case, across EVERY import path (routes, /push + MCP ingest, monitors, hunt
  // collects). Unlike the state lock this one is never optional: an import's "+N events" and its undo
  // checkpoint are only correct if nothing else writes inside its section. See analysis/importLock.ts.
  const importLock = options.importLock ?? new ImportLock();

  // Automatic content-based tagger: after an import dual-writes its new events into the super-timeline,
  // tag just those events (Timesketch tagger analyzer, ported). Best-effort + non-fatal + gated on
  // TAGGER_AUTO — see analysis/taggerAuto.ts. Bound once here so every import site can fire it.
  const autoTagImported = (caseId: string, added: ForensicEvent[]): Promise<void> =>
    autoTagNewEvents(
      {
        taggerStore: options.taggerStore,
        tagsStore: options.tagsStore,
        stateStore: options.stateStore,
        analysisRunStore: options.analysisRunStore,
        operationalMetrics: options.operationalMetrics,
        onTags: options.onTags,
        onState: options.onState,
        logLine,
      },
      caseId,
      added,
    );

  // Diagnostics runtime state (#118): the capped error rings + per-importer health behind the
  // Health/Diagnostics page. See composition/diagnosticsRings.ts for why redaction is on the way in.
  const {
    appStartedAt,
    recentImportFailures,
    recentAiErrors,
    importerRunStats,
    redactErr,
    recordImportFailure,
    recordAiError,
    recordImporterRun,
  } = createDiagnosticsRings(store.casesRoot);

  // Fire a notification event to all matching channels, deep-linked back to the case dashboard.
  // Best-effort, fire-and-forget: a transport failure NEVER bubbles into the request that triggered
  // it (notifications are a side channel). See composition/caseNotifier.ts.
  const dispatchNotify = createCaseNotifier(options);

  // Every layer a request traverses before it reaches a route — origin guard, CSP, demo gate,
  // request log, metrics, body parsers, error redaction, team auth and the per-case gates. Their
  // ORDER is the contract; see composition/httpStack.ts.
  mountRequestPipeline(app, { store, options, instanceSecret });
  const readUnlockState = createUnlockStateReader(instanceSecret);

  // Screenshot OCR full-text search index (#176): background, queued, best-effort — never on the
  // /captures hot path. See composition/ocrIndexer.ts.
  const { indexCaptureText } = createOcrIndexer({ store, ocrRunner: options.ocrRunner });

  // Per-case AI on/off + last-analyzed sequence, write-through cached over the on-disk store.
  // See composition/aiControlCache.ts.
  const { getControl, setControl } = createAiControlCache(store);

  // ── The services createApp composes ────────────────────────────────────────────────────────────
  // Each is a factory in src/composition/ taking its dependencies BY NAME (#416). They are built in
  // dependency order, and all of them before the RouteContext literal below — the ordering is load-
  // bearing now that these are `const`s rather than the hoisted `function` declarations they used to
  // be. Where a genuine cycle exists (a service the routes rebind at runtime, or one that reaches
  // back into a later one) the dependency is passed as a thunk, exactly as RouteContext does.

  // The active DFIR-IRIS client. Mutable: POST /iris/reconnect (routes/reportsExport.ts) can rebuild
  // it at runtime — via ctx.setIrisClient() — without a server restart (config saved via Settings, or
  // IRIS coming back online). Starts from options.
  let irisClient = options.irisClient;
  // The active NSRL RDS SQLite connection (#63). Mutable: the Settings → NSRL connect/disconnect
  // routes can swap it at runtime (unless env-managed). Starts from the startup-resolved DB.
  let nsrlDb = options.nsrlDb;

  const appliers = createCaseAppliers({ store, options, runStateExclusive, nsrlDb: () => nsrlDb });
  const enrichment = createEnrichmentEngine({ store, options, runStateExclusive });
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider,
    getControl,
    setControl,
    recordAiError,
    autoEnrichIfEnabled: enrichment.autoEnrichIfEnabled,
    dispatchNotify,
  });
  const imports = createImportIngest({
    store,
    options,
    runStateExclusive,
    importLock,
    recordImporterRun,
    redactErr,
    autoTagImported,
    getControl,
    applyWhitelistToCase: appliers.applyWhitelistToCase,
    applyNsrlToCase: appliers.applyNsrlToCase,
    applyDeobfuscationToCase: appliers.applyDeobfuscationToCase,
    resynthesizeInBackground: analysis.resynthesizeInBackground,
  });
  const tools = createExternalTools({
    store,
    options,
    resolveImportKind: imports.resolveImportKind,
    ingestStreamed: imports.ingestStreamed,
    pushImportCheckpoint: appliers.pushImportCheckpoint,
  });
  const drops = createDropFolder({
    store,
    options,
    hasAiProvider,
    getControl,
    recordImportFailure,
    dispatchNotify,
    resolveImportKind: imports.resolveImportKind,
    ingestStreamed: imports.ingestStreamed,
    liveToolConfigs: tools.liveToolConfigs,
    resolveToolForExt: tools.resolveToolForExt,
    rawExtClaimed: tools.rawExtClaimed,
    runDropToolAndIngest: tools.runDropToolAndIngest,
    indexCaptureText,
    captureBuffers: analysis.captureBuffers,
    flush: analysis.flush,
  });
  const monitors = createVeloMonitors({ store, options, ingestStreamed: imports.ingestStreamed });
  const hunts = createVeloHunts({
    store,
    options,
    importLock,
    persistEvidence: imports.persistEvidence,
    dispatchImport: imports.dispatchImport,
    resolveImportKind: imports.resolveImportKind,
    autoTagImported,
    demoteForensicForCase: imports.demoteForensicForCase,
    getControl,
    pushImportCheckpoint: appliers.pushImportCheckpoint,
    resynthesizeInBackground: analysis.resynthesizeInBackground,
  });
  // The external hunt/flow import paths (POST .../import-external) — hunts the Companion did not
  // launch, so no job record, outcome ledger or checkpoint. See composition/veloExternalIngest.ts.
  const externalIngest = createVeloExternalIngest({
    options,
    importLock,
    persistEvidence: imports.persistEvidence,
    dispatchImport: imports.dispatchImport,
    resolveImportKind: imports.resolveImportKind,
    autoTagImported,
    demoteForensicForCase: imports.demoteForensicForCase,
    getControl,
    applyWhitelistToCase: appliers.applyWhitelistToCase,
    applyNsrlToCase: appliers.applyNsrlToCase,
    resynthesizeInBackground: analysis.resynthesizeInBackground,
  });
  const rebuildForPrefix = createSettingsReload({
    options,
    setEnrichmentProviders: enrichment.setProviders,
    setIrisClient: (client) => {
      irisClient = client;
    },
  });

  const ctx: RouteContext = {
    store,
    options,
    serverLogger: getServerLogger(),
    recordImportFailure,
    recordAiError,
    readUnlockState,
    appStartedAt,
    recentImportFailures,
    recentAiErrors,
    importerRunStats,
    hasAiProvider,
    // Case-lifecycle graduations (routes/caseLifecycle.ts + routes/casePassword.ts): the unlock-cookie
    // secret, the per-case state mutex, the drop-inbox creator, the importer registry-reload + precedence
    // accessor/setter, and the runtime Timesketch-client rebuild — all shared with code that STAYS in
    // createApp (see context.ts for why each was graduated rather than moved). buildTimesketchClient is a
    // module-level function (kept in server.ts so no route imports a value from ../server.js).
    instanceSecret,
    runStateExclusive,
    importLock,
    ensureDropFolders: drops.ensureDropFolders,
    reloadImporters: imports.reloadImporters,
    importerPrecedence: imports.importerPrecedence,
    setImporterPrecedence: imports.setImporterPrecedence,
    rebuildTimesketchClient: () => (options.rebuildTimesketchClient ?? buildTimesketchClient)(),
    rebuildForPrefix,
    getControl,
    setControl,
    backfill: analysis.backfill,
    flush: analysis.flush,
    indexCaptureText,
    ingestStreamed: imports.ingestStreamed,
    runToolAndIngest: tools.runToolAndIngest,
    reloadCustomTools: tools.reloadCustomTools,
    startSocratesAnalysis: tools.startSocratesAnalysis,
    socratesJobStore: tools.socratesJobStore,
    runDropToolAndIngest: tools.runDropToolAndIngest,
    resolveImportKind: () => imports.resolveImportKind,
    captureBuffers: () => analysis.captureBuffers,
    synthInFlight: () => analysis.synthInFlight,
    importerRegistry: imports.importerRegistry,
    irisClient: () => irisClient,
    setIrisClient: (client) => {
      irisClient = client;
    },
    rebuildIrisClient: () => (options.rebuildIrisClient ?? buildIrisClient)(),
    dispatchNotify,
    dropWatchEnabled: () => drops.watchEnabled,
    enrichmentProviders: enrichment.providers,
    enrichHealth: () => enrichment.health,
    liveToolConfigs: () => tools.liveToolConfigs,
    customTools: tools.customTools,
    dispatchImport: imports.dispatchImport,
    demoteForensicForCase: imports.demoteForensicForCase,
    resynthesizeInBackground: analysis.resynthesizeInBackground,
    pushImportCheckpoint: appliers.pushImportCheckpoint,
    applyWhitelistToCase: appliers.applyWhitelistToCase,
    applyNsrlToCase: appliers.applyNsrlToCase,
    applyDeobfuscationToCase: appliers.applyDeobfuscationToCase,
    moveDropFile: drops.moveDropFile,
    // Threat-intel enrichment engine (routes/threatIntel.ts). The engine + its reachability poller
    // live in composition/enrichment.ts; the moved routes reach them through these members. nsrlDb is
    // a live accessor because Settings → NSRL can swap the handle at runtime.
    enrichInBackground: enrichment.enrichInBackground,
    autoEnrichIfEnabled: enrichment.autoEnrichIfEnabled,
    enabledProvidersFor: enrichment.enabledProvidersFor,
    enrichPending: () => enrichment.pending,
    nsrlDb: () => nsrlDb,
    setNsrlDb: (db) => {
      nsrlDb = db;
    },
    // Velociraptor machinery (routes/velociraptor.ts), from composition/veloMonitors.ts + veloHunts.ts.
    refreshVeloClients: monitors.refreshVeloClients,
    resumeVeloMonitors: monitors.resumeVeloMonitors,
    resumeVeloHuntStatusPolls: hunts.resumeVeloHuntStatusPolls,
    scheduleVeloMonitor: monitors.scheduleVeloMonitor,
    pollVeloMonitor: monitors.pollVeloMonitor,
    stopVeloMonitorTimer: monitors.stopVeloMonitorTimer,
    scheduleVeloHuntStatusPoll: hunts.scheduleVeloHuntStatusPoll,
    pollVeloHuntStatus: hunts.pollVeloHuntStatus,
    startVeloHuntCollect: hunts.startVeloHuntCollect,
    ingestVeloArtifactMap: externalIngest.ingestVeloArtifactMap,
    ingestVeloUploads: externalIngest.ingestVeloUploads,
    createVeloMonitor: monitors.createVeloMonitor,
    recordHuntDeploy: hunts.recordHuntDeploy,
    // Playbook derivation helpers (routes/playbookHunts.ts), shared with the staying
    // POST /cases/:id/push/iris route (syncPlaybook).
    syncPlaybook: appliers.syncPlaybook,
    loadPlaybookControl: appliers.loadPlaybookControl,
    dropSeen: () => drops.seen,
    dropScanning: () => drops.scanning,
    dropPendingLogged: () => drops.pendingLogged,
    veloHuntTimers: () => hunts.veloHuntTimers,
  };
  // Every registerXRoutes call, in order, plus the AI rate-limit gate and the custody hook that are
  // interleaved with them. See composition/routeRegistry.ts — the order there is load-bearing.
  const transports = registerAllRoutes(app, ctx);
  // app.locals is how the host reaches the outbound transports to stop them on shutdown.
  if (transports.telegramPoller) app.locals.telegramPoller = transports.telegramPoller;
  if (transports.slackSocketMode) app.locals.slackSocketMode = transports.slackSocketMode;

  // Re-arm any persisted live Velociraptor monitors so streaming survives a restart (#84). Fire-and-
  // forget + self-gating (no store/client or no persisted monitors → no-op), so it's a safe no-op for
  // tests and embeddings that don't use monitoring.
  void monitors.resumeVeloMonitors();
  void hunts.resumeVeloHuntStatusPolls();

  // Arm the evidence drop-folder watcher (auto-import inbox). Gated on the status store being wired
  // (startServer), so createApp-only unit tests never start a filesystem poller.
  if (drops.watchEnabled && options.dropStatusStore) drops.startDropWatcher();

  // The static-asset whitelist and the terminal error handler, which must be last of all.
  mountTerminalHandlers(app);

  return app;
}

import { loadDatabaseSync } from "./analysis/sqliteRuntime.js";
import { attachLiveSocket } from "./live/wsGate.js";

// AI model factories + the runtime pipeline wiring moved to composition/aiProviders.ts, and the
// threat-intel / customer-exposure provider factories to composition/enrichmentProviders.ts (#416).
// All of it is constructor-calls-over-env with no lifecycle, which is why it moved first. Re-exported
// here because scripts/{reanalyze,synthesize,deep-pass,verify-ai}.ts, the provider wiring tests and
// the settings-reload path import them from `src/server.js`.
export {
  buildProviderFrom,
  buildProvider,
  buildSynthesisProvider,
  buildSecondOpinionProvider,
  buildVelociraptorProvider,
  buildRuntimePipeline,
  DEFAULT_VELO_PROVIDER,
  DEFAULT_VELO_MODEL,
} from "./composition/aiProviders.js";
export type { ProviderParams, RuntimePipelineParams } from "./composition/aiProviders.js";
export {
  buildEnrichmentProviders,
  buildEnrichProviderDelayMap,
  buildCustomerExposureProviders,
} from "./composition/enrichmentProviders.js";
// `export ... from` re-exports without binding the names locally, and both startServer (below) and
// createApp's rebuildForPrefix still call them — so import them too.

export function startServer(casesRoot: string, port = 4773, host = "127.0.0.1", logDir?: string): void {
  // A stray promise rejection must not take a live investigation down with it. Armed here, at the
  // real-server boundary, so createApp() unit tests keep Node's fatal default (see the module).
  installUnhandledRejectionNet();
  // A synchronous exception still ends the process (see the module for why that's correct), but now
  // it logs first — so "the server crashed with no trace anywhere" stops being possible.
  installUncaughtExceptionNet();
  loadDatabaseSync();
  // Every store, client and shared runtime object this run needs. See composition/runtimeStores.ts
  // — including why each global store gets its own subdirectory beside cases/ rather than a loose
  // file next to it (Windows forbids creating files directly in a drive root).
  const rt = createRuntimeStores({ casesRoot, host, port, logDir });
  const {
    demoMode,
    store,
    teamAuth,
    writerGuard,
    logger,
    stateLock,
    operationalMetrics,
    stateStore,
    incidentTypeStore,
    kevStore,
    updateCheckStore,
    updateRepo,
    notifier,
    dashboardBaseUrl,
    velociraptorClient,
    velociraptorClientStore,
    hub,
    analysisRunStore,
    clockSkewStore,
    custodyStore,
    secondOpinionStore,
  } = rt;

  // Automatic state backup (#180) and periodic evidence re-verification (#231): two .unref()'d
  // maintenance timers, armed here because both objects are also handed to createApp below.
  const { backupManager, integrityMonitor } = startMaintenanceTasks({
    store,
    custodyStore,
    notifier,
    dashboardBaseUrl,
  });

  // Model providers, the optional Presidio gate, the OCR runner and the pipeline that binds them to
  // the stores. See composition/aiRuntime.ts.
  const { provider, secondOpinionProvider, ocrRunner, wiredPipeline } = buildAiRuntime({
    store,
    stateStore,
    stateLock,
    logger,
    kevStore,
    clockSkewStore,
    incidentTypeStore,
    analysisRunStore,
    operationalMetrics,
    secondOpinionStore,
    velociraptorClientStore,
    notifier,
    dashboardBaseUrl,
    onState: (s) => hub.broadcast(s),
  });

  // Pre-flight (#179): createApp calls onPreflightReady with runPreflightChecks; we store it
  // here and fire it after app.listen() so probes don't run before the server is ready.
  let scheduledPreflight: (() => Promise<PreflightReport>) | null = null;

  // The ~120-member AppOptions literal binding every store to its live-broadcast callback.
  // See composition/appWiring.ts.
  const app = createApp(
    store,
    buildAppOptions(rt, {
      teamAuth,
      pipeline: wiredPipeline,
      provider,
      secondOpinionProvider,
      ocrRunner,
      backupManager,
      integrityMonitor,
      onPreflightReady: (run) => {
        scheduledPreflight = run;
      },
    }),
  );

  // Serve the logo + favicons from public/ (the dashboard <head> links these). Whitelisted
  // filenames only; browsers that auto-request /favicon.ico get the crisp 32px PNG.
  const iconFiles: Record<string, string> = {
    "/dfir-companion-logo.jpg": "image/jpeg",
    "/favicon-16.png": "image/png",
    "/favicon-32.png": "image/png",
    "/apple-touch-icon.png": "image/png",
    "/favicon.ico": "image/png", // alias → favicon-32.png
  };
  for (const [route, type] of Object.entries(iconFiles)) {
    app.get(route, async (_req, res) => {
      const file = route === "/favicon.ico" ? "/favicon-32.png" : route;
      try {
        const buf = await readPublicAsset(file);
        res.type(type).set("Cache-Control", "public, max-age=86400").send(buf);
      } catch {
        res.status(404).end();
      }
    });
  }

  // Bind host. Defaults to 127.0.0.1 (localhost-only — the OPSEC invariant for native runs).
  // Inside a container set DFIR_HOST=0.0.0.0 so the published port is reachable; the compose
  // file maps it to 127.0.0.1 on the HOST, so the localhost-only posture is preserved end-to-end.
  const server = app.listen(port, host, () => {
    const shownHost = host === "0.0.0.0" ? "127.0.0.1" : host;
    logLine(`DFIR companion on http://${shownHost}:${port} (dashboard at /dashboard)`);
    // Pre-flight (#179): fire now that the server is listening so probes can reach the AI provider
    // and local enrichment servers. Best-effort — a failure is logged, never fatal.
    if (scheduledPreflight) {
      void scheduledPreflight()
        .then((r) => {
          if (r.disabled) {
            logLine("[preflight] checks disabled");
            return;
          }
          const status = r.anyCriticalFailed ? "CRITICAL" : r.anyFailed ? "WARN" : "OK";
          logLine(
            `[preflight] ${status} (${r.durationMs}ms) — ${r.items.map((i) => `${i.name}:${i.ok ? "ok" : "FAIL"}`).join(", ")}`,
          );
          if (r.anyCriticalFailed) {
            const failed = r.items
              .filter((i) => !i.ok && i.critical)
              .map((i) => `  ✗ ${i.name}: ${i.detail}`)
              .join("\n");
            warnLine(
              `[preflight] CRITICAL — open the dashboard → Settings → Diagnostics for details:\n${failed}`,
            );
          }
        })
        .catch((e) => warnLine(`[preflight] error: ${(e as Error).message}`));
    }
  });
  server.once("close", () => {
    teamAuth?.store.close();
    writerGuard?.release();
  });

  // The three best-effort startup tasks that must not run until the server is actually up: demo
  // seeding, the Velociraptor inventory snapshot, and the update check. See
  // composition/maintenanceTasks.ts.
  startPostListenTasks({
    store,
    demoMode,
    velociraptorClient,
    velociraptorClientStore,
    updateCheckStore,
    updateRepo,
  });

  // Friendly message instead of an unhandled-error stack trace when the port is taken.
  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(
        `\n[DFIR] Port ${port} is already in use — a DFIR companion is probably already running.\n` +
          `       Use the existing one (http://127.0.0.1:${port}/dashboard), or stop it first:\n` +
          `       PowerShell:   Get-NetTCPConnection -LocalPort ${port} -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }\n` +
          `       Linux/macOS:  kill $(lsof -ti tcp:${port})    (or, Linux: fuser -k ${port}/tcp)\n`,
      );
      process.exit(1);
    }
    throw err;
  });

  attachLiveSocket(server, hub, {
    store,
    teamAuth,
    operationalMetrics,
    secret: loadOrCreateInstanceSecret(store.casesRoot),
    allowedOrigins: parseAllowedOrigins(process.env.DFIR_ALLOWED_ORIGINS),
    allowedHosts: parseAllowedHosts(process.env.DFIR_ALLOWED_HOSTS),
    allowedHostSuffixes: parseAllowedHostSuffixes(process.env.DFIR_ALLOWED_HOST_SUFFIXES),
  });
}

// Entry point when run directly. Load companion/.env so users can keep config
// (AI provider/model/key, cases root) in a file instead of typing env vars.
// Matches three entries: the tsx dev entry (`server.ts`), the compiled production entry
// (`dist/server.js`, Docker image), and the single-executable bundle (`process.execPath`
// ends in `.exe`/the SEA binary). All three boot the server.
const entryPath = process.argv[1] ?? "";
const seaRuntime = isSeaRuntime();
if (seaRuntime || entryPath.endsWith("server.ts") || entryPath.endsWith("server.js")) {
  // In SEA mode anchor the package dir to the EXE's folder so .env / cases / public live
  // next to the binary. In dev/Docker mode keep the original behaviour (resolve against
  // this module's location → companion/).
  const companionDir = seaRuntime
    ? dirname(process.execPath) + "/"
    : fileURLToPath(new URL("../", import.meta.url)); // .../companion/
  // Resolve the .env via the shared resolver so the dashboard's POST /settings/env writes back to
  // the SAME file we load here (DFIR_ENV_FILE → per-user %LOCALAPPDATA% seed → EXE-adjacent → cwd).
  const envFile = resolveEnvFilePath();
  loadDotenv({ path: envFile, quiet: true });
  logLine(`[DFIR] env file: ${envFile}`);
  // Expand a leading "~" to the user's home directory. dotenv does NOT do this
  // expansion, so DFIR_CASES_ROOT=~/Documents/cases would otherwise create a
  // literal "~/Documents" folder beside the companion package instead of using
  // $HOME/Documents. See src/storage/expandHome.ts.
  const raw = expandHome(process.env.DFIR_CASES_ROOT ?? "cases");
  // Anchor a relative cases root to the companion package directory, so the SAME
  // physical folder is used no matter which directory the server is launched from.
  // (Otherwise "./cases" resolves against cwd and you can end up with two folders.)
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  logLine(`[DFIR] cases root: ${casesRoot}`);

  // Port can be overridden via DFIR_PORT (1-65535). Invalid → fall back to default
  // with a warning so a typo doesn't silently bind the wrong port.
  const DEFAULT_PORT = 4773;
  const rawPort = process.env.DFIR_PORT;
  let port = DEFAULT_PORT;
  if (rawPort !== undefined && rawPort !== "") {
    const parsed = Number(rawPort);
    if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535) {
      port = parsed;
    } else {
      warnLine(`[DFIR] ignoring invalid DFIR_PORT="${rawPort}" — using default ${DEFAULT_PORT}.`);
    }
  }

  // Bind host. Default 127.0.0.1 keeps the server localhost-only for native runs. The Docker
  // image sets DFIR_HOST=0.0.0.0 so the container's published port works; compose maps that
  // port to 127.0.0.1 on the host, so it never listens on the host's public interfaces.
  const host = process.env.DFIR_HOST && process.env.DFIR_HOST !== "" ? process.env.DFIR_HOST : "127.0.0.1";

  // Optional override for the GLOBAL session-log directory (per-case logs always live in the
  // case dir). Relative paths anchor to companion/ like DFIR_CASES_ROOT; unset → logs/ beside
  // the cases root.
  // Expand before the isAbsolute test, not after: "~/logs" is not absolute, so testing the raw
  // value sends it down the relative branch and only resolve()'s absolute-second-argument rule
  // saves it. Same reason as the cases root above — dotenv does not expand "~".
  const rawLogDir = process.env.DFIR_LOG_DIR?.trim() ? expandHome(process.env.DFIR_LOG_DIR) : undefined;
  const logDir = rawLogDir
    ? isAbsolute(rawLogDir)
      ? rawLogDir
      : resolve(companionDir, rawLogDir)
    : undefined;

  startServer(casesRoot, port, host, logDir);
}
