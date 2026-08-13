/**
 * Every store, client and shared runtime object a real server run needs, constructed once from the
 * cases root. Lifted out of startServer by #416.
 *
 * This is the boring half of startup, and it is boring on purpose: ~60 `new XStore(store)` lines
 * with no branching. What is NOT boring, and is why they are gathered here rather than left inline,
 * is WHERE each global one is rooted. A store that belongs to no single case lives in its own
 * subdirectory beside `cases/` — never as a loose file next to it — because when DFIR_CASES_ROOT is
 * a drive-root child (`C:\cases`) the sibling is `C:\`, and Windows forbids creating files
 * directly in a drive root. A subdirectory is always creatable and always writable. Each such store
 * carries that reasoning at its line.
 *
 * `createApp` never calls this. It takes everything as `AppOptions`, which is what lets ~6,800 tests
 * build an app with three stores wired and the rest absent.
 */
import { join, dirname, isAbsolute, resolve } from "node:path";
import { CaseStore } from "../storage/caseStore.js";
import { StateStore as StateStoreImpl } from "../analysis/stateStore.js";
import { ReportWriter as ReportWriterImpl } from "../reports/reportWriter.js";
import { StateLock } from "../analysis/stateLock.js";
import { OperationalMetricsStore } from "../analysis/operationalMetrics.js";
import { startOperationalCapacityMonitor } from "../analysis/operationalCapacity.js";
import { LoggerImpl, normalizeLogLevel } from "../logging/logger.js";
import { logLine, setServerLogger } from "../logging/serverLogger.js";
import { createTeamAuthRuntime } from "../auth/authFactory.js";
import { TemplateStore } from "../analysis/templateStore.js";
import { IncidentTypeStore } from "../analysis/incidentTypeStore.js";
import { CollectionPlanStore } from "../analysis/collectionPlanStore.js";
import { HostScopeStore } from "../analysis/hostScopeStore.js";
import { ArtifactBundleStore } from "../analysis/artifactBundleStore.js";
import { ReportTemplateStore } from "../reports/reportTemplateStore.js";
import { ReportTemplateControlStore } from "../reports/reportTemplateControl.js";
import { DashboardViewStore } from "../analysis/dashboardViewStore.js";
import { TaggerStore } from "../analysis/taggerStore.js";
import { IocWhitelistStore } from "../analysis/iocWhitelistStore.js";
import { ImporterStore } from "../analysis/importerStore.js";
import { NsrlStore, ingestNsrlFiles, splitNsrlPaths } from "../analysis/nsrlStore.js";
import { NsrlDb, loadNsrlDbPath } from "../analysis/nsrlDb.js";
import { CustomToolStore } from "../integrations/tools/customToolStore.js";
import { McpServerStore } from "../integrations/mcp/mcpServerStore.js";
import { KevStore } from "../analysis/kevStore.js";
import { UpdateCheckStore } from "../analysis/updateCheckStore.js";
import { DEFAULT_UPDATE_REPO } from "../analysis/updateCheck.js";
import { getAppVersion } from "../version.js";
import { NotificationConfigStore } from "../analysis/notificationStore.js";
import { SlashCommandChannelStore } from "../analysis/slashCommandStore.js";
import { createNotifier } from "../integrations/notify/notifyDispatch.js";
import { nodeSmtpConnect } from "../integrations/notify/smtpClient.js";
import { tlsFetchFor } from "./tlsFetch.js";
import { VeloHuntStore } from "../analysis/veloHuntStore.js";
import { HuntOutcomeStore } from "../analysis/huntOutcomeStore.js";
import { HuntRunSnapshotStore } from "../analysis/huntRunSnapshotStore.js";
import { VeloMonitorStore } from "../analysis/veloMonitorStore.js";
import { PushTokenStore } from "../analysis/pushTokenStore.js";
import { buildVelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";
import { VelociraptorClientStore } from "../analysis/velociraptorClientStore.js";
import { LiveHub } from "../live/hub.js";
import { JobManager } from "../analysis/jobManager.js";
import { JobLedgerStore } from "../analysis/jobLedgerStore.js";
import { ReportMetaStore } from "../reports/reportMeta.js";
import { ReportVersionStore } from "../reports/reportVersionStore.js";
import { AnalysisRunStore } from "../analysis/analysisRunStore.js";
import { ActivityLogStore } from "../analysis/activityLog.js";
import { CommentsStore } from "../analysis/comments.js";
import { TagsStore } from "../analysis/tags.js";
import { PinnedFindingsStore } from "../analysis/pinnedFindings.js";
import { FindingWorkflowStore } from "../analysis/findingWorkflow.js";
import { NotebookStore } from "../analysis/notebookStore.js";
import { HypothesisStore } from "../analysis/hypothesisStore.js";
import { LearnedPatternStore } from "../analysis/learnedPatternStore.js";
import { SourceTrustStore } from "../analysis/sourceTrustStore.js";
import { DwellWindowStore } from "../analysis/dwellWindowStore.js";
import { ClockSkewStore } from "../analysis/clockSkewStore.js";
import { SuperTimelineStore } from "../analysis/superTimelineStore.js";
import { StarredReportStore } from "../analysis/starredReportStore.js";
import { ForensicGateControlStore } from "../analysis/forensicGateControl.js";
import { CustodyStore } from "../analysis/custody.js";
import { ConfidenceControlStore } from "../analysis/confidenceControl.js";
import { ComplianceControlStore } from "../analysis/complianceControl.js";
import { PlaybookStore } from "../analysis/playbookStore.js";
import { PlaybookHuntStore } from "../analysis/playbookHuntStore.js";
import { PlaybookControlStore } from "../analysis/playbookControl.js";
import { AssetOverridesStore } from "../analysis/assetOverrides.js";
import { IocAliasStore } from "../analysis/iocAlias.js";
import { SynthMetaStore } from "../analysis/synthMeta.js";
import { AiCostStore } from "../analysis/aiCost.js";
import { CorrelationProfileStore } from "../analysis/correlationProfile.js";
import { SecondOpinionStore } from "../analysis/secondOpinionStore.js";
import { ImportMetaStore } from "../analysis/importMeta.js";
import { DropStatusStore } from "../analysis/dropStatus.js";
import { ImportUndoStore, undoMaxBytesFromEnv } from "../analysis/importUndo.js";
import { NotionExportStore } from "../integrations/notion/notionExportStore.js";
import { ClickUpExportStore } from "../integrations/clickup/clickupExportStore.js";
import { IrisExportStore } from "../integrations/iris/irisExportStore.js";
import { LateralPathDismissStore } from "../analysis/lateralPathDismiss.js";
import { ScopeStore } from "../analysis/scope.js";
import { loadHostScopeLedger } from "../analysis/hostScopeLoad.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import { CustomerExposureStore } from "../analysis/customerExposure.js";
import { loadOrCreateInstanceSecret } from "../analysis/instanceSecret.js";

export interface RuntimeStoresParams {
  casesRoot: string;
  /** Host and port only shape the dashboard deep-link and the writer-guard lock record. */
  host: string;
  port: number;
  /** Override for the GLOBAL session-log directory; per-case logs always live in the case dir. */
  logDir?: string;
}

export function createRuntimeStores({ casesRoot, host, port, logDir }: RuntimeStoresParams) {
  const demoMode = process.env.DFIR_DEMO_MODE === "true" || process.env.DFIR_DEMO_MODE === "1";
  const store = new CaseStore(casesRoot);
  const { teamAuth, writerGuard } = createTeamAuthRuntime(casesRoot, host, port);
  if (writerGuard) process.once("exit", () => writerGuard.release());
  // File-backed global and per-case session logs retain the investigation audit trail.
  // Timestamp punctuation is stripped for Windows-compatible filenames.
  const sessionStamp = new Date().toISOString().replace(/[:.]/g, "-");
  const globalLogDir = logDir ?? join(dirname(casesRoot), "logs");
  const logger = new LoggerImpl({
    level: normalizeLogLevel(process.env.DFIR_LOG_LEVEL),
    sessionLogPath: join(globalLogDir, `session-${sessionStamp}.log`),
    caseLogPath: (caseId) => join(store.caseDir(caseId), "logs", `session-${sessionStamp}.log`),
  });
  setServerLogger(logger);
  logLine(`[DFIR] session log: ${join(globalLogDir, `session-${sessionStamp}.log`)}`);
  const stateLock = new StateLock();
  const operationalMetrics = new OperationalMetricsStore(
    join(dirname(casesRoot), "diagnostics", "operational-metrics.json"),
    {
      enabled: !/^(?:0|false|off)$/i.test(process.env.DFIR_LOCAL_TELEMETRY ?? ""),
      onError: (error) => logLine(`[metrics] ${error.message}`),
    },
  );
  const stateStore = new StateStoreImpl(store, undefined, { operationalMetrics });
  startOperationalCapacityMonitor(store, stateStore, operationalMetrics, (error) =>
    logLine(`[capacity] ${error.message}`),
  );
  const templateStore = new TemplateStore(join(dirname(casesRoot), "templates"));
  // Incident-type auto-playbooks (#236): the built-in library ships in companion/data/incident-types/;
  // this dir holds analyst-authored custom types (same drive-root-safe rationale as templates/bundles).
  const incidentTypeStore = new IncidentTypeStore(store, join(dirname(casesRoot), "incident-types"));
  // Collection plan (#347): per-case only — the plan is derived from the timeline, so nothing global.
  const collectionPlanStore = new CollectionPlanStore(store);
  // Host scope ledger: per-case decisions only — the ledger is derived on read, so nothing global.
  const hostScopeStore = new HostScopeStore(store);
  const artifactBundleStore = new ArtifactBundleStore(join(dirname(casesRoot), "bundles"));
  // Report templates are GLOBAL like case templates/bundles — a dedicated subdir beside cases/.
  const reportTemplateStore = new ReportTemplateStore(join(dirname(casesRoot), "report-templates"));
  // Dashboard view presets (#142) — GLOBAL like report templates, its own subdir beside cases/.
  const dashboardViewStore = new DashboardViewStore(join(dirname(casesRoot), "dashboard-views"));
  // Content-based event tagger: dashboard-edited rules persist here; the bundled data/tags.yaml is
  // the fallback default (resolved inside TaggerStore), and TAGGER_RULES_FILE overrides both.
  const taggerStore = new TaggerStore(join(dirname(casesRoot), "tagger", "tags.yaml"));
  // A dedicated subdir (mirrors bundles/templates) rather than a loose file beside cases/, because
  // when DFIR_CASES_ROOT is a drive root child (e.g. C:\cases) the sibling is C:\ — and Windows
  // forbids creating files directly in a drive root. A subdir is always creatable + writable.
  const iocWhitelistStore = new IocWhitelistStore(
    join(dirname(casesRoot), "whitelist", "ioc-whitelist.json"),
  );
  // User-authored declarative importers (#: external plugin layer) — its own subdir beside cases/
  // (same drive-root rationale as the whitelist). Each *.json is one importer spec. The folder is
  // overridable with DFIR_IMPORTERS_DIR (absolute used as-is; relative anchors to the cases-root
  // parent, where the default importers/ lives); unset → importers/ beside the cases root.
  const rawImportersDir = process.env.DFIR_IMPORTERS_DIR;
  const importersDir =
    rawImportersDir && rawImportersDir.trim() !== ""
      ? isAbsolute(rawImportersDir)
        ? rawImportersDir
        : resolve(dirname(casesRoot), rawImportersDir)
      : join(dirname(casesRoot), "importers");
  const importerStore = new ImporterStore(importersDir);
  // NSRL known-good hash set (#63) — its own subdir next to cases/ (same drive-root rationale as the
  // whitelist). Optionally pre-loaded at startup from file(s) named in DFIR_NSRL_FILE (; separated):
  // an NSRLFile.txt RDS export, a hashdeep CSV, or a plain hash-per-line list. Ingest is idempotent.
  const nsrlStore = new NsrlStore(join(dirname(casesRoot), "nsrl", "known-hashes.txt"));
  // Custom external tools (#211) — a global JSON store in its own subdir beside cases/ (drive-root-safe).
  const customToolStore = new CustomToolStore(join(dirname(casesRoot), "tools", "custom-tools.json"));
  // MCP policy (#296) — global and shared across cases, beside the custom-tool list for the same
  // reason: a variable-length list belongs in a JSON store, not fixed .env keys.
  const mcpServerStore = new McpServerStore(join(dirname(casesRoot), "tools", "mcp-servers.json"));
  const nsrlFiles = splitNsrlPaths(process.env.DFIR_NSRL_FILE);
  if (nsrlFiles.length > 0) {
    // Fire-and-forget (startServer is sync): ingest in the background via the same helper the
    // Settings → NSRL "Load from file" route uses. The set is opt-in and the auto-apply sweep loads
    // it fresh, so a late finish just means later imports pick it up.
    void ingestNsrlFiles(nsrlStore, nsrlFiles).then((results) => {
      for (const r of results) {
        logLine(
          r.error
            ? `[nsrl] could not load ${r.file}: ${r.error}`
            : `[nsrl] loaded ${r.file} — +${r.added} new (${r.total} total known-good hashes)`,
        );
      }
    });
  }
  // NSRL RDS SQLite backend (#63): the full ~160 GB set queried on demand. Path from DFIR_NSRL_DB
  // (env-managed → UI connect is read-only) or, when that's unset, the UI-set path persisted in
  // nsrl/db-path.txt. Opened read-only; a bad/missing DB logs and is skipped (the flat store still works).
  const nsrlDbConfigFile = join(dirname(casesRoot), "nsrl", "db-path.txt");
  const nsrlDbEnv = (process.env.DFIR_NSRL_DB ?? "").trim();
  const nsrlDbEnvManaged = nsrlDbEnv.length > 0;
  const resolvedNsrlDbPath = nsrlDbEnv || loadNsrlDbPath(nsrlDbConfigFile);
  let nsrlDb: NsrlDb | undefined;
  if (resolvedNsrlDbPath) {
    try {
      nsrlDb = NsrlDb.open(resolvedNsrlDbPath);
      logLine(
        `[nsrl] connected RDS DB ${resolvedNsrlDbPath} — table ${nsrlDb.table}, columns ${nsrlDb.columns.join("/")}`,
      );
    } catch (err) {
      logLine(`[nsrl] could not open RDS DB ${resolvedNsrlDbPath}: ${(err as Error).message}`);
    }
  }
  // CISA KEV catalog (issue #99) — global, shared across cases, own subdir beside cases/ (same
  // drive-root rationale as the whitelist/nsrl). No env pre-load: analysts fetch/import it via
  // Settings → KEV. The pipeline lazy-loads it so an import during a session is picked up.
  const kevStore = new KevStore(join(dirname(casesRoot), "kev", "catalog.json"));
  const updateCheckStore = new UpdateCheckStore(join(dirname(casesRoot), "updates", "update-check.json"));
  const appVersion = getAppVersion();
  const updateRepo = (() => {
    const envRepo = process.env.DFIR_UPDATE_REPO;
    return envRepo && /^[\w.-]+\/[\w.-]+$/.test(envRepo) ? envRepo : DEFAULT_UPDATE_REPO;
  })();
  // Notifications (issue #58): a global channel store (own subdir, Windows drive-root-safe) + a
  // notifier wired with a TLS-aware fetch (Slack/Teams webhooks, honoring DFIR_NOTIFY_CA/_INSECURE
  // for self-hosted Mattermost) and the built-in SMTP transport for email channels.
  const notificationStore = new NotificationConfigStore(
    join(dirname(casesRoot), "notifications", "config.json"),
  );
  // Per-channel case bindings for the war-room slash-command bot (#235) — a global file beside the
  // notification config (a channel-level concern, not per-case).
  const slashCommandChannelStore = new SlashCommandChannelStore(
    join(dirname(casesRoot), "notifications", "slash-command-bindings.json"),
  );
  const notifier = createNotifier({
    store: notificationStore,
    fetchFn: tlsFetchFor("NOTIFY") ?? fetch,
    smtpConnect: nodeSmtpConnect,
    log: (m) => logLine(m),
  });
  // Deep-link notifications back to the dashboard. Override the host/port guess with DFIR_PUBLIC_URL.
  const dashboardBaseUrl = (process.env.DFIR_PUBLIC_URL || `http://${host}:${port}`).replace(/\/+$/, "");
  const veloHuntStore = new VeloHuntStore(store);
  const huntOutcomeStore = new HuntOutcomeStore(store); // #157 hunting feedback loop ledger
  const huntRunSnapshotStore = new HuntRunSnapshotStore(store); // #80 run-to-run hunt diffing
  // Live Velociraptor CLIENT_EVENT monitors + generic push ingest (#84). The monitor store persists
  // each poller's cursor (resumed on restart); the push token store holds per-case secrets, and
  // DFIR_PUSH_TOKEN is the global one. Push is OFF until a token is configured (see pushAuth.ts).
  const veloMonitorStore = new VeloMonitorStore(store);
  const pushTokenStore = new PushTokenStore(store);
  const pushToken = process.env.DFIR_PUSH_TOKEN?.trim() || undefined;
  const veloMonitorPollSeconds = Number(process.env.DFIR_VELO_MONITOR_POLL_S) || 30;
  // Velociraptor API client (when DFIR_VELOCIRAPTOR_API_CONFIG is set) + the persisted client inventory
  // (host ↔ client_id map, #70) in its own subdir beside cases/ (Windows drive-root-safe, like bundles/nsrl).
  const velociraptorClient = buildVelociraptorClient();
  const velociraptorClientStore = new VelociraptorClientStore(
    join(dirname(casesRoot), "velociraptor", "clients.json"),
  );
  const hub = new LiveHub();
  const jobManager = new JobManager({
    onJob: (caseId) => {
      if (caseId) hub.broadcastTo(caseId, { type: "job_changed" });
    },
    onError: (error) => logLine(`[jobs] durable ledger error: ${error.message}`),
    ledger: new JobLedgerStore(store),
    max: Number(process.env.DFIR_JOBS_MAX) || undefined,
    globalConcurrency: Number(process.env.DFIR_JOBS_CONCURRENCY) || undefined,
    perCaseConcurrency: Number(process.env.DFIR_JOBS_PER_CASE) || undefined,
  });
  const reportMetaStore = new ReportMetaStore(store);
  const reportVersionStore = new ReportVersionStore(store); // #77 report versioning (diff & rollback)
  const analysisRunStore = new AnalysisRunStore(store, { appVersion });
  const reportTemplateControlStore = new ReportTemplateControlStore(store);
  const activityLogStore = new ActivityLogStore(store);
  const commentsStore = new CommentsStore(store);
  const tagsStore = new TagsStore(store);
  const pinnedFindingsStore = new PinnedFindingsStore(
    store,
    Number(process.env.DFIR_MAX_PINNED_FINDINGS) || undefined,
  );
  const findingWorkflowStore = new FindingWorkflowStore(store);
  const notebookStore = new NotebookStore(store);
  const hypothesisStore = new HypothesisStore(store);
  const learnedPatternStore = new LearnedPatternStore(store);
  const sourceTrustStore = new SourceTrustStore(store);
  const dwellWindowStore = new DwellWindowStore(store);
  const clockSkewStore = new ClockSkewStore(store); // #228 per-host clock offsets + alignment toggle
  const superTimelineStore = new SuperTimelineStore(
    store,
    Number(process.env.DFIR_SUPERTIMELINE_MAX) || undefined,
    operationalMetrics,
  );
  const starredReportStore = new StarredReportStore(store);
  const forensicGateControlStore = new ForensicGateControlStore(store);
  const custodyStore = new CustodyStore(store);
  const confidenceControlStore = new ConfidenceControlStore(store);
  const complianceControlStore = new ComplianceControlStore(store);
  const playbookStore = new PlaybookStore(store);
  const playbookHuntStore = new PlaybookHuntStore(store);
  const playbookControlStore = new PlaybookControlStore(store);
  const assetOverridesStore = new AssetOverridesStore(store);
  const iocAliasStore = new IocAliasStore(store); // #82: analyst IOC merges (survive re-synthesis)
  const synthMetaStore = new SynthMetaStore(store);
  const aiCostStore = new AiCostStore(store);
  const correlationProfileStore = new CorrelationProfileStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const dropStatusStore = new DropStatusStore(store); // evidence drop-folder last-sweep summary
  // #76: import undo/redo. Depth is the number of import levels kept (each = a full timeline+IOC copy).
  const importUndoStore = new ImportUndoStore(
    store,
    Number(process.env.DFIR_IMPORT_UNDO_DEPTH) || undefined,
    undoMaxBytesFromEnv(),
  );
  const notionExportStore = new NotionExportStore(store);
  const clickupExportStore = new ClickUpExportStore(store);
  const irisExportStore = new IrisExportStore(store);
  const lateralPathDismissStore = new LateralPathDismissStore(store);
  const reportWriter = new ReportWriterImpl(store, stateStore, {
    custodyStore,
    // Signs the custody manifest that travels inside a redacted package. Same secret createApp
    // loads; loadOrCreateInstanceSecret reads the persisted file, so both see the same value.
    instanceSecret: loadOrCreateInstanceSecret(store.casesRoot),
    scope: new ScopeStore(store),
    // The report renders the scope ledger; assembling it from the stores is composition's job, not
    // the writer's, so it is handed in as a callback.
    hostScope: (caseId: string) =>
      loadHostScopeLedger(
        {
          state: stateStore,
          superTimeline: superTimelineStore,
          decisions: hostScopeStore,
          scope: new ScopeStore(store),
          assetOverrides: assetOverridesStore,
          fleet: velociraptorClientStore,
        },
        caseId,
      ),
    falsePositives: new FalsePositiveStore(store),
    reportMeta: reportMetaStore,
    customerExposure: new CustomerExposureStore(store),
    notebook: notebookStore,
    assetOverrides: assetOverridesStore,
    playbook: playbookStore,
    reportTemplates: reportTemplateStore,
    reportTemplateControl: reportTemplateControlStore,
    kevStore,
    hypothesisStore,
    synthMeta: synthMetaStore,
    lateralPathDismissals: lateralPathDismissStore,
    reportVersions: reportVersionStore,
    analysisRuns: analysisRunStore,
    complianceControl: complianceControlStore,
    clockSkew: clockSkewStore,
  });

  return {
    demoMode,
    store,
    teamAuth,
    writerGuard,
    logger,
    stateLock,
    operationalMetrics,
    stateStore,
    templateStore,
    incidentTypeStore,
    collectionPlanStore,
    hostScopeStore,
    artifactBundleStore,
    reportTemplateStore,
    dashboardViewStore,
    taggerStore,
    iocWhitelistStore,
    importerStore,
    nsrlStore,
    customToolStore,
    mcpServerStore,
    nsrlDbConfigFile,
    nsrlDbEnvManaged,
    nsrlDb,
    kevStore,
    updateCheckStore,
    appVersion,
    updateRepo,
    notificationStore,
    slashCommandChannelStore,
    notifier,
    dashboardBaseUrl,
    veloHuntStore,
    huntOutcomeStore,
    huntRunSnapshotStore,
    veloMonitorStore,
    pushTokenStore,
    pushToken,
    veloMonitorPollSeconds,
    velociraptorClient,
    velociraptorClientStore,
    hub,
    jobManager,
    reportMetaStore,
    reportVersionStore,
    analysisRunStore,
    reportTemplateControlStore,
    activityLogStore,
    commentsStore,
    tagsStore,
    pinnedFindingsStore,
    findingWorkflowStore,
    notebookStore,
    hypothesisStore,
    learnedPatternStore,
    sourceTrustStore,
    dwellWindowStore,
    clockSkewStore,
    superTimelineStore,
    starredReportStore,
    forensicGateControlStore,
    custodyStore,
    confidenceControlStore,
    complianceControlStore,
    playbookStore,
    playbookHuntStore,
    playbookControlStore,
    assetOverridesStore,
    iocAliasStore,
    synthMetaStore,
    aiCostStore,
    correlationProfileStore,
    secondOpinionStore,
    importMetaStore,
    dropStatusStore,
    importUndoStore,
    notionExportStore,
    clickupExportStore,
    irisExportStore,
    lateralPathDismissStore,
    reportWriter,
  };
}

/** Everything a real server run constructs once. `buildAppOptions` consumes the whole object. */
export type RuntimeStores = ReturnType<typeof createRuntimeStores>;
