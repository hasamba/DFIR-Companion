/**
 * The `AppOptions` literal a real server run hands to `createApp` — ~120 members binding every store
 * and client to the live-broadcast callbacks that push their changes to open dashboards. Lifted out
 * of startServer by #416.
 *
 * WHAT THE `on*` CALLBACKS ARE. Each is "this thing changed, tell the browsers looking at this
 * case", and they are supplied HERE rather than inside createApp because the LiveHub is a
 * startServer-owned object: a test builds an app with no hub and simply omits them, and every
 * `options.onX?.(...)` call site becomes a no-op. That is the whole reason AppOptions is ~90
 * optional members instead of a required config — the optionality IS the test seam.
 *
 * BROADCAST SCOPE IS DELIBERATE per callback. Most are `broadcastTo(caseId, …)` — only the
 * dashboards viewing that case care. Two are `broadcastAll`: capture and import ingest, so a
 * dashboard viewing a DIFFERENT case can warn that evidence is arriving for another one (the
 * capture extension pointed at a case the analyst is not looking at).
 */
import type { AppOptions } from "./appOptions.js";
import type { RuntimeStores } from "./runtimeStores.js";
import type { TeamAuth } from "../auth/teamAuth.js";
import type { AnalysisPipeline } from "../analysis/pipeline.js";
import type { AIProvider } from "../providers/provider.js";
import type { OcrRunner } from "../analysis/ocrRedact.js";
import type { BackupManager } from "../storage/backupManager.js";
import type { EvidenceIntegrityMonitor } from "../analysis/custodyIntegrity.js";
import type { PreflightReport } from "../analysis/preflight.js";
import { TesseractOcrRunner } from "../analysis/ocrRedact.js";
import { JiraExportStore } from "../integrations/jira/jiraExportStore.js";
import { ServiceNowExportStore } from "../integrations/servicenow/servicenowExportStore.js";
import {
  buildEnrichmentProviders,
  buildEnrichProviderDelayMap,
  buildCustomerExposureProviders,
} from "./enrichmentProviders.js";
import {
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
} from "./integrationClients.js";
import { buildProvider } from "./aiProviders.js";
import { spawnToolRunner } from "../integrations/tools/toolRunner.js";
import { parseAllowedOrigins, parseAllowedHosts, parseAllowedHostSuffixes } from "../http/originGuard.js";
import { resolveHuntPlatforms } from "../analysis/huntPlatforms.js";
import { numEnv } from "./env.js";

export interface AppWiringDeps {
  teamAuth?: TeamAuth;
  pipeline: AnalysisPipeline;
  /** The VISION provider; its presence is what `aiConfigured` reports. */
  provider?: AIProvider;
  secondOpinionProvider?: AIProvider;
  /** The pipeline's OCR runner — undefined when the vision model is local. See aiRuntime.ts. */
  ocrRunner?: OcrRunner;
  backupManager: BackupManager;
  integrityMonitor: EvidenceIntegrityMonitor;
  /** Called once by createApp with the preflight runner; startServer fires it after listen(). */
  onPreflightReady: (run: () => Promise<PreflightReport>) => void;
}

export function buildAppOptions(rt: RuntimeStores, deps: AppWiringDeps): AppOptions {
  const {
    store,
    hub,
    demoMode,
    stateStore,
    stateLock,
    operationalMetrics,
    reportWriter,
    reportMetaStore,
    reportVersionStore,
    reportTemplateStore,
    reportTemplateControlStore,
    dashboardViewStore,
    taggerStore,
    activityLogStore,
    commentsStore,
    tagsStore,
    pinnedFindingsStore,
    findingWorkflowStore,
    notebookStore,
    hypothesisStore,
    learnedPatternStore,
    sourceTrustStore,
    clockSkewStore,
    dwellWindowStore,
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
    lateralPathDismissStore,
    iocAliasStore,
    synthMetaStore,
    analysisRunStore,
    aiCostStore,
    correlationProfileStore,
    secondOpinionStore,
    importMetaStore,
    dropStatusStore,
    customToolStore,
    mcpServerStore,
    importUndoStore,
    jobManager,
    velociraptorClient,
    velociraptorClientStore,
    artifactBundleStore,
    iocWhitelistStore,
    importerStore,
    nsrlStore,
    nsrlDb,
    nsrlDbConfigFile,
    nsrlDbEnvManaged,
    kevStore,
    veloHuntStore,
    huntOutcomeStore,
    huntRunSnapshotStore,
    veloMonitorStore,
    veloMonitorPollSeconds,
    pushToken,
    pushTokenStore,
    irisExportStore,
    templateStore,
    incidentTypeStore,
    collectionPlanStore,
    notionExportStore,
    clickupExportStore,
    notificationStore,
    slashCommandChannelStore,
    notifier,
    dashboardBaseUrl,
    updateCheckStore,
    appVersion,
    updateRepo,
  } = rt;
  const {
    teamAuth,
    pipeline,
    provider,
    secondOpinionProvider,
    ocrRunner,
    backupManager,
    integrityMonitor,
    onPreflightReady,
  } = deps;

  // Live synthesis on by default — set DFIR_AI_AUTO_SYNTHESIZE=off to disable.
  const autoSynthesize = (process.env.DFIR_AI_AUTO_SYNTHESIZE ?? "on").toLowerCase() !== "off";
  const autoSynthesizeDebounceMs = Number(process.env.DFIR_AI_AUTO_SYNTHESIZE_MS) || 8000;
  // Safety-net flush: drain any non-empty capture buffer on this interval so a lone `timer`/`click`
  // screenshot is still analyzed instead of waiting for a full window. Default 5 min in createApp;
  // set DFIR_FLUSH_INTERVAL_MS=0 to disable it entirely.
  const flushIntervalMs =
    process.env.DFIR_FLUSH_INTERVAL_MS === "0" ? 0 : Number(process.env.DFIR_FLUSH_INTERVAL_MS) || undefined;

  return {
    teamAuth,
    pipeline,
    aiConfigured: Boolean(provider),
    flushIntervalMs,
    stateStore,
    operationalMetrics,
    liveConnectionCount: () => hub.connectionCount(),
    stateLock,
    reportWriter,
    // The redacted-export route needs OCR even when the vision model is local (the pipeline's
    // ocrRunner is undefined in that case), so give createApp its own always-available runner.
    ocrRunner: ocrRunner ?? new TesseractOcrRunner(),
    reportMetaStore,
    reportVersionStore,
    reportTemplateStore,
    reportTemplateControlStore,
    dashboardViewStore,
    taggerStore,
    onReportTemplate: (caseId) => hub.broadcastTo(caseId, { type: "report_template_changed" }),
    activityLogStore,
    onActivity: (caseId) => hub.broadcastTo(caseId, { type: "activity_changed" }),
    commentsStore,
    onComments: (caseId) => hub.broadcastTo(caseId, { type: "comments_changed" }),
    tagsStore,
    onTags: (caseId) => hub.broadcastTo(caseId, { type: "tags_changed" }),
    pinnedFindingsStore,
    onPins: (caseId) => hub.broadcastTo(caseId, { type: "pins_changed" }),
    findingWorkflowStore,
    onFindingWorkflow: (caseId) => hub.broadcastTo(caseId, { type: "finding_workflow_changed" }),
    notebookStore,
    onNotebook: (caseId) => hub.broadcastTo(caseId, { type: "notebook_changed" }),
    hypothesisStore,
    onHypotheses: (caseId) => hub.broadcastTo(caseId, { type: "hypotheses_changed" }),
    learnedPatternStore,
    onLearnedPatterns: (caseId) => hub.broadcastTo(caseId, { type: "learned_patterns_changed" }),
    sourceTrustStore,
    clockSkewStore,
    onClockSkew: (caseId) => hub.broadcastTo(caseId, { type: "clock_skew_changed" }),
    onSourceTrust: (caseId) => hub.broadcastTo(caseId, { type: "source_trust_changed" }),
    dwellWindowStore,
    onDwellWindow: (caseId) => hub.broadcastTo(caseId, { type: "dwell_window_changed" }),
    superTimelineStore,
    onSuperTimeline: (caseId) => hub.broadcastTo(caseId, { type: "super_timeline_changed" }),
    starredReportStore,
    forensicGateControlStore,
    onForensicGate: (caseId) => hub.broadcastTo(caseId, { type: "forensic_gate_changed" }),
    custodyStore,
    integrityMonitor,
    confidenceControlStore,
    onConfidenceControl: (caseId) => hub.broadcastTo(caseId, { type: "confidence_control_changed" }),
    complianceControlStore,
    playbookStore,
    playbookHuntStore,
    playbookControlStore,
    onPlaybook: (caseId) => hub.broadcastTo(caseId, { type: "playbook_changed" }),
    assetOverridesStore,
    onAssetOverrides: (caseId) => hub.broadcastTo(caseId, { type: "asset_overrides_changed" }),
    lateralPathDismissStore,
    iocAliasStore,
    onIocMerge: (caseId) => hub.broadcastTo(caseId, { type: "ioc_merge_changed" }),
    onFalsePositive: (caseId) => hub.broadcastTo(caseId, { type: "false_positive_changed" }),
    onScope: (caseId, scope) => hub.broadcastTo(caseId, { type: "scope_changed", ...scope }),
    synthMetaStore,
    analysisRunStore,
    aiCostStore,
    correlationProfileStore,
    secondOpinionStore,
    secondOpinionEnabled: Boolean(secondOpinionProvider),
    onSecondOpinion: (caseId) => hub.broadcastTo(caseId, { type: "second_opinion_changed" }),
    importMetaStore,
    onImportMeta: (caseId) => hub.broadcastTo(caseId, { type: "import_meta_changed" }),
    dropStatusStore,
    onDropStatus: (caseId) => hub.broadcastTo(caseId, { type: "drop_status_changed" }),
    // External forensic tools (#211): the real spawn runner (tests inject a stub). Config is read live
    // from DFIR_TOOL_* env, so a tool is off until its binary is set — no gating client to build.
    toolRunner: spawnToolRunner(),
    customToolStore,
    // MCP policy (#296). No gating client: the companion holds no credentials and reaches every
    // server through Claude Code, which must be installed and configured on this host.
    mcpServerStore,
    // Extra browser origins permitted past the origin guard (#211), beyond the extension and
    // loopback. Comma-separated, e.g. "https://soc.example.com".
    allowedOrigins: parseAllowedOrigins(process.env.DFIR_ALLOWED_ORIGINS),
    // Extra hostnames this companion answers to (#280), beyond loopback and bare IP addresses.
    // Only a deployment reached through a NAME needs these — e.g. "dfir.example.com", or the
    // suffix ".lab.example.com" where the platform mints a fresh hostname per session.
    allowedHosts: parseAllowedHosts(process.env.DFIR_ALLOWED_HOSTS),
    allowedHostSuffixes: parseAllowedHostSuffixes(process.env.DFIR_ALLOWED_HOST_SUFFIXES),
    importUndoStore,
    onImportUndo: (caseId) => hub.broadcastTo(caseId, { type: "import_undo_changed" }),
    jobManager,
    autoSynthesize,
    autoSynthesizeDebounceMs,
    onAiStatus: (caseId, event) => hub.broadcastTo(caseId, { type: "ai_status", ...event }),
    // Broadcast to ALL dashboards so one viewing a different case can warn that captures are
    // arriving here (the capture extension is pointed at a case the analyst isn't looking at).
    onCapture: (caseId) => hub.broadcastAll({ type: "capture_ingest", caseId }),
    onImport: (caseId) => hub.broadcastAll({ type: "import_ingest", caseId }),
    onState: (s) => hub.broadcast(s),
    enrichmentProviders: buildEnrichmentProviders(),
    enrichDelayMs: Number(process.env.DFIR_ENRICH_DELAY_MS) || undefined,
    enrichProviderDelayMs: buildEnrichProviderDelayMap(),
    // #78: ± jitter on the inter-call wait, and bounded retry-with-backoff on a 429 (honouring
    // Retry-After) instead of a single rate-limit hit aborting the lookup.
    // NOTE: parse with `numEnv` (not `Number(x) || undefined`) so an explicit "0" is honored —
    // `Number("0") || undefined` is `undefined` (0 is falsy), which silently fell back to the
    // hardcoded default. An operator who set DFIR_ENRICH_RETRIES=0 to disable 429 retry still
    // got 2 retries (#5). The poller's `=== "0"` special-case is now unified here too.
    enrichJitterMs: numEnv("DFIR_ENRICH_JITTER_MS"),
    enrichRetries: numEnv("DFIR_ENRICH_RETRIES"),
    enrichRetryBackoffMs: numEnv("DFIR_ENRICH_RETRY_BACKOFF_MS"),
    enrichMaxIocs: numEnv("DFIR_ENRICH_MAX"),
    customerExposureProviders: buildCustomerExposureProviders(),
    customerExposureDelayMs: numEnv("DFIR_EXPOSURE_DELAY_MS"),
    // Reachability gate: probe a self-hosted MISP/YETI before sending IOCs, cached this long
    // (default 60s in the cache). The poller re-checks down servers on the same cadence and
    // auto-resumes skipped cases on recovery — set DFIR_ENRICH_HEALTH_POLL_MS=0 to disable it.
    enrichHealthTtlMs: numEnv("DFIR_ENRICH_HEALTH_TTL_MS"),
    enrichHealthPollMs: numEnv("DFIR_ENRICH_HEALTH_POLL_MS") ?? 60_000,
    irisClient: buildIrisClient(),
    velociraptorClient,
    velociraptorClientStore,
    artifactBundleStore,
    iocWhitelistStore,
    importerStore,
    onImporters: () => hub.broadcastAll({ type: "importers_changed" }),
    nsrlStore,
    nsrlDb,
    nsrlDbConfigFile,
    nsrlDbEnvManaged,
    kevStore,
    veloHuntStore,
    huntOutcomeStore,
    huntRunSnapshotStore,
    onVeloHunt: (caseId) => hub.broadcastTo(caseId, { type: "velo_hunt_changed" }),
    veloMonitorStore,
    onVeloMonitor: (caseId) => hub.broadcastTo(caseId, { type: "velo_monitor_changed" }),
    veloMonitorPollSeconds,
    pushToken,
    pushTokenStore,
    onPushToken: (caseId) => hub.broadcastTo(caseId, { type: "push_token_changed" }),
    // Trim the dashboard's hunt-query modal to the tools this team runs (default: all).
    huntPlatforms: resolveHuntPlatforms(process.env.DFIR_HUNT_PLATFORMS),
    irisOptions: irisPushOptions(),
    irisExportStore,
    timesketchClient: buildTimesketchClient(),
    timesketchOptions: timesketchPushOptions(),
    rebuildTimesketchClient: buildTimesketchClient,
    templateStore,
    incidentTypeStore,
    collectionPlanStore,
    mispPushClient: buildMispPushClient(),
    mispPushOptions: mispPushOptions(),
    notionClient: buildNotionClient(),
    notionOptions: notionPushOptions(),
    notionExportStore,
    clickupClient: buildClickUpClient(),
    clickupExportStore,
    clickupOptions: clickupOptions(),
    jiraClient: buildJiraClient(),
    jiraExportStore: new JiraExportStore(store),
    jiraOptions: jiraOptions(),
    servicenowClient: buildServiceNowClient(),
    servicenowExportStore: new ServiceNowExportStore(store),
    servicenowOptions: servicenowOptions(),
    notificationStore,
    slashCommandChannelStore,
    telegramPolling: (process.env.DFIR_TELEGRAM_POLL ?? "").trim().toLowerCase() === "on",
    slackSocketMode: (process.env.DFIR_SLACK_SOCKET_MODE ?? "").trim().toLowerCase() === "on",
    notifier,
    notifyEmailEnabled: true,
    dashboardBaseUrl,
    // Diagnostics AI connectivity test (#118): rebuild a provider from the CURRENT env each call,
    // so a key/model saved via Settings is reflected even before a server restart.
    aiTestProvider: () => buildProvider(),
    updateCheckStore,
    appVersion,
    updateCheckEnv: process.env.DFIR_UPDATE_CHECK,
    updateRepo,
    demoMode,
    backupManager,
    // Pre-flight (#179): fire the checks once the server is listening (startServer does that).
    onPreflightReady,
  };
}
