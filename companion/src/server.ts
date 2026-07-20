import express, { type Express, type Request, type Response, type NextFunction, type CookieOptions } from "express";
// Patch Express 4's router so async route handlers that throw or reject are forwarded to the
// terminal error middleware (see the end of createApp) instead of hanging the client connection
// or surfacing an UnhandledPromiseRejection. Side-effect-only import; must load before any route
// is registered, so it stays at the top with express itself.
import "express-async-errors";
import { config as loadDotenv } from "dotenv";
import { join, basename, isAbsolute, resolve, dirname, relative, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { writeFile, readFile, rm, readdir, stat, open, copyFile, mkdir, mkdtemp, rename } from "node:fs/promises";
import { ZodError } from "zod";
import { CaseStore, isValidCaseId } from "./storage/caseStore.js";
import { BackupManager, resolveBackupConfig } from "./storage/backupManager.js";
import { atomicWrite } from "./storage/atomicWrite.js";
import type { RouteContext, ImportBase } from "./routes/context.js";
import { registerSystemRoutes } from "./routes/system.js";
import { registerCaptureRoutes } from "./routes/captures.js";
import { registerPushNotifyRoutes } from "./routes/pushNotify.js";
import { registerTemplatesViewsRoutes } from "./routes/templatesViews.js";
import { registerToolsRoutes } from "./routes/tools.js";
import { registerImportRoutes } from "./routes/import.js";
import { registerVelociraptorRoutes } from "./routes/velociraptor.js";
import { registerThreatIntelRoutes } from "./routes/threatIntel.js";
import { registerAnonymizationRoutes } from "./routes/anonymization.js";
import { registerTimelineRoutes } from "./routes/timeline.js";
import { registerAnalysisGraphRoutes } from "./routes/analysisGraph.js";
import { registerFindingsRoutes } from "./routes/findings.js";
import { registerTaggerRoutes } from "./routes/tagger.js";
import { registerPlaybookHuntsRoutes } from "./routes/playbookHunts.js";
import { registerAiSynthesisRoutes } from "./routes/aiSynthesis.js";
import { registerReportsExportRoutes } from "./routes/reportsExport.js";
import { registerCasePasswordRoutes } from "./routes/casePassword.js";
import { registerCaseLifecycleRoutes } from "./routes/caseLifecycle.js";
import { ingestCapture, CaseNotFoundError } from "./ingest/captureIngest.js";
import { AiControlStore, type AiControl } from "./analysis/aiControl.js";
import { JobManager, type RegisteredJob } from "./analysis/jobManager.js";
import { AnonControlStore } from "./analysis/anonControl.js";
import { CustomEntitiesStore } from "./analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "./analysis/anonDiscovered.js";
import { isLocalAiProvider } from "./analysis/anonymize.js";
import { TesseractOcrRunner, type OcrRunner } from "./analysis/ocrRedact.js";
import { extractOcrText, isOcrSearchEnabled } from "./analysis/ocrSearch.js";
import { FalsePositiveStore, markerId, type FalsePositiveMarker } from "./analysis/falsePositive.js";
import { ScopeStore, type ScopeWindow } from "./analysis/scope.js";
import { CorrelationProfileStore } from "./analysis/correlationProfile.js";
import {
  exportEncryptedCase,
  importEncryptedCase,
  CaseImportConflictError,
  MIN_PASSWORD_LENGTH,
  dfircaseFilename,
} from "./analysis/caseExportArchive.js";
import {
  verifyUnlockToken,
  isRememberedUnlockToken,
  unlockCookieName,
  parseCookieHeader,
} from "./analysis/casePassword.js";
import { loadOrCreateInstanceSecret } from "./analysis/instanceSecret.js";
import { createCaseLockGate } from "./analysis/caseLockGate.js";
import { contextTokens as resolveContextTokens } from "./analysis/promptBudget.js";
import { resolveHuntPlatforms, type HuntPlatform } from "./analysis/huntPlatforms.js";
import { parseVelociraptorJson } from "./analysis/velociraptorImport.js";
import { detectImportWithCustom } from "./analysis/importDetect.js";
import { ImporterStore, type ImporterRegistry, type ImporterPrecedence } from "./analysis/importerStore.js";
import { resolveEnvFilePath } from "./settings/envManager.js";
import { applySeverityFloor } from "./analysis/severityFloor.js";
import { enrichIocs, hasEnrichableWork, type EnrichLookupEvent } from "./enrichment/enrichService.js";
import { EnrichControlStore, resolveEnabledProviders } from "./enrichment/enrichControl.js";
import { ProviderHealthCache } from "./enrichment/providerHealth.js";
import type { EnrichmentProvider } from "./enrichment/provider.js";
import { VirusTotalProvider } from "./enrichment/virustotal.js";
import { HuntingChProvider } from "./enrichment/huntingch.js";
import { CrowdStrikeProvider } from "./enrichment/crowdstrike.js";
import { AbuseIpdbProvider } from "./enrichment/abuseipdb.js";
import { MispProvider } from "./enrichment/misp.js";
import { RockyRaccoonProvider, type ParentChildResult } from "./enrichment/rockyraccoon.js";
import { YetiProvider } from "./enrichment/yeti.js";
import { OpenCtiProvider } from "./enrichment/opencti.js";
import { ReverseDnsProvider } from "./enrichment/reverseDns.js";
import { LookalikeDomainProvider } from "./enrichment/lookalikeDomain.js";
import { RdapProvider } from "./enrichment/rdap.js";
import { GeoIpProvider } from "./enrichment/geoip.js";
import { ShodanProvider } from "./enrichment/shodan.js";
import { HashlookupProvider } from "./enrichment/hashlookup.js";
import { buildTlsFetch } from "./enrichment/tlsFetch.js";
import { validateProcessChains, hasChainWork, type ChainSummary } from "./enrichment/chainValidate.js";
import type { AnalysisPipeline } from "./analysis/pipeline.js";
import type { InvestigationState, Severity, ForensicEvent, IOC, Finding } from "./analysis/stateTypes.js";
import type { CaptureMetadata } from "./types.js";
import type { StateStore } from "./analysis/stateStore.js";
import type { ReportWriter } from "./reports/reportWriter.js";
import type { IocBlocklistFormat, IocBlocklistOptions, BlocklistIocType } from "./reports/iocBlocklist.js";
import { ReportMetaStore } from "./reports/reportMeta.js";
import { ReportTemplateStore } from "./reports/reportTemplateStore.js";
import { ReportTemplateControlStore } from "./reports/reportTemplateControl.js";
import { DashboardViewStore } from "./analysis/dashboardViewStore.js";
import { ActivityLogStore } from "./analysis/activityLog.js";
import { CommentsStore } from "./analysis/comments.js";
import { TagsStore, type Tag } from "./analysis/tags.js";
import { PinnedFindingsStore } from "./analysis/pinnedFindings.js";
import { FindingWorkflowStore } from "./analysis/findingWorkflow.js";
import { NotebookStore } from "./analysis/notebookStore.js";
import { HypothesisStore } from "./analysis/hypothesisStore.js";
import { LearnedPatternStore } from "./analysis/learnedPatternStore.js";
import { SourceTrustStore } from "./analysis/sourceTrustStore.js";
import { DwellWindowStore } from "./analysis/dwellWindowStore.js";
import { SuperTimelineStore } from "./analysis/superTimelineStore.js";
import { StarredReportStore } from "./analysis/starredReportStore.js";
import { TaggerStore } from "./analysis/taggerStore.js";
import { autoTagNewEvents } from "./analysis/taggerAuto.js";
import { ForensicGateControlStore } from "./analysis/forensicGateControl.js";
import { demoteBelowSeverity, resolveForensicMinSeverity } from "./analysis/forensicGate.js";
import { ConfidenceControlStore } from "./analysis/confidenceControl.js";
import { PlaybookStore } from "./analysis/playbookStore.js";
import { type PlaybookTask } from "./analysis/playbook.js";
import { PlaybookHuntStore } from "./analysis/playbookHuntStore.js";
import { HuntOutcomeStore } from "./analysis/huntOutcomeStore.js";
import { recordDeploy, fillOutcome, HUNT_OUTCOME_MAX_DEFAULT, type HuntDeployInput } from "./analysis/huntOutcomes.js";
import { PlaybookControlStore, DEFAULT_PLAYBOOK_CONTROL, type PlaybookControl } from "./analysis/playbookControl.js";
import { AssetOverridesStore } from "./analysis/assetOverrides.js";
import { LateralPathDismissStore } from "./analysis/lateralPathDismiss.js";
import { IocAliasStore } from "./analysis/iocAlias.js";
import { SynthMetaStore } from "./analysis/synthMeta.js";
import { AiCostStore } from "./analysis/aiCost.js";
import { SecondOpinionStore } from "./analysis/secondOpinionStore.js";
import { ImportMetaStore } from "./analysis/importMeta.js";
import { DropStatusStore, type DropFailure, type PendingRawInput } from "./analysis/dropStatus.js";
import {
  selectReadyFiles, classifyDropFile, rawToolInputExt, RAW_TOOL_EXTS, shouldIgnoreDropFile, isOversize,
  DROP_PROCESSED, DROP_FAILED, DROP_README, type DropFileStat,
} from "./analysis/dropScan.js";
import { formatDropLogLines, appendDropLog, buildSweepLogEntries, type DropLogEntry } from "./analysis/dropLog.js";
import {
  loadAllToolConfigs, toolForExtension, suggestedToolForExtension, type ToolId, type ToolConfig,
} from "./integrations/tools/toolConfig.js";
import { spawnToolRunner, type ToolRunner } from "./integrations/tools/toolRunner.js";
import { runToolAgainstFile, resolveContainedPath } from "./integrations/tools/runToolImport.js";
import { CustomToolStore, customToolToConfig, normalizeExt, type CustomTool } from "./integrations/tools/customToolStore.js";
import { TemplateStore } from "./analysis/templateStore.js";
import { diffTimeline, addedForensicEvents } from "./analysis/timelineDiff.js";
import { diffIocs } from "./analysis/iocsDiff.js";
import { ImportUndoStore, pushCheckpoint } from "./analysis/importUndo.js";
import { IocWhitelistStore } from "./analysis/iocWhitelistStore.js";
import { whitelistMatches } from "./analysis/iocWhitelist.js";
import { sanitizeExcludeRuleInput, matchIocToExclude, type IocExcludeRule } from "./analysis/iocExclude.js";
import { NsrlStore, ingestNsrlFiles, splitNsrlPaths } from "./analysis/nsrlStore.js";
import { nsrlMatchIocs, nsrlMatchEvents } from "./analysis/nsrl.js";
import { KevStore } from "./analysis/kevStore.js";
import { getAppVersion } from "./version.js";
import {
  resolveUpdateMode, DEFAULT_UPDATE_REPO,
  UPDATE_CHECK_THROTTLE_MS,
} from "./analysis/updateCheck.js";
import { UpdateCheckStore } from "./analysis/updateCheckStore.js";
import { performUpdateCheck } from "./analysis/updateCheckRun.js";
import { StateLock } from "./analysis/stateLock.js";
import { NsrlDb, loadNsrlDbPath } from "./analysis/nsrlDb.js";
import { applyDeobfuscation } from "./analysis/applyDeobfuscation.js";
import { readPublicAsset, isSeaRuntime } from "./serverAssets.js";
import {
  CustomerExposureStore,
  type CustomerExposureProvider,
} from "./analysis/customerExposure.js";
import { IrisClient } from "./integrations/iris/irisClient.js";
import { VelociraptorClient, buildVelociraptorClient, ALL_CLIENTS, type HuntUpload } from "./integrations/velociraptor/velociraptorApi.js";
import { ArtifactBundleStore } from "./analysis/artifactBundleStore.js";
import { VelociraptorClientStore } from "./analysis/velociraptorClientStore.js";
import { VeloHuntStore, type VeloHuntJob } from "./analysis/veloHuntStore.js";
import { VeloMonitorStore, monitorId, type VeloMonitor } from "./analysis/veloMonitorStore.js";
import { pollMonitorOnce, monitorArtifactMap, type PollDeps } from "./integrations/velociraptor/monitorPoller.js";
import { pollHuntStatusOnce, isHuntStoppedEarly, type HuntPollDeps } from "./integrations/velociraptor/huntStatusPoller.js";
import { PushTokenStore } from "./analysis/pushTokenStore.js";
import { type IrisPushOptions } from "./integrations/iris/irisPush.js";
import { IrisExportStore } from "./integrations/iris/irisExportStore.js";
import { TimesketchClient } from "./integrations/timesketch/timesketchClient.js";
import { type TimesketchPushOptions } from "./integrations/timesketch/timesketchPush.js";
import { MispPushClient } from "./integrations/misp/mispPushClient.js";
import { type MispPushOptions } from "./integrations/misp/mispPush.js";
import { NotionClient, parseNotionPageId } from "./integrations/notion/notionClient.js";
import { type NotionPushOptions } from "./integrations/notion/notionPush.js";
import { NotionExportStore } from "./integrations/notion/notionExportStore.js";
import { ClickUpClient } from "./integrations/clickup/clickupClient.js";
import { ClickUpExportStore } from "./integrations/clickup/clickupExportStore.js";
import type { ImporterFailure, AiError, ImporterRunStat } from "./analysis/diagnostics.js";
import type { PreflightReport } from "./analysis/preflight.js";
import { NotificationConfigStore } from "./analysis/notificationStore.js";
import { seedDemoCase } from "./analysis/seedDemoCase.js";
import {
  findingEventsFromDiff, milestoneEvent,
  type NotificationEvent,
} from "./analysis/notifications.js";
import { createNotifier, type Notifier } from "./integrations/notify/notifyDispatch.js";
import { nodeSmtpConnect } from "./integrations/notify/smtpClient.js";
import {
  DeHashedExposureProvider,
  HaveIBeenPwnedExposureProvider,
  LeakCheckExposureProvider,
  ShodanExposureProvider,
} from "./integrations/customerExposureProviders.js";
import {
  LoggerImpl,
  createConsoleLogger,
  normalizeLogLevel,
  type Logger,
} from "./logging/logger.js";

// Server logging. A single shared Logger tees every line to the console AND to log files
// (a global session log + per-case logs); the helpers below delegate to it so the existing
// call sites keep working. startServer() swaps in the file-backed logger and the dashboard's
// Logging toggle changes its level live (no restart); tests/CLI get a console-only default.
let serverLogger: Logger = createConsoleLogger(normalizeLogLevel(process.env.DFIR_LOG_LEVEL));
export function setServerLogger(logger: Logger): void { serverLogger = logger; }
export function getServerLogger(): Logger { return serverLogger; }
function logLine(msg: string): void { serverLogger.info(msg); }
function warnLine(msg: string): void { serverLogger.warn(msg); }

// Truncate a long indicator (e.g. a SHA-256) for a readable one-line log entry.
function shortValue(value: string): string {
  return value.length > 24 ? `${value.slice(0, 24)}…` : value;
}

export type AiStatus = "analyzing" | "idle" | "error";
// What the AI is actually doing, so the dashboard can say "processing screenshots"
// vs "synthesizing" vs idle rather than a generic "analyzing".
export type AiPhase = "extracting" | "synthesizing";

export interface AiStatusEvent {
  status: AiStatus;
  at: string;        // ISO timestamp
  phase?: AiPhase;   // present when status === "analyzing"
  detail?: string;   // e.g. window size, or error message
}

export interface AppOptions {
  pipeline?: AnalysisPipeline;
  // Per-case mutex serializing load->save critical sections so concurrent state writes
  // (manual adds vs background enrichment/synthesis) cannot clobber each other.
  stateLock?: StateLock;
  aiConfigured?: boolean;
  windowSize?: number;
  // Safety-net flush interval. A `timer`/`click` capture buffers until `windowSize`
  // accumulates (only a `navigation`/`tab_switch` flushes early), so a lone screenshot could
  // sit unanalyzed indefinitely. A background sweep drains any non-empty buffer on this
  // interval so even a single capture is analyzed. Default 5 min; set 0 to disable.
  flushIntervalMs?: number;
  stateStore?: StateStore;
  reportWriter?: ReportWriter;
  // OCR backend for the redacted case export (#54), used to blur PII text in screenshots. Provided
  // unconditionally in startServer (the export needs it even when the vision model is local); tests
  // inject a stub. The export route falls back to a fresh TesseractOcrRunner when this is absent.
  ocrRunner?: OcrRunner;
  // Human-authored report metadata (title page, distribution, BIA, glossary, recommendations…)
  // edited from the dashboard and merged into report.md.
  reportMetaStore?: ReportMetaStore;
  // Custom report templates (issue #60): GLOBAL branded layouts (accent, cover, header/footer,
  // section selection) + the per-case selection of which template renders the report.
  reportTemplateStore?: ReportTemplateStore;
  reportTemplateControlStore?: ReportTemplateControlStore;
  onReportTemplate?: (caseId: string) => void;
  // Dashboard view presets (#142): GLOBAL role/phase layouts (sections + severity/top-N filter +
  // matching report template) the dashboard applies. Built-ins editable in place, custom via CRUD.
  dashboardViewStore?: DashboardViewStore;
  // Per-case investigation activity log (#238): chronological record of security-relevant
  // actions. onActivity pings dashboard clients over the WS to re-fetch on a new entry.
  activityLogStore?: ActivityLogStore;
  onActivity?: (caseId: string) => void;
  // Investigator comments on case entities (collaboration). onComments pings dashboard
  // clients over the WS to re-fetch when a comment is added/removed.
  commentsStore?: CommentsStore;
  onComments?: (caseId: string) => void;
  // Analyst triage tags on case entities (hand labels like confirmed-malicious / false-positive
  // / key-evidence, independent of AI severity). onTags pings dashboard clients over the WS to
  // re-fetch when a tag is added/removed.
  tagsStore?: TagsStore;
  onTags?: (caseId: string) => void;
  // Analyst-pinned findings (#220): a small ordered shortlist the analyst pins so the most
  // important findings stay visible in a dedicated strip while scrolling. onPins pings dashboard
  // clients over the WS to re-fetch when a finding is pinned/unpinned/reordered.
  pinnedFindingsStore?: PinnedFindingsStore;
  onPins?: (caseId: string) => void;
  // Analyst assignment + workflow status for findings (#87): a human owner and an analyst-editable
  // triage state (new/in-progress/in-review/resolved), kept in a side file so re-synthesis never
  // wipes them. onFindingWorkflow pings dashboard clients over the WS to re-fetch on any change.
  findingWorkflowStore?: FindingWorkflowStore;
  onFindingWorkflow?: (caseId: string) => void;
  // Per-case analyst notebook (hypotheses, notes, open questions). onNotebook pings dashboard
  // clients over the WS to re-fetch when an entry is added, updated, or removed.
  notebookStore?: NotebookStore;
  onNotebook?: (caseId: string) => void;
  // Per-case hypotheses (issue #140): status-tracked investigative hypotheses, analyst-authored or
  // auto-generated by synthesis. onHypotheses pings dashboard clients over the WS to re-fetch.
  hypothesisStore?: HypothesisStore;
  onHypotheses?: (caseId: string) => void;
  // Learned dismissal patterns (issue #65): recurring reasoned dismissals accumulated per case, fed to
  // synthesis as a confidence-lowering block. onLearnedPatterns pings dashboard clients to re-fetch.
  learnedPatternStore?: LearnedPatternStore;
  onLearnedPatterns?: (caseId: string) => void;
  // Per-case source-trust overrides (issue #66). onSourceTrust pings dashboard clients to re-fetch.
  sourceTrustStore?: SourceTrustStore;
  onSourceTrust?: (caseId: string) => void;
  // Analyst-defined attacker-presence time windows (dwell-time feature). onDwellWindow pings live
  // dashboard clients over the WS to re-fetch after a mutation, mirroring onHypotheses.
  dwellWindowStore?: DwellWindowStore;
  onDwellWindow?: (caseId: string) => void;
  // Fired after the super-timeline changes (a label (un)set) so live dashboard clients refresh.
  onSuperTimeline?: (caseId: string) => void;
  // Super-timeline: the complete record of every imported event (a superset of the forensic timeline).
  // Every normal import dual-writes its newly-added events here; the forensic timeline stays curated.
  superTimelineStore?: SuperTimelineStore;
  // Saved copy of the TimeSketch-style Starred Events Report (a per-case side file) — POST
  // /starred-report generates it fresh each time (ephemeral); PUT persists the analyst's chosen
  // copy here so it survives a reload; GET reads it back.
  starredReportStore?: StarredReportStore;
  // Content-based event tagger (Timesketch-style tags.yaml): the rule file store. Powers manual
  // "Run tagger" + rule editing (routes/tagger.ts) and the automatic post-import run (pipeline).
  taggerStore?: TaggerStore;
  // Per-case forensic-timeline severity cut (machine/analyst preference — NOT snapshotted). After every
  // import dual-writes into the super-timeline, sub-threshold (Info-by-default) events are demoted OUT of
  // the forensic timeline so the AI only synthesizes graded signal. onForensicGate pings live dashboard
  // clients over the WS to re-fetch after the per-case threshold changes.
  forensicGateControlStore?: ForensicGateControlStore;
  onForensicGate?: (caseId: string) => void;
  // Per-case minimum-confidence display preference (#226) — a machine/analyst preference, not
  // investigation data, mirroring forensicGateControlStore's shape. Purely a display filter: nothing
  // is removed from state, only the dashboard's findings list defaults to this floor.
  confidenceControlStore?: ConfidenceControlStore;
  onConfidenceControl?: (caseId: string) => void;
  // Per-case playbook (issue #36): a trackable checklist auto-derived from the case's next
  // steps + high-severity findings (idempotent re-derive preserves analyst progress), plus
  // custom tasks. Persisted in state/playbook.json; survives synthesis. onPlaybook pings
  // dashboard clients over the WS to re-fetch when a task changes or a sync runs.
  playbookStore?: PlaybookStore;
  onPlaybook?: (caseId: string) => void;
  // AI-suggested Velociraptor hunts persisted per case (#70) so they survive a page refresh; a
  // suggestion is dropped on read once its task is reworded/deleted (state/playbook-hunts.json).
  playbookHuntStore?: PlaybookHuntStore;
  // Per-case playbook settings (Phase 2): whether Critical/High findings expand into severity-based
  // IR templates. Read when deriving auto-tasks; default off (opt-in per case).
  playbookControlStore?: PlaybookControlStore;
  // Manual edits to the asset ↔ IoC graph (renames, additions, suppressions, link overrides).
  // Persisted per case in state/asset-overrides.json; survives synthesis. onAssetOverrides
  // pings dashboard clients over the WS to re-fetch the graph when overrides change.
  assetOverridesStore?: AssetOverridesStore;
  onAssetOverrides?: (caseId: string) => void;
  // Analyst-dismissed lateral-movement chains, persisted per case in
  // state/lateral-path-dismissals.json. Rejects a derived INFERENCE without discarding the
  // underlying evidence the way a false-positive marker would.
  lateralPathDismissStore?: LateralPathDismissStore;
  // Entity merging for duplicate IOCs (#82). iocAliasStore persists per-case merge aliases (state/
  // ioc-aliases.json) so a future re-synthesis routes the merged-away value onto its canonical IOC
  // instead of recreating it (see pipeline.ts's mergeWithAliases). onIocMerge pings dashboard
  // clients over the WS to re-fetch when a merge/unmerge happens.
  iocAliasStore?: IocAliasStore;
  onIocMerge?: (caseId: string) => void;
  // Confirmed false-positive markers. onFalsePositive pings dashboard
  // clients over the WS so other investigators see the change immediately, before synthesis.
  onFalsePositive?: (caseId: string) => void;
  // Investigation time-window changes. onScope pings dashboard clients with the new window so
  // other investigators can apply the same scope instantly, without waiting for re-synthesis.
  onScope?: (caseId: string, scope: ScopeWindow) => void;
  // Last-synthesis record (when it ran + findings diff) for the dashboard's "last synthesized N
  // ago" indicator and what-changed view. Read-only here; the pipeline writes it on each run.
  synthMetaStore?: SynthMetaStore;
  // Per-case AI cost/token accounting (vision/synthesis/other buckets), read-only here —
  // the pipeline (via AiCostStore.record) writes it after every AI call.
  aiCostStore?: AiCostStore;
  correlationProfileStore?: CorrelationProfileStore;
  // Second LLM opinion (issue #116): the last QA cross-check record (deltas + analyst decisions),
  // read by the GET route. `secondOpinionEnabled` gates the dashboard button (a different model is
  // configured). onSecondOpinion pings dashboard clients to re-fetch after a run or accept/reject.
  secondOpinionStore?: SecondOpinionStore;
  secondOpinionEnabled?: boolean;
  onSecondOpinion?: (caseId: string) => void;
  // Last-import record (when it ran + forensic-timeline diff) for the dashboard's "last import N
  // ago - +N new events" indicator and what-was-added view above the timeline. The unified /import
  // route writes it after the importer completes; onImportMeta pings dashboard clients to re-fetch.
  importMetaStore?: ImportMetaStore;
  onImportMeta?: (caseId: string) => void;
  // Evidence drop folder (auto-import inbox): the last-sweep summary read by GET /cases/:id/drop-status
  // and the live "📥 Drop: N imported, M failed" banner. Presence of dropStatusStore also ARMS the
  // background watcher (so createApp-only unit tests that omit it never start a filesystem poller).
  // onDropStatus pings dashboard clients to re-fetch after a sweep that imported or failed something.
  dropStatusStore?: DropStatusStore;
  onDropStatus?: (caseId: string) => void;
  // Import undo/redo (#76): before each import the pre-import forensic timeline + IOCs are snapshotted
  // onto a per-case stack so the analyst can roll back an import that floods the dashboard (and redo).
  // onImportUndo pings dashboard clients to re-fetch the undo-stack state (button enable/labels).
  importUndoStore?: ImportUndoStore;
  onImportUndo?: (caseId: string) => void;
  // Called when an AI analysis window starts / finishes / fails, so the
  // server can push a live "AI status" indicator to dashboard clients.
  onAiStatus?: (caseId: string, event: AiStatusEvent) => void;
  // Called for every ingested capture (duplicate or not). Lets the server broadcast a cross-case
  // signal so a dashboard can warn when captures are arriving for a DIFFERENT case than it's viewing.
  onCapture?: (caseId: string) => void;
  // Called for every accepted artifact import / push. Same purpose as onCapture but for imported
  // evidence (the extension's "Push to DFIR-Companion") — broadcast to ALL dashboards so one viewing
  // a different case warns that artifacts are arriving for another case (parity with screenshots).
  onImport?: (caseId: string) => void;
  // When true, run the synthesis pass automatically (debounced) after capture
  // windows are analyzed, so the live dashboard shows findings/attacker path.
  autoSynthesize?: boolean;
  autoSynthesizeDebounceMs?: number;
  // Threat-intel enrichment providers (VirusTotal, MalwareBazaar, AbuseIPDB…).
  enrichmentProviders?: EnrichmentProvider[];
  enrichDelayMs?: number;
  enrichProviderDelayMs?: Record<string, number>;  // per-provider throttle overrides (keyed by provider.name)
  enrichJitterMs?: number;          // ± random jitter added to the inter-call wait (#78)
  enrichRetries?: number;           // retry attempts for a provider call that hits a 429 (#78)
  enrichRetryBackoffMs?: number;    // base backoff before the first 429 retry, doubles each attempt (#78)
  enrichMaxIocs?: number;
  // Customer Exposure is separate from IOC enrichment: only customer-owned domains/emails are
  // sent to breach-data providers. IOC domains are never queried here.
  customerExposureProviders?: CustomerExposureProvider[];
  customerExposureDelayMs?: number;
  // Provider reachability gate. A self-hosted MISP / YETI can be down; rather than fire one
  // doomed request per IOC, each provider is probed (cached `enrichHealthTtlMs`, default 60s)
  // before sending — a down provider is skipped this run. When `enrichHealthPollMs` is set
  // (>0), a background poller re-probes down providers on that interval and auto-resumes
  // enrichment for cases it had to skip, once the server is reachable again.
  enrichHealthTtlMs?: number;
  enrichHealthPollMs?: number;
  // Broadcast a fresh investigation state to dashboard clients (for routes that change
  // state outside the AI pipeline, e.g. enrichment).
  onState?: (state: InvestigationState) => void;
  // DFIR-IRIS push: a configured client (when DFIR_IRIS_URL/KEY are set) + mapping options
  // (customer/classification ids, base URL for the case link).
  irisClient?: IrisClient;
  irisOptions?: IrisPushOptions;
  // Rebuilds the IRIS client from current config (used by POST /iris/reconnect so config saved
  // via Settings, or IRIS coming back online, applies without a server restart). Defaults to the
  // env-based buildIrisClient; tests inject a stub (no network).
  rebuildIrisClient?: () => IrisClient | undefined;
  // Remembers the IRIS case name used on the last push per Companion case, so a re-push with
  // no explicit override still targets the same IRIS case (find-or-create is name-based).
  irisExportStore?: IrisExportStore;
  // Velociraptor API: a configured client (when DFIR_VELOCIRAPTOR_API_CONFIG is set) lets the
  // dashboard run the generated hunt VQL against the server and show the rows inline.
  velociraptorClient?: VelociraptorClient;
  // Rebuilds the Velociraptor client from current config (used by POST /velociraptor/reconnect so
  // config saved via Settings, or the Velociraptor server coming back online, applies without a server
  // restart). Defaults to the env-based buildVelociraptorClient; tests inject a stub (no spawn).
  rebuildVelociraptorClient?: () => VelociraptorClient | undefined;
  // External forensic tools (#211): a runner that spawns the analyst-configured LOCAL binaries
  // (Hayabusa/Velociraptor CLI/Suricata/Snort/YARA) against raw evidence and hands the output to the
  // existing importers. Absent → the tools feature is off (routes 501, drops surface a "configure"
  // banner). Config is read live from DFIR_TOOL_* env via `loadToolConfigs` (default reads process.env,
  // so POST /tools/reconnect applies saved settings without a restart). Tests inject stubs (no spawn).
  toolRunner?: ToolRunner;
  loadToolConfigs?: () => Map<ToolId, ToolConfig>;
  // User-defined custom tools (#211) — a GLOBAL JSON store of analyst-added tools (name/binary/command/
  // extensions), merged into the tool set alongside the built-ins. Absent → only built-ins.
  customToolStore?: CustomToolStore;
  // Persisted inventory of enrolled clients (issue #70 — host ↔ client_id map). A single-endpoint
  // collection resolves the host against this file instead of a brittle live `clients(search=...)`
  // lookup; refreshed at startup, on demand (Settings), and lazily on a collect miss.
  velociraptorClientStore?: VelociraptorClientStore;
  // Triage bundles (global, shared across cases): named selections of Velociraptor CLIENT artifacts
  // the analyst runs as a hunt. Per-case veloHuntStore tracks the in-flight/last bundle hunt so the
  // dashboard can show its status + countdown; onVeloHunt broadcasts a change to the case's clients.
  artifactBundleStore?: ArtifactBundleStore;
  veloHuntStore?: VeloHuntStore;
  onVeloHunt?: (caseId: string) => void;
  // Background-job registry (#225): tracks heavy async operations (import / synthesis / enrichment)
  // as cancellable Jobs for the dashboard Jobs panel + /api/jobs. Constructed in startServer (its
  // onJob hook WS-broadcasts job_changed); absent in createApp-only unit tests + scripts/* pipelines.
  jobManager?: JobManager;
  // Hunting feedback loop (#157): per-case ledger of deployed hunts + their outcomes (hit/miss +
  // counts). Recorded on deploy (bundle + suggested fleet/playbook/technique hunts), filled on collect,
  // read by the suggestion routes (exclude + "PRIOR HUNTS" context) and the dashboard hunting profile.
  huntOutcomeStore?: HuntOutcomeStore;
  // Live Velociraptor CLIENT_EVENT monitors (#84): per-case pollers that stream a client monitoring
  // artifact's new rows into the push/import pipeline. The store persists each monitor + its cursor so
  // a restart resumes without re-ingesting; onVeloMonitor broadcasts a change to the case's clients.
  veloMonitorStore?: VeloMonitorStore;
  onVeloMonitor?: (caseId: string) => void;
  // Poll interval (seconds) for live monitors when the request doesn't specify one (DFIR_VELO_MONITOR_POLL_S).
  veloMonitorPollSeconds?: number;
  // Generic push ingest (#84): the global shared secret (DFIR_PUSH_TOKEN) external tools present in
  // X-DFIR-Key, and the per-case token store (generated in Settings). Either authorizes a push.
  pushToken?: string;
  pushTokenStore?: PushTokenStore;
  onPushToken?: (caseId: string) => void;
  // IOC whitelist (global, shared across cases): known-good patterns (CIDR ranges, hashes, regexes)
  // that auto-mark matching IOCs LEGITIMATE on import. Opt-in (the store starts empty).
  iocWhitelistStore?: IocWhitelistStore;
  // User-authored declarative importers (global, shared across cases): the external plugin layer that
  // lets analysts add new import shapes without code. onImporters broadcasts a registry change.
  importerStore?: ImporterStore;
  onImporters?: () => void;
  // NSRL known-good hash set (global, shared across cases, #63): a forensic event whose file hash —
  // or an IOC whose value — is a known-software hash is auto-marked LEGITIMATE on import, reducing
  // false positives. Opt-in (the store starts empty).
  nsrlStore?: NsrlStore;
  // NSRL RDS SQLite backend (#63): the real ~160 GB RDS queried on demand (complements the flat
  // store). nsrlDbConfigFile persists a UI-set DB path; nsrlDbEnvManaged = DFIR_NSRL_DB is set, so
  // the path is env-managed and the UI connect is read-only.
  nsrlDb?: NsrlDb;
  nsrlDbConfigFile?: string;
  nsrlDbEnvManaged?: boolean;
  // CISA KEV catalog (issue #99): CVEs from the forensic timeline / Shodan exposure results that
  // CISA confirms are actively exploited are flagged in synthesis + the report. Opt-in (starts empty).
  kevStore?: KevStore;
  // Which hunt-query platforms the dashboard's 🔍 generator offers (DFIR_HUNT_PLATFORMS allowlist).
  // Exposed on /health so the dashboard renders only these cards. Undefined → all platforms.
  huntPlatforms?: HuntPlatform[];
  // Timesketch push: a configured client (when DFIR_TIMESKETCH_URL/USER/PASSWORD are set) +
  // options (base URL for the sketch link, managed timeline name).
  timesketchClient?: TimesketchClient;
  timesketchOptions?: TimesketchPushOptions;
  // Rebuild the Timesketch client at runtime so POST /timesketch/reconnect can apply newly-saved
  // DFIR_TIMESKETCH_* (or recover a server that came back online) WITHOUT the #1-gotcha restart.
  // Defaults to the env-based buildTimesketchClient; tests inject a stub (no network).
  rebuildTimesketchClient?: () => TimesketchClient | undefined;
  // Case templates: built-in + user-saved templates selectable at case creation.
  templateStore?: TemplateStore;
  // MISP export: a configured client (when DFIR_MISP_URL/KEY are set) + push options
  // (distribution, analysis state, base URL for the event link).
  mispPushClient?: MispPushClient;
  mispPushOptions?: MispPushOptions;
  // Notion export: a configured client (when DFIR_NOTION_TOKEN is set) + push options
  // (default parent database/page, container title). The export's page/container pointer is
  // remembered per case in notionExportStore so a re-export refreshes only Companion content.
  notionClient?: NotionClient;
  notionOptions?: NotionPushOptions;
  notionExportStore?: NotionExportStore;
  // ClickUp export (issue #36 Phase 3): a configured client (when DFIR_CLICKUP_TOKEN is set) pushes
  // the Response Playbook as ClickUp tasks. The per-task ClickUp ids are remembered per case in
  // clickupExportStore so a re-export updates instead of duplicating. Default target list id +
  // base URL come from clickupOptions.
  clickupClient?: ClickUpClient;
  clickupExportStore?: ClickUpExportStore;
  clickupOptions?: { defaultListId?: string };
  // Notifications (issue #58): a GLOBAL channel store (Slack/Teams webhooks + SMTP email) + a
  // notifier that dispatches NotificationEvents to the channels that want them. Opt-in — the store
  // starts empty. `notifier` is the dispatcher (loads channels, formats, sends, best-effort);
  // `notifyEmailEnabled` tells the dashboard whether an SMTP transport is wired (so it can hint).
  // `dashboardBaseUrl` deep-links notifications back to the case.
  notificationStore?: NotificationConfigStore;
  notifier?: Notifier;
  notifyEmailEnabled?: boolean;
  dashboardBaseUrl?: string;
  // Diagnostics (#118): builds an AI provider from the CURRENT config so the diagnostics
  // page's "Test AI connectivity" button can make a lightweight live request (validating
  // auth + timeout). Defaults to the env-based buildProvider in startServer; tests inject a
  // fake (no network). Absent / returns undefined → the test route reports "not configured".
  aiTestProvider?: () => AnalyzeProvider | undefined;
  // Opt-in "newer release available" notice (issue #127). All optional → a bare createApp (tests)
  // gets the feature OFF and never touches the network or a timer.
  updateCheckStore?: UpdateCheckStore;
  appVersion?: string;                 // resolved once in startServer via getAppVersion()
  updateRepo?: string;                 // default DEFAULT_UPDATE_REPO; override for forks
  updateCheckEnv?: string;             // raw DFIR_UPDATE_CHECK (passed, not read globally, for testability)
  updateFetch?: typeof fetch;          // injectable so tests never hit the network
  // Demo mode (DFIR_DEMO_MODE): blocks all mutating routes except POST /cases/seed-demo so a
  // public Railway/cloud deployment is safe to share. The startup seed + periodic reset live in
  // startServer; the middleware here enforces the read-only surface at the API layer.
  demoMode?: boolean;
  // Automatic state backup (#180): snapshots SNAPSHOT_STATE_FILES before synthesis + on a timer.
  // Opt-in — absent → backup routes 404.
  backupManager?: BackupManager;
  // Startup pre-flight (#179): called once inside createApp with the runPreflight function.
  // startServer stores the function and fires it after app.listen() so the probes run when
  // the server is actually ready. Tests can inject their own handler or leave it absent.
  onPreflightReady?: (run: () => Promise<PreflightReport>) => void;
}

export function createApp(store: CaseStore, options: AppOptions = {}): Express {
  const app = express();
  // Signs/verifies case-unlock cookies (issue: case password protection). Persisted next to
  // the cases root so "remember on this computer" survives a server restart.
  const instanceSecret = loadOrCreateInstanceSecret(store.casesRoot);
  const hasAiProvider = (): boolean => options.aiConfigured ?? Boolean(options.pipeline?.hasAiProvider());
  // Serialize the load->save critical section for a case's investigation.json so concurrent
  // mutations (a manual event/IOC add while background enrichment or re-synthesis saves)
  // cannot clobber each other (lost update). No-op when no StateLock is wired (tests).
  const runStateExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> =>
    options.stateLock ? options.stateLock.runExclusive(caseId, fn) : fn();

  // Automatic content-based tagger: after an import dual-writes its new events into the super-timeline,
  // tag just those events (Timesketch tagger analyzer, ported). Best-effort + non-fatal + gated on
  // TAGGER_AUTO — see analysis/taggerAuto.ts. Bound once here so every import site can fire it.
  const autoTagImported = (caseId: string, added: ForensicEvent[]): Promise<void> =>
    autoTagNewEvents(
      { taggerStore: options.taggerStore, tagsStore: options.tagsStore, stateStore: options.stateStore, onTags: options.onTags, onState: options.onState, logLine },
      caseId, added,
    );

  // ── Diagnostics runtime state (#118) ─────────────────────────────────────────────────
  // In-memory, best-effort rings powering the Health/Diagnostics page. They reset on restart
  // (like the capture-recency marker in routes/captures.ts) — durable history lives in the
  // per-case audit logs. Capped so a long-running server can't grow them unbounded.
  const appStartedAt = Date.now();
  const DIAG_RING = 50;
  const recentImportFailures: ImporterFailure[] = [];
  const recentAiErrors: AiError[] = [];
  function recordImportFailure(caseId: string, kind: string, filename: string, err: unknown): void {
    recentImportFailures.unshift({ at: new Date().toISOString(), caseId, kind, filename, error: (err as Error)?.message ?? String(err) });
    if (recentImportFailures.length > DIAG_RING) recentImportFailures.length = DIAG_RING;
  }
  function recordAiError(caseId: string, phase: string, err: unknown): void {
    const kind = err instanceof ProviderError ? err.kind : "other";
    recentAiErrors.unshift({ at: new Date().toISOString(), caseId, phase, kind, detail: (err as Error)?.message ?? String(err) });
    if (recentAiErrors.length > DIAG_RING) recentAiErrors.length = DIAG_RING;
  }
  // Per-importer health (#84): last run's outcome per custom (declarative) importer id. Keyed by
  // spec.id, one entry per importer — NOT a ring, since only the latest run matters for a health view.
  const importerRunStats = new Map<string, ImporterRunStat>();
  function recordImporterRun(id: string, patch: Omit<ImporterRunStat, "lastRunAt">): void {
    importerRunStats.set(id, { ...patch, lastRunAt: new Date().toISOString() });
  }

  // Deep link a notification back to the case dashboard (when a public base URL is configured).
  const caseLink = (caseId: string): string | undefined =>
    options.dashboardBaseUrl ? `${options.dashboardBaseUrl.replace(/\/+$/, "")}/dashboard?caseId=${encodeURIComponent(caseId)}` : undefined;

  // Fire a notification event to all matching channels. Best-effort, fire-and-forget: a transport
  // failure NEVER bubbles into the request that triggered it (notifications are a side channel).
  const dispatchNotify = (event: NotificationEvent): void => {
    if (!options.notifier) return;
    const enriched = event.url ? event : { ...event, url: caseLink(event.caseId) };
    options.notifier.dispatch(enriched).catch((err) => logLine(`[notify] dispatch error: ${(err as Error).message}`));
  };

  // Allow the browser extension (a chrome-extension:// origin) to reach this
  // localhost-only server. Binding is 127.0.0.1, so this is local-machine access.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    // Chromium Private Network Access: a request from an extension page to a
    // private address (127.0.0.1) is blocked unless the preflight allows it.
    res.header("Access-Control-Allow-Private-Network", "true");
    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  });

  // Demo mode guard: allow all GETs and the manual reset route; block everything else.
  // This makes the public Railway demo safe — visitors can browse the pre-seeded case but
  // cannot create new cases, import evidence, trigger AI calls, or change global settings.
  if (options.demoMode) {
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.method === "GET" || req.method === "OPTIONS") return next();
      if (req.path === "/cases/seed-demo") return next();
      return res.status(403).json({ error: "Demo mode: this action is disabled. The demo case resets every hour." });
    });
  }

  // Log each request and its final status (useful for a local single-user tool).
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.on("finish", () => {
      logLine(`[req] ${req.method} ${req.url} -> ${res.statusCode}`);
    });
    next();
  });

  // JSON body limit. Bulk evidence imports (CSV / log / THOR / SIEM-EDR JSON exports) wrap the
  // whole file in the request body, and SIEM/EDR exports in particular are routinely tens to
  // hundreds of MB — so the cap is generous and configurable via DFIR_MAX_BODY_MB (default
  // 256 MB). Localhost-only single-user tool, so a large limit is not a DoS concern. Files
  // beyond a few hundred MB approach V8's max string length; for those, split the export.
  const maxBodyMb = Number(process.env.DFIR_MAX_BODY_MB) || 256;
  app.use(express.json({ limit: `${maxBodyMb}mb` }));
  // Also accept text/plain + NDJSON bodies so the generic push endpoint (#84) can take a raw blob
  // (a Velociraptor monitor dump, an NDJSON alert stream) without forcing every caller to wrap it in
  // a JSON envelope. JSON bodies still parse via express.json above; this only catches non-JSON types.
  app.use(express.text({ limit: `${maxBodyMb}mb`, type: ["text/*", "application/x-ndjson", "application/jsonl"] }));

  // Turn body-parser failures into actionable JSON (instead of Express's default HTML page):
  // an over-limit upload → 413 with how to raise the cap; malformed JSON → 400. Placed right
  // after the parser so it catches its errors; normal requests skip it (4-arg = error-only).
  app.use((err: Error & { type?: string; status?: number }, _req: Request, res: Response, next: NextFunction) => {
    if (err?.type === "entity.too.large") {
      return res.status(413).json({ error: `upload exceeds the ${maxBodyMb} MB limit — raise DFIR_MAX_BODY_MB and restart the companion, or split the export into smaller files` });
    }
    if (err?.type === "entity.parse.failed") {
      return res.status(400).json({ error: "request body is not valid JSON" });
    }
    return next(err);
  });

  // ── Case password protection ─────────────────────────────────────────────────────────
  // Gates every /cases/:id/* route behind that case's password, when one is set. Mounted
  // here, before ANY /cases/:id/* route is registered, so it covers all of them via prefix
  // matching. See docs/superpowers/specs/2026-07-09-case-password-protection-design.md.
  app.use("/cases/:id", createCaseLockGate(store, instanceSecret));

  // Whether this request already carries a valid unlock for `id` (used by /lock-status), and
  // whether that unlock — if present — was signed with "remember on this computer". The
  // dashboard needs the latter to know whether it's safe to explicitly forget the unlock when
  // navigating away from a case it didn't itself just unlock in this page load (e.g. a case
  // that was already unlocked via a remembered cookie from an earlier session).
  function readUnlockState(req: Request, id: string, salt: string): { unlocked: boolean; remembered: boolean } {
    const cookies = parseCookieHeader(req.headers.cookie);
    const token = cookies[unlockCookieName(id)];
    if (!token) return { unlocked: false, remembered: false };
    const unlocked = verifyUnlockToken(token, id, salt, instanceSecret);
    return { unlocked, remembered: unlocked && isRememberedUnlockToken(token, id, salt, instanceSecret) };
  }

  const ctx: RouteContext = {
    store,
    options,
    serverLogger,
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
    // createApp (see context.ts for why each was graduated rather than moved). instanceSecret +
    // runStateExclusive are bound at construction (defined above); ensureDropFolders/reloadImporters are
    // hoisted async functions; importerPrecedence is a live accessor over the `let` below; buildTimesketchClient
    // is a module-level function (kept in server.ts so no route imports a value from ../server.js).
    instanceSecret,
    runStateExclusive,
    ensureDropFolders,
    reloadImporters,
    importerPrecedence: () => importerPrecedence,
    setImporterPrecedence: (precedence) => { importerPrecedence = precedence; },
    rebuildTimesketchClient: () => (options.rebuildTimesketchClient ?? buildTimesketchClient)(),
    getControl,
    setControl,
    backfill,
    flush,
    indexCaptureText,
    ingestStreamed,
    runToolAndIngest,
    reloadCustomTools,
    resolveImportKind: () => resolveImportKind,
    captureBuffers: () => buffers,
    synthInFlight: () => synthInFlight,
    importerRegistry: () => importerRegistry,
    irisClient: () => irisClient,
    setIrisClient: (client) => { irisClient = client; },
    rebuildIrisClient: () => (options.rebuildIrisClient ?? buildIrisClient)(),
    dispatchNotify,
    dropWatchEnabled: () => dropWatchEnabled,
    enrichmentProviders: () => allProviders,
    enrichHealth: () => enrichHealth,
    liveToolConfigs: () => liveToolConfigs,
    customTools: () => customTools,
    dispatchImport,
    demoteForensicForCase,
    resynthesizeInBackground,
    pushImportCheckpoint,
    applyWhitelistToCase,
    applyNsrlToCase,
    applyDeobfuscationToCase,
    moveDropFile,
    // Threat-intel enrichment engine (routes/threatIntel.ts). enrichInBackground/autoEnrichIfEnabled/
    // enabledProvidersFor are hoisted functions defined later in createApp; enrichPending/nsrlDb are
    // live accessors (their bindings are created after this literal). The engine + reachability poller
    // stay here; the moved routes reach them through these members.
    enrichInBackground,
    autoEnrichIfEnabled,
    enabledProvidersFor,
    enrichPending: () => enrichPending,
    nsrlDb: () => nsrlDb,
    setNsrlDb: (db) => { nsrlDb = db; },
    // Velociraptor machinery (routes/velociraptor.ts). All hoisted `function` declarations defined later
    // in createApp, so binding them here (before their textual definition) is safe.
    refreshVeloClients,
    resumeVeloMonitors,
    resumeVeloHuntStatusPolls,
    scheduleVeloMonitor,
    pollVeloMonitor,
    stopVeloMonitorTimer,
    scheduleVeloHuntStatusPoll,
    pollVeloHuntStatus,
    importVeloHuntResults,
    ingestVeloArtifactMap,
    ingestVeloUploads,
    createVeloMonitor,
    recordHuntDeploy,
    // Playbook derivation helpers (routes/playbookHunts.ts); hoisted functions defined later, shared
    // with the staying POST /cases/:id/push/iris route (syncPlaybook), so bound here as stable methods.
    syncPlaybook,
    loadPlaybookControl,
    dropSeen: () => dropSeen,
    dropScanning: () => dropScanning,
    dropPendingLogged: () => dropPendingLogged,
    veloHuntTimers: () => veloHuntTimers,
  };
  registerSystemRoutes(app, ctx);
  registerCaptureRoutes(app, ctx);
  registerPushNotifyRoutes(app, ctx);
  registerTemplatesViewsRoutes(app, ctx);
  registerToolsRoutes(app, ctx);
  registerImportRoutes(app, ctx);
  registerVelociraptorRoutes(app, ctx);
  registerThreatIntelRoutes(app, ctx);
  registerAnonymizationRoutes(app, ctx);
  registerTimelineRoutes(app, ctx);
  registerAnalysisGraphRoutes(app, ctx);
  registerFindingsRoutes(app, ctx);
  registerTaggerRoutes(app, ctx);
  registerPlaybookHuntsRoutes(app, ctx);
  registerAiSynthesisRoutes(app, ctx);
  registerReportsExportRoutes(app, ctx);
  // Case-password routes first (mirrors their original registration order, right after the case-lock gate),
  // then the case-core catch-all (lifecycle, archives, integration pushes, importers, jobs, settings, static
  // app shell). Both register before the terminal error handler at the end of createApp.
  registerCasePasswordRoutes(app, ctx);
  registerCaseLifecycleRoutes(app, ctx);

  const windowSize = options.windowSize ?? 4;
  const buffers = new Map<string, CaptureMetadata[]>();

  // Screenshot OCR full-text search index (#176). Runs in the BACKGROUND after a capture is
  // persisted — never on the /captures hot path (Tesseract is ~0.5–2s/image and evidence-first
  // means the screenshot is already on disk). Best-effort: a failure is logged, never thrown.
  // A burst of captures (e.g. a batch import) is QUEUED and drained at most OCR_MAX_CONCURRENT
  // at a time, so every non-duplicate screenshot is indexed — not dropped — without spawning N
  // Tesseract workers at once. The queue is bounded purely as a runaway safety net; in practice
  // captures are paced far slower than OCR drains.
  const ocrQueue: CaptureMetadata[] = [];
  let ocrActive = 0;
  const OCR_MAX_CONCURRENT = 2;
  const OCR_MAX_QUEUE = 1000;
  function pumpOcrQueue(): void {
    while (ocrActive < OCR_MAX_CONCURRENT && ocrQueue.length > 0) {
      const metadata = ocrQueue.shift()!;
      ocrActive++;
      void (async () => {
        try {
          const path = join(store.screenshotsDir(metadata.caseId), metadata.screenshotFile);
          const bytes = await readFile(path);
          const runner = options.ocrRunner ?? new TesseractOcrRunner();
          const words = await runner.recognize(bytes);
          const text = extractOcrText(words);
          await store.putOcrEntry(metadata.caseId, {
            screenshotFile: metadata.screenshotFile,
            text,
            ocrAt: new Date().toISOString(),
            wordCount: text.length === 0 ? 0 : text.split(" ").length,
          });
        } catch (err) {
          serverLogger.debug(`OCR index failed for ${metadata.screenshotFile}: ${(err as Error).message}`, { caseId: metadata.caseId });
        } finally {
          ocrActive--;
          pumpOcrQueue();
        }
      })();
    }
  }
  function indexCaptureText(metadata: CaptureMetadata): void {
    if (!isOcrSearchEnabled() || !metadata.screenshotFile || metadata.isDuplicate) return;
    if (ocrQueue.length >= OCR_MAX_QUEUE) {
      // Runaway safety net only — recover anything dropped here with `npm run ocr-index`.
      serverLogger.debug(`OCR index: queue full, skipped seq=${metadata.sequenceNumber}`, { caseId: metadata.caseId });
      return;
    }
    ocrQueue.push(metadata);
    pumpOcrQueue();
  }

  // Per-case AI on/off + last-analyzed sequence (cached, persisted to disk).
  const aiControl = new AiControlStore(store);
  const controlCache = new Map<string, AiControl>();
  async function getControl(caseId: string): Promise<AiControl> {
    let c = controlCache.get(caseId);
    if (!c) { c = await aiControl.load(caseId); controlCache.set(caseId, c); }
    return c;
  }
  async function setControl(caseId: string, patch: Partial<AiControl>): Promise<AiControl> {
    const next = { ...(await getControl(caseId)), ...patch };
    controlCache.set(caseId, next);
    await aiControl.save(caseId, next);
    return next;
  }

  // Debounced live synthesis: after capture windows are analyzed, re-derive the
  // findings / MITRE / attacker path so the dashboard updates as you browse.
  const autoSynth = options.autoSynthesize ?? false;
  const synthDebounceMs = options.autoSynthesizeDebounceMs ?? 8000;
  const synthTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const synthInFlight = new Set<string>();

  function scheduleSynthesis(caseId: string): void {
    // synthesize() is TEXT work — it runs on the synthesis provider (falling back to the vision
    // provider), so gate on that, not hasAiProvider(): an OCR-less install (only
    // DFIR_AI_SYNTH_PROVIDER set) must still auto-synthesize after imports.
    if (!autoSynth || !options.pipeline || !options.pipeline.hasSynthesisProvider()) return;
    const existing = synthTimers.get(caseId);
    if (existing) clearTimeout(existing);
    synthTimers.set(caseId, setTimeout(() => {
      synthTimers.delete(caseId);
      if (synthInFlight.has(caseId)) { scheduleSynthesis(caseId); return; } // busy — retry after debounce
      synthInFlight.add(caseId);
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "synthesizing conclusions" });
      // #225: this debounced/auto path (live re-synth after captures, and the AI off→on backfill
      // catch-up) previously ran outside the job registry, so it never showed up in the Jobs panel
      // or offered a Cancel button — only the manual "re-synthesize" button did. Track it the same way.
      // exclusive: a manual re-synthesize racing this live run (synthInFlight only serializes
      // auto-vs-auto) supersedes rather than running alongside it.
      const job = options.jobManager?.register({ caseId, kind: "synthesis", label: "live synthesis", cancellable: true, exclusive: true });
      options.pipeline!.synthesize(caseId, job?.signal ? { signal: job.signal } : {})
        .then(() => { if (job) options.jobManager?.finish(job.jobId); options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); autoEnrichIfEnabled(caseId); })
        .catch((err) => {
          const aborted = job?.signal?.aborted === true;
          if (job) options.jobManager?.fail(job.jobId, err); // no-op if already cancelled
          recordAiError(caseId, "synthesizing", err);
          // A newer exclusive registration may have superseded this run — if a synthesis job for
          // this case is still active, that newer run owns the status; don't stomp it to idle.
          if (!(aborted && options.jobManager?.hasActive(caseId, "synthesis"))) {
            options.onAiStatus?.(caseId, aborted
              ? { status: "idle", at: new Date().toISOString(), detail: "synthesis cancelled" }
              : { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
          }
        })
        .finally(() => synthInFlight.delete(caseId));
    }, synthDebounceMs));
  }

  async function flush(caseId: string): Promise<void> {
    const buf = buffers.get(caseId) ?? [];
    if (buf.length === 0 || !options.pipeline || !hasAiProvider()) return;
    buffers.set(caseId, []);
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: new Date().toISOString(),
      detail: `${buf.length} screenshot(s)`,
    });
    try {
      await options.pipeline.analyzeWindow(caseId, buf);
      // Analysis recovered — drop any stale failure marker from a prior window.
      await rm(join(store.stateDir(caseId), "pending_analysis.json"), { force: true });
      const maxSeq = Math.max(...buf.map((c) => c.sequenceNumber));
      const cur = await getControl(caseId);
      if (maxSeq > cur.lastAnalyzedSeq) await setControl(caseId, { lastAnalyzedSeq: maxSeq });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      scheduleSynthesis(caseId); // live findings/attacker path
    } catch (err) {
      recordAiError(caseId, "extracting", err);
      const seqs = buf.map((c) => c.sequenceNumber);
      await writeFile(
        join(store.stateDir(caseId), "pending_analysis.json"),
        JSON.stringify({ pending: seqs, error: (err as Error).message }, null, 2),
        "utf8",
      );
      options.onAiStatus?.(caseId, {
        status: "error",
        at: new Date().toISOString(),
        detail: (err as Error).message,
      });
    }
  }

  // Safety-net periodic flush. A `timer`/`click` capture buffers until `windowSize` accumulates
  // (only a `navigation`/`tab_switch` flushes early), so a single (or sub-window) capture could
  // otherwise sit unanalyzed indefinitely. Every `flushIntervalMs` (default 5 min) drain any
  // non-empty buffer so even one screenshot gets analyzed. `flush` is a no-op on an empty buffer
  // or when AI is unconfigured, and per-case buffers only hold captures for AI-enabled cases
  // (the route gates on `enabled`; pausing clears the buffer). `unref()` so the timer never keeps
  // the process — or a test runner — alive.
  const flushIntervalMs = options.flushIntervalMs ?? 5 * 60_000;
  if (flushIntervalMs > 0 && options.pipeline) {
    const sweep = setInterval(() => {
      for (const [caseId, buf] of buffers) {
        if (buf.length > 0) void flush(caseId);
      }
    }, flushIntervalMs);
    sweep.unref?.();
  }

  // Analyze every non-duplicate capture taken since lastAnalyzedSeq — used when AI
  // is switched back on after capturing with it off. Runs in the background.
  async function backfill(caseId: string): Promise<void> {
    // Fired on an AI off→on transition. The dashboard optimistically shows
    // "AI on — catching up on un-analyzed screenshots…" the instant you toggle — that text is
    // NOT a live progress indicator, so EVERY exit path here must emit a terminal status, or it
    // hangs forever (a real bug report: "this message is stuck, I don't know if it finished").
    const idle = (detail?: string) =>
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), ...(detail ? { detail } : {}) });
    // No screenshots to analyze, but evidence IMPORTED while AI was off (deterministic Velociraptor/
    // CSV/… imports populate the timeline without an AI call) still needs synthesis. Trigger it —
    // skip-if-unchanged makes it a no-op when nothing actually changed — so turning AI on analyzes
    // the imported data, not just screenshots. If synthesis can't run, clear the optimistic message.
    const catchUpSynthesis = () => {
      if (autoSynth && options.pipeline && hasAiProvider()) {
        options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "synthesizing imported evidence" });
        scheduleSynthesis(caseId);
      } else {
        idle();
      }
    };
    if (!options.pipeline || !hasAiProvider()) {
      idle("AI on — no AI model configured"); // can't analyze, but clear the optimistic message
      return;
    }
    let control = await getControl(caseId);
    let captures: CaptureMetadata[];
    try {
      const log = await readFile(store.capturesLogPath(caseId), "utf8");
      captures = log.split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l) as CaptureMetadata);
    } catch {
      catchUpSynthesis(); // no capture log (import-only case) → still synthesize imported evidence
      return;
    }
    const pending = captures.filter((c) => !c.isDuplicate && c.sequenceNumber > control.lastAnalyzedSeq);
    if (pending.length === 0) {
      catchUpSynthesis(); // no new screenshots → still synthesize anything imported while off
      return;
    }
    options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `catching up on ${pending.length} screenshot(s)` });
    try {
      for (let i = 0; i < pending.length; i += windowSize) {
        const win = pending.slice(i, i + windowSize);
        await options.pipeline.analyzeWindow(caseId, win);
        control = await setControl(caseId, { lastAnalyzedSeq: Math.max(...win.map((c) => c.sequenceNumber)) });
      }
      await rm(join(store.stateDir(caseId), "pending_analysis.json"), { force: true });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      scheduleSynthesis(caseId);
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
    }
  }

  // The active DFIR-IRIS client. Mutable: POST /iris/reconnect (routes/reportsExport.ts) can rebuild
  // it at runtime — via ctx.setIrisClient() — without a server restart (config saved via Settings, or
  // IRIS coming back online). Starts from options; createApp's /cases/:id/push/iris reads it, and
  // ctx.irisClient() exposes it live to the moved iris routes.
  let irisClient = options.irisClient;

  // Snapshot the enrolled fleet into the persisted client inventory (issue #70). Best-effort; returns
  // the count. No-op (count 0) when the API or store isn't configured.
  async function refreshVeloClients(): Promise<number> {
    const client = options.velociraptorClient;
    const store = options.velociraptorClientStore;
    if (!client || !store) return 0;
    const clients = await client.listClients();
    await store.save(clients, new Date().toISOString());
    logLine(`[velociraptor] client inventory refreshed — ${clients.length} enrolled client(s)`);
    return clients.length;
  }

  // In-memory auto-collect timers, keyed by HUNT id (globally unique) so concurrent hunts each get
  // their own. Lost on a server restart BY DESIGN — the jobs are persisted (veloHuntStore), so after a
  // restart the dashboard still shows them and the analyst triggers "Collect now". .unref() so a
  // pending timer never blocks exit.
  const veloHuntTimers = new Map<string, NodeJS.Timeout>();
  const collectingNow = new Set<string>();   // in-memory guard closing the TOCTOU race between the fixed-delay
                                              // timer and the status poller both deciding to collect the same
                                              // hunt around the same moment (VeloHuntStore has no lock/CAS) —
                                              // checked+set synchronously before any await.

  // User-authored declarative importers (external plugin layer). Loaded async at startup; empty
  // until the load resolves (parity with the velociraptor inventory / iris reconnect self-heals).
  let importerRegistry: ImporterRegistry = { importers: new Map(), meta: [], errors: [] };
  let importerPrecedence: ImporterPrecedence = "builtin-first";
  if (options.importerStore) {
    options.importerStore.loadAll().then((r) => { importerRegistry = r; }).catch(() => { /* keep empty */ });
    options.importerStore.precedence().then((p) => { importerPrecedence = p; }).catch(() => { /* default */ });
  }
  async function reloadImporters(): Promise<void> {
    if (!options.importerStore) return;
    importerRegistry = await options.importerStore.loadAll();
    importerPrecedence = await options.importerStore.precedence();
    options.onImporters?.();
  }
  const resolveImportKind = (filename: string, text: string): string =>
    detectImportWithCustom(filename, text, importerRegistry.importers, importerPrecedence);

  // Dispatch a detected import kind to the matching pipeline importer. Shared by the unified /import
  // route and the Velociraptor bundle collector (which ingests uploaded JSON reports the same way).
  function dispatchImport(kind: string, caseId: string, text: string, base: ImportBase): Promise<unknown> {
    const pipeline = options.pipeline;
    if (!pipeline) return Promise.reject(new Error("AI pipeline not configured"));
    // A user-authored declarative importer takes the matching kind first (its id is the kind).
    const custom = importerRegistry.importers.get(kind);
    if (custom) {
      let parsed: { total: number; kept: number; dropped: number } | null = null;
      return pipeline.importDeclarative(caseId, text, {
        importer: custom, ...base,
        onParsed: (r) => {
          parsed = { total: r.total, kept: r.kept, dropped: r.dropped };
          recordImporterRun(kind, { lastStatus: "ok", ...parsed, lastError: null });
        },
      }).catch((err) => {
        recordImporterRun(kind, { lastStatus: "error", total: parsed?.total ?? 0, kept: parsed?.kept ?? 0, dropped: parsed?.dropped ?? 0, lastError: (err as Error)?.message ?? String(err) });
        throw err;
      });
    }
    switch (kind) {
      case "thor": return pipeline.importThor(caseId, text, base);
      case "siem": return pipeline.importSiem(caseId, text, base);
      case "evtxxml": return pipeline.importEvtxXml(caseId, text, base);
      case "chainsaw": return pipeline.importChainsaw(caseId, text, base);
      case "hayabusa": return pipeline.importHayabusa(caseId, text, base);
      case "velociraptor": return pipeline.importVelociraptor(caseId, text, base);
      case "securityonion": return pipeline.importSecurityOnion(caseId, text, base);
      case "socrates": return pipeline.importSocrates(caseId, text, base);
      case "network": return pipeline.importNetwork(caseId, text, base);
      case "kape": return pipeline.importKape(caseId, text, base);
      case "cybertriage": return pipeline.importCybertriage(caseId, text, base);
      case "m365": return pipeline.importM365(caseId, text, base);
      case "aws": return pipeline.importAws(caseId, text, base);
      case "cloud": return pipeline.importCloudActivity(caseId, text, base);
      case "k8s": return pipeline.importK8sAudit(caseId, text, base);
      case "osquery": return pipeline.importOsquery(caseId, text, base);
      case "plaso": return pipeline.importPlaso(caseId, text, base);
      case "sandbox": return pipeline.importSandbox(caseId, text, base);
      case "memory": return pipeline.importMemory(caseId, text, base);
      case "email": return pipeline.importEmail(caseId, text, base);
      case "thehive": return pipeline.importTheHive(caseId, text, base);
      case "auditd": return pipeline.importAuditd(caseId, text, base);
      case "journald": return pipeline.importJournald(caseId, text, base);
      case "sysdig": return pipeline.importSysdig(caseId, text, base);
      case "wazuh": return pipeline.importWazuh(caseId, text, base);
      case "bashhistory": return pipeline.importBashHistory(caseId, text, base);
      case "ecar": return pipeline.importEcar(caseId, text, base);
      case "snort": return pipeline.importSnort(caseId, text, base);
      case "yara": return pipeline.importYara(caseId, text, base);
      case "combinedlog": return pipeline.importCombinedLog(caseId, text, base);
      case "asa": return pipeline.importCiscoAsa(caseId, text, base);
      case "syslog": return pipeline.importSyslog(caseId, text, base);
      case "csv": return pipeline.analyzeCsv(caseId, text, base);
      case "log": return pipeline.analyzeLog(caseId, text, base);
      default: return Promise.reject(new Error(`unhandled import kind: ${kind as string}`));
    }
  }

  // Evidence-first persist of an imported blob: next sequence, save the raw file, append the audit line.
  async function persistEvidence(caseId: string, originalName: string, text: string): Promise<{ storedName: string; importedAt: string; seq: number }> {
    const seq = await store.nextImportSeq(caseId);
    const safe = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat";
    const storedName = `${String(seq).padStart(4, "0")}_${safe}`;
    const importedAt = new Date().toISOString();
    await store.saveImport(caseId, storedName, text);
    await store.appendImport(caseId, {
      caseId, sequenceNumber: seq, importedAt, filename: storedName,
      originalName, rows: 0, bytes: Buffer.byteLength(text, "utf8"),
    });
    return { storedName, importedAt, seq };
  }

  // Route sub-threshold (Info by default) telemetry to the super-timeline only. The super-timeline
  // already captured these events (dual-write above at each import seam); here we drop them from the
  // forensic timeline so the AI only synthesizes graded signal. Promotion re-adds them if the analyst
  // wants (it goes through pipeline.promoteSuperTimeline, NOT this gate). Threshold: per-case
  // forensic-gate ?? DFIR_FORENSIC_MIN_SEVERITY ?? "Low". Returns the (possibly unchanged) state.
  async function demoteForensicForCase(caseId: string): Promise<InvestigationState> {
    return runStateExclusive(caseId, async () => {
      const state = await options.stateStore!.load(caseId);
      if (!options.forensicGateControlStore) return state;
      const min = resolveForensicMinSeverity(
        (await options.forensicGateControlStore.load(caseId)).minSeverity,
        process.env.DFIR_FORENSIC_MIN_SEVERITY,
      );
      const { kept, demoted } = demoteBelowSeverity(state.forensicTimeline, min);
      if (!demoted.length) return state;
      const next = { ...state, forensicTimeline: kept };
      await options.stateStore!.save(next);
      options.onState?.(next);
      return next;
    });
  }

  // Shared streamed-ingest path for the generic push endpoint (#84) and the Velociraptor client-event
  // poller: persist the blob as evidence, run the detected importer, record the import-meta diff (when
  // it added anything), auto-legitimate via whitelist/NSRL, then re-synthesize. It mirrors the /import
  // route's chain but is tuned for HIGH-FREQUENCY streaming: it AWAITS the deterministic import (so the
  // caller can report +N events), backgrounds only the AI synthesis, records import-meta only on a
  // non-empty diff (a quiet poll must not reset the dashboard's NEW highlights), and skips the undo
  // checkpoint (per-poll snapshots would flood the undo stack). Resolves with the diff counts; the push
  // route fires-and-forgets, the poller awaits to update the monitor's running stats.
  async function ingestStreamed(
    caseId: string, kind: string, text: string, originalName: string, minSeverity?: Severity,
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    options.onImport?.(caseId); // cross-case signal (parity with /import + captures) for push/monitor ingest
    const { storedName, importedAt, seq } = await persistEvidence(caseId, originalName, text);

    // CSV/log are themselves an LLM call → respect the per-case AI toggle exactly like /import: with
    // AI OFF the evidence is saved but not sent to the model. Deterministic importers proceed.
    const aiDependent = kind === "csv" || kind === "log";
    if (aiDependent && !(await getControl(caseId)).enabled) {
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `AI is off — ${kind.toUpperCase()} saved as evidence but not analyzed (turn AI on, then re-import)` });
      return { storedName, addedEvents: 0, addedIocs: 0, analyzed: false };
    }

    const onProgress = (done: number, total: number): void => options.onAiStatus?.(caseId, {
      status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `${kind} import — ${done}/${total}`,
    });
    options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing (${kind})${minSeverity ? ` — min severity ${minSeverity}` : ""}` });

    let stateBefore: InvestigationState | null = null;
    if (options.stateStore) { try { stateBefore = await options.stateStore.load(caseId); } catch { /* keep null */ } }

    await dispatchImport(kind, caseId, text, { label: storedName, idPrefix: `${seq}`, importedAt, onProgress, minSeverity });
    options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });

    let addedEvents = 0, addedIocs = 0;
    if (options.stateStore && stateBefore) {
      try {
        const imported = await options.stateStore.load(caseId);
        // Dual-write the newly-imported events into the super-timeline FIRST so it stays a superset of
        // everything imported (Info telemetry included). The diff is lossy, so resolve the FULL events
        // from the imported (pre-demote) state. Best-effort — a side record.
        if (options.superTimelineStore) {
          const superDiff = diffTimeline(stateBefore.forensicTimeline, imported.forensicTimeline);
          const added = addedForensicEvents(imported.forensicTimeline, superDiff);
          if (added.length) { try { await options.superTimelineStore.append(caseId, added); options.onSuperTimeline?.(caseId); } catch { /* non-fatal */ } await autoTagImported(caseId, added); }
        }
        // Now demote sub-threshold events out of the forensic timeline (they live on in the super-
        // timeline). Compute the import-meta diff on the POST-demote state so "+N events" counts only
        // what actually entered forensic.
        const s = await demoteForensicForCase(caseId);
        const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
        const iDiff = diffIocs(stateBefore.iocs, s.iocs);
        addedEvents = tDiff.added.length; addedIocs = iDiff.added.length;
        if ((addedEvents || addedIocs || tDiff.removed.length || iDiff.removed.length) && options.importMetaStore) {
          await options.importMetaStore.record(caseId, { kind, file: storedName, diff: tDiff, iocsDiff: iDiff });
          options.onImportMeta?.(caseId);
        }
      } catch { /* non-fatal */ }
    }
    // Auto-mark known-good IOCs/hashes legitimate (whitelist + NSRL) BEFORE re-synthesis, like /import.
    try { const wl = await applyWhitelistToCase(caseId); if (wl.added > 0) logLine(`[whitelist] ${caseId} auto-marked ${wl.added} pushed IOC(s) legitimate`); } catch { /* non-fatal */ }
    try { const ns = await applyNsrlToCase(caseId); if (ns.added > 0) logLine(`[nsrl] ${caseId} auto-marked ${ns.added} pushed known-good item(s) legitimate`); } catch { /* non-fatal */ }
    try { const deob = await applyDeobfuscationToCase(caseId); if (deob.deobfuscated > 0) logLine(`[deobfuscate] ${caseId} decoded ${deob.deobfuscated} pushed event(s), +${deob.newIocs} new IOC(s)`); } catch { /* non-fatal */ }
    resynthesizeInBackground(caseId);
    return { storedName, addedEvents, addedIocs, analyzed: true };
  }

  // ── Evidence drop folder (auto-import inbox) ──────────────────────────────────────────────────
  // A per-case `cases/<id>/drop/` folder: anything copied in (at any depth) is auto-imported via the
  // SAME chain as the Import button. ONE global self-rescheduling poller (mirrors resumeVeloMonitors)
  // — chosen over fs.watch because cases/ often lives in a Dropbox/OneDrive-synced folder where watch
  // events are unreliable (the same reason atomicWrite retries sync locks). Files settle for one poll
  // (size+mtime stable) before import, so a half-copied file isn't read. On success the file moves to
  // drop/_processed/ (which is also the dedup — the watcher skips that subtree); on failure to
  // drop/_failed/. The watcher is ARMED only when options.dropStatusStore is wired (startServer), so
  // createApp-only unit tests never spin up a filesystem poller.
  const dropWatchEnabled = (process.env.DFIR_DROP_ENABLED ?? "on").trim().toLowerCase() !== "off";
  const dropPollMs = Math.min(600, Math.max(2, Number(process.env.DFIR_DROP_POLL_S) || 10)) * 1000;
  const dropMaxBytes = Number(process.env.DFIR_DROP_MAX_BYTES) || 200 * 1024 * 1024;
  const DROP_CONCURRENCY = 4;
  const dropSeen = new Map<string, Map<string, { size: number; mtimeMs: number }>>();
  const dropScanning = new Set<string>();
  // Files logged as PENDING (relpath per case) so a still-waiting raw-tool file doesn't get a new
  // PENDING line every poll — only once when first seen pending, cleared once it resolves.
  const dropPendingLogged = new Map<string, Set<string>>();
  const DROP_README_TEXT = [
    "DFIR Companion — evidence drop folder",
    "",
    "Copy artifacts into this folder (subfolders are fine — they're scanned recursively).",
    "Each file is auto-detected and imported into this case, exactly like the dashboard Import button.",
    "Images (.png/.jpg/...) are ingested as screenshot evidence.",
    "",
    "After processing, files move to _processed/ (success) or _failed/ (error).",
    "Failures are reported in the dashboard (📥 Drop banner) and any configured notification channel.",
    "A running history of every file processed (imported/failed/pending, with reasons) is kept in",
    "drop-log.txt in this same folder.",
    "",
    "This README, drop-log.txt, and the _processed/ and _failed/ subfolders are ignored by the scanner.",
    "",
  ].join("\n");

  // User-defined custom tools (#211) held in memory + refreshed on CRUD (mirrors importerRegistry), so
  // liveToolConfigs stays synchronous.
  let customTools: CustomTool[] = [];
  if (options.customToolStore) options.customToolStore.load().then((t) => { customTools = t; }).catch(() => { /* keep empty */ });
  async function reloadCustomTools(): Promise<void> {
    if (options.customToolStore) customTools = await options.customToolStore.load();
  }

  // External-tools (#211) config is read LIVE from env so POST /tools/reconnect applies without a
  // restart; tests inject a fixed map. The built-in tools come from env; custom tools are merged in from
  // the in-memory store. Keyed by string id (built-in ToolId or a custom id). The runner is stateless.
  const liveToolConfigs = (): Map<string, ToolConfig> => {
    const out = new Map<string, ToolConfig>((options.loadToolConfigs ?? (() => loadAllToolConfigs(process.env)))());
    for (const t of customTools) out.set(t.id, customToolToConfig(t));
    return out;
  };
  // Resolve which CONFIGURED tool handles a file extension: built-in preference first (via TOOL_DEFS),
  // then a custom tool that claims the extension.
  const resolveToolForExt = (ext: string, configured: Map<string, ToolConfig>): string | null => {
    const builtin = toolForExtension(ext, configured);
    if (builtin) return builtin;
    const e = ext.toLowerCase();
    const custom = customTools.find((t) => configured.has(t.id) && t.extensions.some((x) => x.toLowerCase() === e));
    return custom ? custom.id : null;
  };
  // Every file extension claimed by a built-in raw type OR a defined custom tool (for drop routing).
  const rawExtClaimed = (ext: string): boolean =>
    RAW_TOOL_EXTS.has(ext.toLowerCase()) || customTools.some((t) => t.extensions.some((x) => x.toLowerCase() === ext.toLowerCase()));

  // Run a configured external tool against a raw on-disk file (contained in the case dir) and ingest its
  // output through the SAME chain as the Import button (ingestStreamed). Shared by the drop-folder
  // auto-run and the manual POST /cases/:id/tools/:toolId/run route. A custom tool's output kind is
  // "auto" → detected from the output. Throws when not configured / the run fails; the output work dir
  // is server-owned + auto-cleaned inside runToolAgainstFile.
  async function runToolAndIngest(
    caseId: string, toolId: string, targetPath: string, opts: { undoLabel?: string } = {},
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }> {
    if (!options.toolRunner) throw new Error("external tools not configured");
    const cfg = liveToolConfigs().get(toolId);
    if (!cfg) throw new Error(`tool "${toolId}" is not configured`);
    const caseDir = store.caseDir(caseId);
    const contained = resolveContainedPath(caseDir, targetPath);
    const { outputText, importKind } = await runToolAgainstFile({
      cfg, runner: options.toolRunner, targetPath: contained, workDir: join(caseDir, ".toolwork"),
    });
    const outName = `${basename(contained)}.${toolId}.out`;
    // Custom tools declare no fixed importer — detect the kind from the tool's output.
    const kind = importKind === "auto" ? resolveImportKind(outName, outputText) : importKind;
    if (kind === "unknown") throw new Error(`${toolId}: could not detect the tool output's format (not a recognized import)`);
    // ingestStreamed skips the undo checkpoint (built for high-frequency streaming), so a MANUAL tool
    // run (Import dialog / Run button) wouldn't be undoable. When a label is given, snapshot the
    // pre-import state and push an undo checkpoint if the import changed anything — parity with /import.
    let before: InvestigationState | null = null;
    if (opts.undoLabel && options.stateStore) { try { before = await options.stateStore.load(caseId); } catch { /* keep null */ } }
    const r = await ingestStreamed(caseId, kind, outputText, outName);
    if (before && opts.undoLabel && (r.addedEvents > 0 || r.addedIocs > 0)) {
      await pushImportCheckpoint(caseId, before, opts.undoLabel);
    }
    return r;
  }

  function dropDirOf(caseId: string): string { return join(store.caseDir(caseId), "drop"); }

  async function ensureDropFolders(caseId: string): Promise<void> {
    const dropDir = dropDirOf(caseId);
    await mkdir(join(dropDir, DROP_PROCESSED), { recursive: true });
    await mkdir(join(dropDir, DROP_FAILED), { recursive: true });
    const readme = join(dropDir, DROP_README);
    try { await stat(readme); } catch { await writeFile(readme, DROP_README_TEXT, "utf8").catch(() => { /* best-effort */ }); }
  }

  // Recursive walk of drop/, skipping the reserved subtrees + README + OS/sync junk (shouldIgnoreDropFile).
  async function listDropFiles(dropDir: string): Promise<DropFileStat[]> {
    const out: DropFileStat[] = [];
    const walk = async (dir: string): Promise<void> => {
      let entries;
      try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const full = join(dir, e.name);
        const rel = relative(dropDir, full);
        if (shouldIgnoreDropFile(rel)) continue;
        if (e.isDirectory()) { await walk(full); continue; }
        if (!e.isFile()) continue;
        try { const st = await stat(full); out.push({ relpath: rel, size: st.size, mtimeMs: st.mtimeMs }); } catch { /* vanished mid-walk */ }
      }
    };
    await walk(dropDir);
    return out;
  }

  // Find a non-colliding destination (a re-dropped same-name file shouldn't clobber an earlier one).
  async function uniqueDest(path: string): Promise<string> {
    let candidate = path;
    const ext = extname(path);
    const stem = path.slice(0, path.length - ext.length);
    for (let n = 1; n < 1000; n++) {
      try { await stat(candidate); } catch { return candidate; } // ENOENT → free
      candidate = `${stem}_${n}${ext}`;
    }
    return candidate;
  }

  async function moveDropFile(dropDir: string, relpath: string, ok: boolean): Promise<void> {
    const src = join(dropDir, relpath);
    const dest = await uniqueDest(join(dropDir, ok ? DROP_PROCESSED : DROP_FAILED, relpath));
    await mkdir(dirname(dest), { recursive: true });
    try {
      await rename(src, dest);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EXDEV") { await copyFile(src, dest); await rm(src, { force: true }); }
      else throw e;
    }
  }

  // Ingest one dropped image as screenshot evidence: transcode to webp (imageLoader sends screenshots
  // as image/webp, so a dropped png/jpg must be honest on disk + wire), then run the SAME capture +
  // vision trigger as POST /captures. triggerType "navigation" forces a prompt flush.
  async function ingestDroppedImage(caseId: string, fullPath: string, name: string, mtimeMs: number): Promise<void> {
    const raw = await readFile(fullPath);
    let webp: Buffer;
    try { const sharp = (await import("sharp")).default; webp = await sharp(raw).webp().toBuffer(); }
    catch (e) { throw new Error(`not a readable image: ${(e as Error).message}`); }
    const metadata = await ingestCapture(store, {
      caseId, timestamp: new Date(mtimeMs).toISOString(), url: `drop://${name}`,
      tabTitle: name, triggerType: "navigation", imageBase64: webp.toString("base64"),
    });
    const willAnalyze = !metadata.isDuplicate && Boolean(options.pipeline) && hasAiProvider() && (await getControl(caseId)).enabled;
    options.onCapture?.(caseId);
    indexCaptureText(metadata);
    if (willAnalyze) {
      const buf = buffers.get(caseId) ?? [];
      buf.push(metadata);
      buffers.set(caseId, buf);
      void flush(caseId);
    }
  }

  async function processDropFile(caseId: string, dropDir: string, file: DropFileStat): Promise<{ ok: boolean; reason?: string; pending?: PendingRawInput }> {
    const full = join(dropDir, file.relpath);
    const name = basename(file.relpath);
    try {
      // A raw file an external tool handles (built-in EVTX/PCAP, or any extension a CUSTOM tool claims)
      // — can't be read as text. Run the configured tool against the on-disk file (size-independent, so
      // checked BEFORE the oversize cap), or surface it as pending so the dashboard offers "Run/Configure
      // <tool>". Auto-run is gated per-tool (#211). Images always go to the capture path, not here.
      const ext = extname(file.relpath).toLowerCase();
      if (options.toolRunner && classifyDropFile(file.relpath) !== "image" && rawExtClaimed(ext)) {
        const configured = liveToolConfigs();
        const toolId = resolveToolForExt(ext, configured);
        const cfg = toolId ? configured.get(toolId) : undefined;
        if (!toolId || !cfg || !cfg.autoRun) {
          // Not runnable now → pending (banner). Do NOT move the file so a manual run can still act on it.
          return { ok: false, pending: { relpath: file.relpath, ext, suggestedTool: toolId ?? suggestedToolForExtension(ext), configured: !!toolId } };
        }
        const r = await runToolAndIngest(caseId, toolId, full);
        if (!r.analyzed) return { ok: false, reason: `${toolId} ran but AI is off — output saved as evidence but not analyzed` };
        return { ok: true };
      }
      if (isOversize(file.size, dropMaxBytes)) {
        return { ok: false, reason: `too large (${Math.round(file.size / 1048576)} MB > ${Math.round(dropMaxBytes / 1048576)} MB cap) — use Import-from-path` };
      }
      if (classifyDropFile(file.relpath) === "image") {
        await ingestDroppedImage(caseId, full, name, file.mtimeMs);
        return { ok: true };
      }
      const text = await readFile(full, "utf8");
      if (!text.trim()) return { ok: false, reason: "empty file" };
      const kind = resolveImportKind(name, text);
      if (kind === "unknown") return { ok: false, reason: "unrecognized file type (not a supported import format)" };
      const r = await ingestStreamed(caseId, kind, text, name, undefined);
      if (!r.analyzed) return { ok: false, reason: "AI is off — saved as evidence but not analyzed; enable AI and re-import" };
      return { ok: true };
    } catch (err) {
      recordImportFailure(caseId, "drop", name, err);
      return { ok: false, reason: (err as Error)?.message ?? String(err) };
    }
  }

  async function scanCaseDrops(caseId: string): Promise<void> {
    if (dropScanning.has(caseId)) return;   // a previous sweep of this case is still running
    dropScanning.add(caseId);
    // Surface the auto-import sweep as a background job (registered below once we know files are
    // ready) so the dashboard Jobs panel shows drop-folder activity, exactly like a manual /import (#225).
    let job: RegisteredJob | undefined;
    try {
      const meta = await store.getCaseMeta(caseId).catch(() => null);
      if (meta?.status === "closed" || meta?.status === "archived") return; // don't auto-import into a closed or archived case (parity with /import)
      const dropDir = dropDirOf(caseId);
      await ensureDropFolders(caseId);
      const listing = await listDropFiles(dropDir);
      const { ready, nextSeen } = selectReadyFiles(listing, dropSeen.get(caseId) ?? new Map());
      dropSeen.set(caseId, nextSeen);
      if (ready.length === 0) return;

      // One job per sweep, kind "import" (same panel row as the Import button). Non-cancellable: the
      // sweep runs mixed importers that don't thread an abort signal, and a file already imported and
      // moved to _processed/ can't be un-imported — so there's nothing safe to cancel mid-flight.
      job = options.jobManager?.register({
        caseId, kind: "import", label: `drop import (${ready.length} file${ready.length === 1 ? "" : "s"})`,
      });

      const imported: string[] = [];
      const failed: DropFailure[] = [];
      const pendingRawInputs: PendingRawInput[] = [];
      let processed = 0;
      for (let i = 0; i < ready.length; i += DROP_CONCURRENCY) {
        const batch = ready.slice(i, i + DROP_CONCURRENCY);
        await Promise.all(batch.map(async (file) => {
          try {
            const res = await processDropFile(caseId, dropDir, file);
            if (res.pending) {
              // Raw input awaiting a tool: keep it in place (don't move, keep tracked) so the banner's
              // "Run <tool>" can act on it and a later config/auto-run picks it up next sweep.
              pendingRawInputs.push(res.pending);
              return;
            }
            if (res.ok) imported.push(file.relpath);
            else failed.push({ relpath: file.relpath, reason: res.reason ?? "import failed" });
            await moveDropFile(dropDir, file.relpath, res.ok).catch((e) => logLine(`[drop] move failed for ${file.relpath}: ${(e as Error).message}`));
            nextSeen.delete(file.relpath); // moved out of the watched area — forget it
            dropPendingLogged.get(caseId)?.delete(file.relpath); // resolved — no longer pending
          } finally {
            if (job) options.jobManager?.progress(job.jobId, ++processed, ready.length, basename(file.relpath));
          }
        }));
      }
      if (job) options.jobManager?.finish(job.jobId);
      if (imported.length === 0 && failed.length === 0 && pendingRawInputs.length === 0) return;

      if (options.dropStatusStore) {
        try {
          await options.dropStatusStore.record(caseId, { dropPath: dropDir, imported, failed, pendingRawInputs });
          options.onDropStatus?.(caseId);
        } catch (e) { logLine(`[drop] status record failed: ${(e as Error).message}`); }
      }

      // Folder-visible history (drop/drop-log.txt): every imported/failed file gets a line; a pending
      // raw-tool file gets ONE PENDING line the first time it's seen (dropPendingLogged dedups it across
      // the ~10s poll interval until it resolves).
      const { entries: logEntries, nextLoggedPending } = buildSweepLogEntries(
        { imported, failed, pendingRawInputs },
        dropPendingLogged.get(caseId) ?? new Set<string>(),
      );
      dropPendingLogged.set(caseId, nextLoggedPending);
      if (logEntries.length > 0) {
        await appendDropLog(dropDir, formatDropLogLines(logEntries, new Date().toISOString()))
          .catch((e) => logLine(`[drop] log append failed: ${(e as Error).message}`));
      }

      logLine(`[drop] ${caseId}: ${imported.length} imported, ${failed.length} failed`);
      if (failed.length > 0) {
        const lines = failed.slice(0, 20).map((x) => `• ${x.relpath} — ${x.reason}`);
        dispatchNotify(milestoneEvent(caseId, `Drop import: ${imported.length} imported, ${failed.length} failed`, lines, new Date().toISOString()));
      }
    } catch (err) {
      // A sweep-level failure (listing/meta/store I/O) must terminate the job — a job stuck "running"
      // forever is a worse UI bug than the original invisibility. No-op if it already finished.
      if (job) options.jobManager?.fail(job.jobId, err);
      throw err;
    } finally {
      dropScanning.delete(caseId);
    }
  }

  let dropTimer: NodeJS.Timeout | null = null;
  async function pollDropFolders(): Promise<void> {
    try {
      for (const c of await store.listCases()) await scanCaseDrops(c.caseId);
    } catch (e) {
      logLine(`[drop] poll error: ${(e as Error).message}`);
    } finally {
      dropTimer = setTimeout(() => { void pollDropFolders(); }, dropPollMs);
      dropTimer.unref();
    }
  }
  function startDropWatcher(): void {
    if (dropTimer) return;
    logLine(`[drop] watching evidence drop folders (poll every ${dropPollMs / 1000}s, cap ${Math.round(dropMaxBytes / 1048576)} MB)`);
    dropTimer = setTimeout(() => { void pollDropFolders(); }, dropPollMs);
    dropTimer.unref();
  }

  // ── Live Velociraptor CLIENT_EVENT monitors (#84) ─────────────────────────────────────────────
  // Per-monitor self-rescheduling timers (setTimeout, not setInterval, so a slow poll can't overlap
  // itself). Keyed `caseId monitorId`. Lost on restart, then re-armed from the persisted store by
  // resumeVeloMonitors(). .unref() so a pending poll never blocks process exit.
  const veloMonitorTimers = new Map<string, NodeJS.Timeout>();
  const monitorKey = (caseId: string, id: string): string => `${caseId} ${id}`;

  // The ingest step a poll hands its rows to: wrap them as a Velociraptor artifact-map and run the
  // shared streamed-ingest path; return how many forensic events it added (for the running stat).
  async function ingestMonitorRows(caseId: string, monitor: VeloMonitor, rows: unknown[]): Promise<number> {
    const json = monitorArtifactMap(monitor.artifact, rows);
    const shortHost = (monitor.hostname || monitor.clientId).split(".")[0].replace(/[^\w.\-]+/g, "_").slice(0, 40);
    const filename = `velo-monitor_${monitor.artifact}_${shortHost}.json`;
    const r = await ingestStreamed(caseId, "velociraptor", json, filename, monitor.minSeverity);
    return r.addedEvents;
  }

  // One poll cycle for a monitor: load it, poll (pure pollMonitorOnce), persist the updated monitor,
  // broadcast, and reschedule the next tick (unless it was removed/stopped). Never throws.
  async function pollVeloMonitor(caseId: string, id: string): Promise<void> {
    const monStore = options.veloMonitorStore;
    const client = options.velociraptorClient;
    if (!monStore || !client) { veloMonitorTimers.delete(monitorKey(caseId, id)); return; }
    let monitor: VeloMonitor | null = null;
    try { monitor = await monStore.get(caseId, id); } catch { /* treat as gone */ }
    if (!monitor || monitor.status === "stopped") { veloMonitorTimers.delete(monitorKey(caseId, id)); return; }

    const deps: PollDeps = {
      read: async (clientId, artifact, start, end) => (await client.monitorResults(clientId, artifact, start, end)).rows,
      ingest: (m, rows) => ingestMonitorRows(caseId, m, rows),
      now: () => Math.floor(Date.now() / 1000),
      defaultLookbackSeconds: monitor.pollSeconds,
      log: logLine,
    };
    const updated = await pollMonitorOnce(monitor, deps);
    try { await monStore.upsert(caseId, updated); } catch { /* best-effort */ }
    options.onVeloMonitor?.(caseId);
    // Reschedule only if it's still meant to run (a concurrent stop/delete clears the timer below).
    if (veloMonitorTimers.has(monitorKey(caseId, id))) scheduleVeloMonitor(caseId, updated);
  }

  // Arm (or re-arm) a monitor's timer for one poll interval out. Clears any existing timer first so
  // start is idempotent. Clamped 5s..1h so a bad value can't busy-loop or stall forever.
  function scheduleVeloMonitor(caseId: string, monitor: VeloMonitor): void {
    const key = monitorKey(caseId, monitor.id);
    const existing = veloMonitorTimers.get(key);
    if (existing) clearTimeout(existing);
    const seconds = Math.min(3600, Math.max(5, Math.floor(monitor.pollSeconds) || 30));
    const timer = setTimeout(() => { void pollVeloMonitor(caseId, monitor.id); }, seconds * 1000);
    timer.unref?.();
    veloMonitorTimers.set(key, timer);
  }

  function stopVeloMonitorTimer(caseId: string, id: string): void {
    const key = monitorKey(caseId, id);
    const timer = veloMonitorTimers.get(key);
    if (timer) clearTimeout(timer);
    veloMonitorTimers.delete(key);
  }

  // Re-arm timers for every active monitor across all cases (called once at startup so monitoring
  // survives the #1-gotcha restart). Best-effort — a single bad case must not abort the sweep.
  async function resumeVeloMonitors(): Promise<void> {
    const monStore = options.veloMonitorStore;
    if (!monStore || !options.velociraptorClient) return;
    let cases: { caseId: string }[] = [];
    try { cases = await store.listCases(); } catch { return; }
    let resumed = 0;
    for (const c of cases) {
      try {
        for (const m of await monStore.list(c.caseId)) {
          if (m.status !== "stopped") { scheduleVeloMonitor(c.caseId, m); resumed++; }
        }
      } catch { /* skip this case */ }
    }
    if (resumed > 0) logLine(`[velo-monitor] resumed ${resumed} live monitor(s) across ${cases.length} case(s)`);
  }

  // Build + persist + schedule one monitor (shared by the manual start route and the auto-monitor
  // route). `clientId` is a real client (`C....`) or the ALL_CLIENTS sentinel (`*`) for every endpoint.
  // Idempotent per (clientId, artifact): re-arming keeps the existing cursor so events aren't re-ingested;
  // a brand-new monitor starts at "now" (no history backfill). Returns the persisted monitor.
  async function createVeloMonitor(caseId: string, spec: { clientId: string; artifact: string; pollSeconds: number; hostname?: string; minSeverity?: Severity; allClients?: boolean }): Promise<VeloMonitor> {
    const monStore = options.veloMonitorStore!;
    const nowEpoch = Math.floor(Date.now() / 1000);
    const id = monitorId(spec.clientId, spec.artifact);
    const existing = await monStore.get(caseId, id);
    const monitor: VeloMonitor = {
      id, clientId: spec.clientId, artifact: spec.artifact, pollSeconds: spec.pollSeconds,
      allClients: spec.allClients || undefined,
      hostname: spec.allClients ? (spec.hostname || "all clients") : spec.hostname,
      cursor: existing?.cursor && existing.cursor > 0 ? existing.cursor : nowEpoch,
      status: "active", minSeverity: spec.minSeverity,
      createdAt: existing?.createdAt ?? new Date().toISOString(),
      addedEvents: existing?.addedEvents ?? 0, polls: existing?.polls ?? 0,
    };
    await monStore.upsert(caseId, monitor);
    scheduleVeloMonitor(caseId, monitor);
    options.onVeloMonitor?.(caseId);
    logLine(`[velo-monitor] started ${spec.artifact} on ${monitor.hostname || spec.clientId} (every ${spec.pollSeconds}s) for case ${caseId}`);
    return monitor;
  }

  // Collect a bundle hunt and import it the SAME way a manual import works. Ingests BOTH the result
  // ROWS (the {"Artifact.Name":[rows]} artifact-map the Velociraptor importer consumes) AND any
  // uploaded JSON reports (e.g. THOR/Hayabusa via Generic.Scanner.ThorZIP) — for those the rows don't
  // matter, the uploaded JSON does; it's detected + dispatched to the right importer. Honors the run's
  // minSeverity floor, records ONE combined import-meta diff, then synthesizes. Never throws (timer).
  async function importVeloHuntResults(caseId: string, huntId: string): Promise<void> {
    const client = options.velociraptorClient;
    const huntStore = options.veloHuntStore;
    const pipeline = options.pipeline;
    if (!client || !huntStore || !pipeline) return;
    if (collectingNow.has(huntId)) return;   // already collecting this hunt in this process — avoid a double-run
    collectingNow.add(huntId);
    try {
    const pending = veloHuntTimers.get(huntId);
    if (pending) { clearTimeout(pending); veloHuntTimers.delete(huntId); }
    stopVeloHuntStatusPoll(caseId, huntId);   // an import is starting — it now owns this job's status

    let job = await huntStore.get(caseId, huntId);
    if (!job) return;
    if (job.status === "collecting") return;   // a collection of this hunt is already in flight
    try {
      // A last live check right before collecting: was this hunt stopped/deleted in Velociraptor well
      // before its own scheduled expiry? Checked HERE (not just in the status poller) so every entry
      // point — the poller, the fixed-delay auto-collect timer, and a manual "Collect now" — gets the
      // same signal. Best-effort: a failed check must not block the collect itself.
      let stoppedEarly = job.stoppedEarly === true;
      if (!stoppedEarly) {
        try { stoppedEarly = isHuntStoppedEarly(await client.huntStatus(job.huntId), Date.now()); } catch { /* best-effort */ }
      }
      job = { ...job, status: "collecting", ...(stoppedEarly ? { stoppedEarly: true } : {}) };
      await huntStore.upsert(caseId, job);
      options.onVeloHunt?.(caseId);
      const minSeverity = job.minSeverity;

      // Snapshot the full state BEFORE any import so we record one combined import-meta diff for the
      // whole collection AND can push a single pre-collection undo checkpoint (#76).
      let stateBefore: InvestigationState | null = null;
      if (options.stateStore) {
        try { stateBefore = await options.stateStore.load(caseId); } catch { /* keep null */ }
      }

      let importedAny = false;
      let lastFile: string | undefined;

      // A bundle flagged superTimelineOnly (the built-in super-timeline-triage) collects raw host
      // artifacts (MFT/USN/Prefetch) whose only purpose is the super-timeline — routing them through the
      // normal Velociraptor importer would flood the forensic timeline + IOC list, defeating the point.
      // So for such a bundle we PARSE the rows (no mergeDelta) and append straight to the super-timeline.
      const bundle = job.bundleId && options.artifactBundleStore ? await options.artifactBundleStore.get(job.bundleId) : null;
      const superOnly = bundle?.superTimelineOnly === true && !!options.superTimelineStore;

      // 1) Result ROWS → the Velociraptor importer (detections + telemetry). Resilient: an artifact
      // whose output is too large to fetch is skipped (logged), not fatal — the rest still import, and
      // its uploaded JSON (if any) is still picked up in step 2.
      // For a suggested fleet hunt the single Custom.Hunt artifact stores rows under named sources
      // (Pivot0…); map them so collect reads `artifact/source` (else 0 rows → false "no evidence", #157).
      const sourcesByArtifact = (job.sources?.length && job.artifacts.length === 1) ? { [job.artifacts[0]]: job.sources } : undefined;
      const { results: map, skipped } = await client.huntResultsByArtifact(job.huntId, job.artifacts, job.filters, sourcesByArtifact);
      if (skipped.length) logLine(`[velociraptor] hunt ${job.huntId}: skipped ${skipped.length} artifact(s) — ${skipped.map((s) => `${s.name} (${s.error})`).join("; ")} — raise DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT / DFIR_VELOCIRAPTOR_MAX_ROWS if these are oversized`);
      const totalRows = Object.values(map).reduce((n, rows) => n + rows.length, 0);
      // The artifacts that returned NEITHER rows nor an error — not a failure (they simply had nothing
      // to report), but worth distinguishing from `skipped` so "N artifacts collected, M had no findings,
      // K failed to collect" is fully accounted for instead of a bare "+X events" that reads as one artifact.
      const skippedNames = new Set(skipped.map((s) => s.name));
      const emptyArtifacts = job.artifacts.filter((a) => !map[a] && !skippedNames.has(a));
      if (totalRows > 0) {
        const json = JSON.stringify(map);
        const { storedName, importedAt, seq } = await persistEvidence(caseId, `velo-hunt_${job.huntId}.json`, json);
        lastFile = storedName;
        options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing Velociraptor hunt ${job.huntId} rows (${Object.keys(map).length} artifact(s), ${totalRows} row(s))` });
        // Deep-link back to the hunt in the Velociraptor GUI: reuse the URL saved on the job when
        // present, else build it from the hunt id. Shared by every event from this hunt, on EITHER
        // path — previously only the super-only branch stamped it, so a normal (forensic-timeline-
        // bound) bundle/hunt collection never carried a veloUrl and the FT's "↗ Velociraptor" link
        // never rendered for its events.
        const huntId = job.huntId;   // hoisted so the .map closure below doesn't re-narrow the reassignable `job`
        const veloUrl = job.guiUrl || client.huntGuiUrlFor(huntId);
        if (superOnly) {
          // Parse WITHOUT merging into forensic; append the mapped events to the super-timeline only.
          // The artifact-map carries each row's _Source, so `artifact` is just a filename fallback.
          const artifact = storedName.replace(/^\d+_/, "").replace(/\.(json|jsonl|ndjson|csv)$/i, "");
          // Complete record: don't aggregate rows, lift the 2000-event cap to the super store's cap.
          const parsed = parseVelociraptorJson(json, { artifact, aggregate: false, maxEvents: Number(process.env.DFIR_SUPERTIMELINE_MAX) || 100000 });
          const floored = applySeverityFloor(parsed.events, minSeverity);   // honor the import floor (no-op when unset) — the forensic path floors via importVelociraptor
          // Id by the HUNT id, not the import `seq` (which increments each collect): re-collecting the
          // same hunt (Collect now / auto-collect after a manual collect) re-parses the SAME rows, and
          // the super-timeline's id-based dedup (dedupeAppend) only drops repeats when the ids are
          // stable. Same rows in the same order → same ids → deduped; a straggler that checks in later
          // gets a higher index and appends. (Forensic imports get this from correlation dedup; the
          // super-only path has no such guard, so the ids must be stable across re-collects.)
          const events: ForensicEvent[] = floored.map((e, i) => ({
            id: `${huntId}-e${i + 1}`,
            timestamp: e.timestamp,
            description: e.description,
            severity: e.severity,
            mitreTechniques: e.mitreTechniques ?? [],
            relatedFindingIds: [],
            sourceScreenshots: [storedName],
            ...(e.artifactName ? { artifactName: e.artifactName } : {}),
            ...(e.message ? { message: e.message } : {}),
            ...(veloUrl ? { veloUrl } : {}),
            sources: e.sources?.length ? e.sources : ["Velociraptor"],
            ...(e.asset ? { asset: e.asset } : {}),
            ...(e.path ? { path: e.path } : {}),
            ...(e.sha256 ? { sha256: e.sha256 } : {}),
            ...(e.md5 ? { md5: e.md5 } : {}),
          }));
          await options.superTimelineStore!.append(caseId, events);
          options.onSuperTimeline?.(caseId);   // live dashboards refresh as super-only events stream in
          await autoTagImported(caseId, events);
          importedAny = true;   // report success even though nothing hit the forensic timeline
        } else {
          await pipeline.importVelociraptor(caseId, json, { label: storedName, idPrefix: `${seq}`, importedAt, minSeverity, veloUrl });
          importedAny = true;
        }
      }

      // 2) Uploaded JSON reports (e.g. THOR/Hayabusa) → detect + dispatch. Best-effort: a wrong upload
      // VQL for the server version must not break the rows import (set DFIR_VELOCIRAPTOR_UPLOAD_VQL).
      let uploads: HuntUpload[] = [];
      try { uploads = await client.huntUploads(job.huntId); }
      catch (e) { logLine(`[velociraptor] hunt uploads read failed (override DFIR_VELOCIRAPTOR_UPLOAD_VQL?): ${(e as Error).message}`); }
      for (const up of uploads) {
        const upKind = resolveImportKind(up.name, up.content);   // honor custom importers like /import + /push
        if (upKind === "unknown") continue;
        if (superOnly) {
          // Super-only bundles route to the super-timeline; the upload path (THOR/Hayabusa JSON) only has
          // a forensic-merge importer (dispatchImport), so ingesting it would leak into the forensic
          // timeline and break the super-only invariant. Skip it and tell the analyst to collect
          // upload-based artifacts via a normal bundle. (The shipped super-timeline-triage bundle has no
          // upload artifacts; this guards custom/edited super-only bundles.)
          logLine(`[velociraptor] super-only bundle: skipping uploaded ${upKind} report ${up.name} (upload-based artifacts aren't ingested for super-only bundles — collect them via a normal bundle)`);
          continue;
        }
        if ((upKind === "csv" || upKind === "log") && !(await getControl(caseId)).enabled) continue;   // AI-dependent, AI off
        try {
          const { storedName, importedAt, seq } = await persistEvidence(caseId, up.name, up.content);
          lastFile = storedName;
          options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing uploaded ${upKind} report ${up.name}` });
          await dispatchImport(upKind, caseId, up.content, { label: storedName, idPrefix: `${seq}`, importedAt, minSeverity });
          importedAny = true;
        } catch (e) { logLine(`[velociraptor] upload import failed (${up.name}): ${(e as Error).message}`); }
      }
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });

      // 3) One combined import-meta diff (so the dashboard's "📥 last import / +N" banner lights up).
      let addedEvents = 0;
      let addedIocs = 0;
      if (importedAny && options.stateStore && stateBefore) {
        try {
          const imported = await options.stateStore.load(caseId);
          // Dual-write the hunt's new events into the super-timeline FIRST (superset of everything
          // imported, Info telemetry included); resolve the FULL events from the imported (pre-demote)
          // state since the diff is lossy.
          if (options.superTimelineStore) {
            const superDiff = diffTimeline(stateBefore.forensicTimeline, imported.forensicTimeline);
            const added = addedForensicEvents(imported.forensicTimeline, superDiff);
            if (added.length) { try { await options.superTimelineStore.append(caseId, added); options.onSuperTimeline?.(caseId); } catch { /* non-fatal */ } await autoTagImported(caseId, added); }
          }
          // Demote sub-threshold events out of forensic (kept in super), then compute the import-meta
          // diff + checkpoint decision on the POST-demote state so "+N events" counts only graded signal.
          const s = await demoteForensicForCase(caseId);
          const diff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
          const iocsDiff = diffIocs(stateBefore.iocs, s.iocs);
          addedEvents = diff.added.length;
          addedIocs = iocsDiff.added.length;
          if (options.importMetaStore) {
            await options.importMetaStore.record(caseId, { kind: "velociraptor", file: lastFile ?? `velo-hunt_${job.huntId}.json`, diff, iocsDiff });
            options.onImportMeta?.(caseId);
          }
          // #76: snapshot the pre-collect state for undo when the hunt actually added data.
          if (diff.added.length || diff.removed.length || iocsDiff.added.length || iocsDiff.removed.length) {
            await pushImportCheckpoint(caseId, stateBefore, `velociraptor (${lastFile ?? `hunt ${job.huntId}`})`);
          }
        } catch { /* non-fatal */ }
      }

      // #157 feedback loop: fill this hunt's outcome (by huntId) — for a bundle hunt OR a deployed
      // suggested hunt. Done regardless of importedAny so a hunt that ran and found nothing is recorded
      // as a miss (the loop must know it ran empty so it isn't re-proposed as productive). Best-effort.
      if (options.huntOutcomeStore) {
        try {
          const cur = await options.huntOutcomeStore.load(caseId);
          // resultRows = the rows the hunt RETURNED (what the analyst sees); addedEvents = new-to-case
          // after dedup. Showing both stops "+1 event" reading as wrong next to a 10-row result table.
          await options.huntOutcomeStore.save(caseId, fillOutcome(cur, job.huntId, { resultRows: totalRows, addedEvents, addedIocs, collectedAt: new Date().toISOString() }));
        } catch (e) { logLine(`[hunt-outcomes] fill failed for hunt ${job.huntId}: ${(e as Error).message}`); }
      }

      job = {
        ...job, status: "imported", importedAt: new Date().toISOString(), importFile: lastFile, addedEvents, addedIocs, error: undefined,
        skippedArtifacts: skipped.length ? skipped : undefined, emptyArtifacts: emptyArtifacts.length ? emptyArtifacts : undefined,
      };
      await huntStore.upsert(caseId, job);
      options.onVeloHunt?.(caseId);
      if (importedAny) resynthesizeInBackground(caseId);
    } catch (err) {
      try {
        const cur = await huntStore.get(caseId, huntId);
        if (cur) await huntStore.upsert(caseId, { ...cur, status: "error", error: (err as Error).message });
      } catch { /* ignore */ }
      options.onVeloHunt?.(caseId);
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: `Velociraptor hunt collect failed: ${(err as Error).message}` });
    }
    } finally {
      collectingNow.delete(huntId);
    }
  }

  // Ingest ONE Velociraptor artifact-map JSON into a case — the shared core used by the external
  // hunt/flow import route (POST .../import-external). Mirrors importVeloHuntResults' rows step but is
  // self-contained for a single map (no uploads / hunt-outcome / checkpoint — those are hunt-launch
  // concerns). Routes to the forensic timeline (normal, + dual-write to the super-timeline) OR the
  // super-timeline ONLY (superOnly). `idBase` gives super-only events STABLE ids so re-importing the
  // same external hunt/flow dedups (dedupeAppend keys on id) instead of duplicating.
  async function ingestVeloArtifactMap(
    caseId: string,
    mapJson: string,
    opts: { label: string; idBase: string; superOnly?: boolean; minSeverity?: Severity; hostFallback?: string; veloUrl?: string },
  ): Promise<{ addedEvents: number; addedIocs: number; storedName: string }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    let stateBefore: InvestigationState | null = null;
    if (options.stateStore) { try { stateBefore = await options.stateStore.load(caseId); } catch { /* null */ } }
    const { storedName, importedAt, seq } = await persistEvidence(caseId, opts.label, mapJson);

    if (opts.superOnly && options.superTimelineStore) {
      const artifact = storedName.replace(/^\d+_/, "").replace(/\.(json|jsonl|ndjson|csv)$/i, "");
      // The super-timeline is the COMPLETE record — do NOT aggregate near-identical rows (which would
      // collapse e.g. 221 collected rows to ~141), and lift the default 2000-event cap to the super
      // store's cap so a big collection isn't silently truncated.
      const parsed = parseVelociraptorJson(mapJson, { artifact, hostFallback: opts.hostFallback, aggregate: false, maxEvents: Number(process.env.DFIR_SUPERTIMELINE_MAX) || 100000 });
      const floored = applySeverityFloor(parsed.events, opts.minSeverity);   // honor the import floor (no-op when unset) — the forensic path floors via importVelociraptor
      // Same field set as importVeloHuntResults' super-only mapping (intentional parallel — the two
      // paths stay decoupled).
      const events: ForensicEvent[] = floored.map((e, i) => ({
        id: `${opts.idBase}-e${i + 1}`, timestamp: e.timestamp, description: e.description, severity: e.severity,
        mitreTechniques: e.mitreTechniques ?? [], relatedFindingIds: [], sourceScreenshots: [storedName],
        ...(e.artifactName ? { artifactName: e.artifactName } : {}),
        ...(e.message ? { message: e.message } : {}),
        ...(opts.veloUrl ? { veloUrl: opts.veloUrl } : {}),
        sources: e.sources?.length ? e.sources : ["Velociraptor"],
        ...(e.asset ? { asset: e.asset } : {}), ...(e.path ? { path: e.path } : {}),
        ...(e.sha256 ? { sha256: e.sha256 } : {}), ...(e.md5 ? { md5: e.md5 } : {}),
      }));
      const superAdded = await options.superTimelineStore.append(caseId, events);
      options.onSuperTimeline?.(caseId);
      await autoTagImported(caseId, events);
      // Super-only imports never touch the forensic timeline, so the forensic diff below is always 0 —
      // report the SUPER-TIMELINE count instead so "+N events" reflects what actually landed.
      resynthesizeInBackground(caseId);
      return { addedEvents: superAdded, addedIocs: 0, storedName };
    }
    await pipeline.importVelociraptor(caseId, mapJson, {
      label: storedName, idPrefix: `${seq}`, importedAt, minSeverity: opts.minSeverity,
      velociraptor: opts.hostFallback ? { hostFallback: opts.hostFallback } : undefined,
      veloUrl: opts.veloUrl,
    });

    let addedEvents = 0, addedIocs = 0;
    if (options.stateStore && stateBefore) {
      try {
        const imported = await options.stateStore.load(caseId);
        // Dual-write into the super-timeline FIRST (superset, Info telemetry included) — the super-only
        // path early-returned above, so this is always the forensic path; the `!opts.superOnly` guard is
        // defensive. Resolve the FULL events from the imported (pre-demote) state since the diff is lossy.
        if (!opts.superOnly && options.superTimelineStore) {
          const superDiff = diffTimeline(stateBefore.forensicTimeline, imported.forensicTimeline);
          const added = addedForensicEvents(imported.forensicTimeline, superDiff);
          if (added.length) { try { await options.superTimelineStore.append(caseId, added); options.onSuperTimeline?.(caseId); } catch { /* non-fatal */ } await autoTagImported(caseId, added); }
        }
        // Demote sub-threshold events out of forensic (kept in super), then compute the import-meta diff
        // on the POST-demote state so "+N events" counts only graded signal.
        const s = opts.superOnly ? imported : await demoteForensicForCase(caseId);
        const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
        const iDiff = diffIocs(stateBefore.iocs, s.iocs);
        addedEvents = tDiff.added.length; addedIocs = iDiff.added.length;
        if ((addedEvents || addedIocs || tDiff.removed.length || iDiff.removed.length) && options.importMetaStore) {
          await options.importMetaStore.record(caseId, { kind: "velociraptor", file: storedName, diff: tDiff, iocsDiff: iDiff });
          options.onImportMeta?.(caseId);
        }
      } catch { /* non-fatal */ }
    }
    try { await applyWhitelistToCase(caseId); } catch { /* non-fatal */ }
    try { await applyNsrlToCase(caseId); } catch { /* non-fatal */ }
    resynthesizeInBackground(caseId);
    return { addedEvents, addedIocs, storedName };
  }

  // Import ONLY a hunt/flow's uploaded report files (e.g. THOR), skipping rows entirely — used when
  // the analyst pastes the Velociraptor GUI's "Uploaded Files" tab URL specifically (ref.isUploadsUrl).
  // Mirrors importVeloHuntResults' uploads step (same resolveImportKind + dispatchImport chain) but
  // standalone, with ONE before/after diff across every uploaded file instead of hunt-job bookkeeping.
  async function ingestVeloUploads(
    caseId: string,
    uploads: HuntUpload[],
    opts: { minSeverity?: Severity; label: string },
  ): Promise<{ addedEvents: number; addedIocs: number; imported: string[]; skipped: string[] }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    let stateBefore: InvestigationState | null = null;
    if (options.stateStore) { try { stateBefore = await options.stateStore.load(caseId); } catch { /* null */ } }

    const imported: string[] = [];
    const skipped: string[] = [];
    let lastStoredName: string | undefined;
    for (const up of uploads) {
      const kind = resolveImportKind(up.name, up.content);
      if (kind === "unknown") { skipped.push(up.name); continue; }
      // CSV/log are themselves an LLM call — respect the per-case AI toggle exactly like every other
      // import path (dispatchImport's own CSV/log routes, and the bundle-collect uploads step).
      // With AI off, skip entirely rather than persisting evidence that never analyzes.
      if ((kind === "csv" || kind === "log") && !(await getControl(caseId)).enabled) { skipped.push(up.name); continue; }
      try {
        const { storedName, importedAt, seq } = await persistEvidence(caseId, up.name, up.content);
        lastStoredName = storedName;
        await dispatchImport(kind, caseId, up.content, { label: storedName, idPrefix: `${seq}`, importedAt, minSeverity: opts.minSeverity });
        imported.push(up.name);
      } catch (e) {
        logLine(`[velociraptor] uploads-only import failed (${up.name}): ${(e as Error).message}`);
        skipped.push(up.name);
      }
    }

    let addedEvents = 0, addedIocs = 0;
    if (imported.length && options.stateStore && stateBefore) {
      try {
        const afterImport = await options.stateStore.load(caseId);
        if (options.superTimelineStore) {
          const superDiff = diffTimeline(stateBefore.forensicTimeline, afterImport.forensicTimeline);
          const added = addedForensicEvents(afterImport.forensicTimeline, superDiff);
          if (added.length) { try { await options.superTimelineStore.append(caseId, added); options.onSuperTimeline?.(caseId); } catch { /* non-fatal */ } await autoTagImported(caseId, added); }
        }
        const s = await demoteForensicForCase(caseId);
        const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
        const iDiff = diffIocs(stateBefore.iocs, s.iocs);
        addedEvents = tDiff.added.length; addedIocs = iDiff.added.length;
        if ((addedEvents || addedIocs || tDiff.removed.length || iDiff.removed.length) && options.importMetaStore && lastStoredName) {
          await options.importMetaStore.record(caseId, { kind: "velociraptor", file: lastStoredName, diff: tDiff, iocsDiff: iDiff });
          options.onImportMeta?.(caseId);
        }
      } catch { /* non-fatal */ }
      try { await applyWhitelistToCase(caseId); } catch { /* non-fatal */ }
      try { await applyNsrlToCase(caseId); } catch { /* non-fatal */ }
      resynthesizeInBackground(caseId);
    }
    return { addedEvents, addedIocs, imported, skipped };
  }

  // ── Velociraptor hunt STATUS polling ─────────────────────────────────────────────────────────
  // Independent from the fixed-delay auto-collect timer above (veloHuntTimers): every
  // DFIR_VELO_HUNT_POLL_S (default 30s, clamped 5-300) asks Velociraptor for the hunt's real state,
  // so a hunt deleted/stopped in Velociraptor is reflected promptly instead of waiting out the fixed
  // delay. Keyed `caseId huntId`, self-rescheduling setTimeout (not setInterval, so a slow poll can't
  // overlap itself), .unref()'d so a pending poll never blocks process exit. Mirrors the live-monitor
  // scheduling above (veloMonitorTimers / scheduleVeloMonitor / pollVeloMonitor / resumeVeloMonitors).
  const veloStatusTimers = new Map<string, NodeJS.Timeout>();
  const statusKey = (caseId: string, huntId: string): string => `${caseId} ${huntId}`;

  // One status-poll tick: load the job, poll (pure pollHuntStatusOnce), persist + broadcast only on
  // an actual status change, then either reschedule, trigger an immediate collect, or stop. Never
  // throws (pollHuntStatusOnce itself never throws; store I/O failures are best-effort).
  async function pollVeloHuntStatus(caseId: string, huntId: string): Promise<void> {
    const huntStore = options.veloHuntStore;
    const client = options.velociraptorClient;
    if (!huntStore || !client) { veloStatusTimers.delete(statusKey(caseId, huntId)); return; }
    let job: VeloHuntJob | null = null;
    try { job = await huntStore.get(caseId, huntId); } catch (err) { logLine(`[velo-hunt-status] failed to load hunt ${huntId} for status poll: ${(err as Error).message}`); }
    if (!job) { veloStatusTimers.delete(statusKey(caseId, huntId)); return; }

    const deps: HuntPollDeps = { getState: (id) => client.huntStatus(id), log: logLine };
    const outcome = await pollHuntStatusOnce(job, deps);
    if (outcome.job.status !== job.status) {
      try { await huntStore.upsert(caseId, outcome.job); } catch { /* best-effort */ }
      options.onVeloHunt?.(caseId);
    }

    if (outcome.action === "reschedule") {
      if (veloStatusTimers.has(statusKey(caseId, huntId))) scheduleVeloHuntStatusPoll(caseId, huntId);
    } else if (outcome.action === "collect") {
      veloStatusTimers.delete(statusKey(caseId, huntId));
      void importVeloHuntResults(caseId, huntId);   // clears the fixed-delay timer + status poll itself (see below)
    } else {
      veloStatusTimers.delete(statusKey(caseId, huntId));
    }
  }

  // Arm (or re-arm) a hunt's status-poll timer for one interval out. Clears any existing timer first
  // so start is idempotent. Clamped 5s..300s so a bad env value can't busy-loop or stall forever.
  function scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const key = statusKey(caseId, huntId);
    const existing = veloStatusTimers.get(key);
    if (existing) clearTimeout(existing);
    const seconds = Math.min(300, Math.max(5, Number(process.env.DFIR_VELO_HUNT_POLL_S) || 30));
    const timer = setTimeout(() => { void pollVeloHuntStatus(caseId, huntId); }, seconds * 1000);
    timer.unref?.();
    veloStatusTimers.set(key, timer);
  }

  function stopVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const key = statusKey(caseId, huntId);
    const timer = veloStatusTimers.get(key);
    if (timer) clearTimeout(timer);
    veloStatusTimers.delete(key);
  }

  // Re-arm status polling for every non-terminal hunt job across all cases (server restart). As a
  // side effect this also self-heals the pre-existing "fixed-delay auto-collect timer is lost on
  // restart" gap: a resumed status poll will detect STOPPED/ARCHIVED on its own and trigger the
  // collect even though the original setTimeout is gone. Best-effort per case.
  async function resumeVeloHuntStatusPolls(): Promise<void> {
    const huntStore = options.veloHuntStore;
    if (!huntStore || !options.velociraptorClient) return;
    let cases: { caseId: string }[] = [];
    try { cases = await store.listCases(); } catch { return; }
    let resumed = 0;
    for (const c of cases) {
      try {
        for (const job of await huntStore.list(c.caseId)) {
          if (job.status === "running" || job.status === "unreachable") {
            scheduleVeloHuntStatusPoll(c.caseId, job.huntId);
            resumed++;
          }
        }
      } catch { /* skip this case */ }
    }
    if (resumed > 0) logLine(`[velo-hunt-status] resumed status polling for ${resumed} hunt(s) across ${cases.length} case(s)`);
  }

  // Record a deployed hunt in the per-case hunting feedback loop ledger (#157). Best-effort + never
  // throws — an outcome-recording failure must not break a deploy. Stamps the time here so huntOutcomes
  // stays time-free. Re-deploying the same huntId upserts (recordDeploy dedups by id).
  async function recordHuntDeploy(caseId: string, input: HuntDeployInput): Promise<void> {
    if (!options.huntOutcomeStore) return;
    try {
      const max = Number(process.env.DFIR_HUNT_OUTCOME_MAX) || HUNT_OUTCOME_MAX_DEFAULT;
      const cur = await options.huntOutcomeStore.load(caseId);
      await options.huntOutcomeStore.save(caseId, recordDeploy(cur, input, max));
    } catch (e) {
      logLine(`[hunt-outcomes] record deploy failed: ${(e as Error).message}`);
    }
  }

  // Client-confirmed false-positive findings/IOCs. Marking one re-runs synthesis so the AI
  // re-derives its conclusions without it.
  const falsePositives = new FalsePositiveStore(store);
  // The active NSRL RDS SQLite connection (#63). Mutable: the Settings → NSRL connect/disconnect
  // routes can swap it at runtime (unless env-managed). Starts from the startup-resolved DB.
  let nsrlDb = options.nsrlDb;

  // Threat-intel enrichment is OFF by default (OPSEC). When the analyst turns it on it
  // enriches the current IOCs and — via autoEnrichIfEnabled below — any IOCs added later.
  const enrichControl = new EnrichControlStore(store);

  // Provider classification (from the configured set) + the per-case enabled subset.
  const allProviders = options.enrichmentProviders ?? [];
  const configuredNames = allProviders.map((p) => p.name);
  const localNames = allProviders.filter((p) => p.scope === "local").map((p) => p.name);
  async function enabledProvidersFor(caseId: string): Promise<EnrichmentProvider[]> {
    const enabled = new Set(resolveEnabledProviders(await enrichControl.load(caseId), configuredNames, localNames));
    return allProviders.filter((p) => enabled.has(p.name));
  }

  // Shared reachability gate (one per server, so the cache survives across enrich runs: if a
  // self-hosted instance is down and three imports land within a minute, it's probed once,
  // not three times). Logs each real probe's verdict so the operator sees DOWN/UP transitions.
  const enrichHealth = new ProviderHealthCache({
    ttlMs: options.enrichHealthTtlMs,
    onProbe: (name, h) => logLine(`[enrich] health ${name} ${h.ok ? "UP" : `DOWN (${h.detail ?? "unreachable"})`}`),
  });
  // Cases whose last enrich run had to skip a provider that was down. The background poller
  // drains this and re-enriches once the server is reachable again (the per-provider cache
  // means only the still-unchecked IOCs are actually queried).
  const enrichPending = new Set<string>();

  function enrichInBackground(caseId: string, force = false): void {
    if (allProviders.length === 0 || !options.stateStore) return;
    let job: { jobId: string; signal?: AbortSignal } | undefined; // #225: registered once providers are known
    void (async () => {
      const providers = await enabledProvidersFor(caseId);
      if (providers.length === 0) { enrichPending.delete(caseId); return; }     // nothing enabled — drop any stale pending mark so the poller can idle
      const state = await options.stateStore!.load(caseId);
      // Pure no-op guard: every enrichable IOC already has a result from every enabled provider,
      // and (when a RockyRaccoon-style provider is present) every process chain is already
      // checked. Callers like resynthesizeInBackground fire this after EVERY re-synthesis —
      // including one triggered only by marking an event/finding false-positive, which touches
      // neither IOCs nor process chains — so without this guard the analyst sees a spurious
      // "enriching…" status and a no-op state save/broadcast on every FP mark. Skip entirely
      // (no job, no status flip, no save) unless there's real work or the caller forced a re-check.
      if (!force) {
        const chainCapable = providers.some((p) => typeof (p as { checkParentChild?: unknown }).checkParentChild === "function");
        const work = hasEnrichableWork(state.iocs, providers) || (chainCapable && hasChainWork(state.forensicTimeline));
        if (!work) { enrichPending.delete(caseId); return; }
      }
      // #225: track enrichment as a cancellable job — a throttled run (up to maxIocs × delayMs) can be long.
      job = options.jobManager?.register({ caseId, kind: "enrichment", label: `enrich (${providers.map((p) => p.name).join(", ")})`, cancellable: true });
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `enriching IOCs (${providers.map((p) => p.name).join(", ")})` });
      logLine(`[enrich] ${caseId} START providers=[${providers.map((p) => p.name).join(", ")}] force=${force} iocs=${state.iocs.length}`);
      const { iocs, summary } = await enrichIocs(state.iocs, {
        providers,
        delayMs: options.enrichDelayMs,
        perProviderDelayMs: options.enrichProviderDelayMs,
        jitterMs: options.enrichJitterMs,
        retry: { retries: options.enrichRetries, backoffMs: options.enrichRetryBackoffMs },
        maxIocs: options.enrichMaxIocs,
        force,
        signal: job?.signal,    // #225: analyst cancel — stop between IOCs (partial enrichment is additive/safe)
        health: enrichHealth,   // probe each provider (cached ~60s) before sending — skip the dead ones
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `enriching IOC ${done}/${total}`,
        }),
        // One audit line per outbound threat-intel API call: which provider, indicator, result.
        onLookup: (e: EnrichLookupEvent) => logLine(
          `[enrich] ${caseId} ${e.provider} ${e.kind} ${shortValue(e.value)} -> ${e.outcome}${e.detail ? ` (${e.detail})` : ""} ${e.ms}ms`,
        ),
      });
      const downNote = summary.unavailable.length ? ` unavailable=[${summary.unavailable.join(", ")}]` : "";
      logLine(`[enrich] ${caseId} DONE queried=${summary.queried} hits=${summary.withHits} errors=${summary.errors} skipped=${summary.skipped}${downNote}`);
      // Remember (or clear) this case for the background poller: if a provider was down we
      // couldn't finish, so retry it on recovery; if all reachable, drop any stale pending mark.
      if (summary.unavailable.length) enrichPending.add(caseId);
      else enrichPending.delete(caseId);
      const { chainSummary } = await runStateExclusive(caseId, async () => {
      // Re-load + write only the iocs so we don't clobber a concurrent state change.
        const latest = await options.stateStore!.load(caseId);
      const byValue = new Map(iocs.map((i) => [i.value, i]));
      let merged = { ...latest, iocs: latest.iocs.map((i) => byValue.get(i.value) ?? i), updatedAt: new Date().toISOString() };

      // Process-chain validation: if a RockyRaccoon provider is present, validate
      // parent→child relationships on the forensic timeline (anomalous chains are a
      // strong signal). Uses the same throttle/cap as IOC enrichment.
      const rocky = providers.find((p): p is EnrichmentProvider & { checkParentChild: (p: string, c: string) => Promise<ParentChildResult | null> } =>
        typeof (p as { checkParentChild?: unknown }).checkParentChild === "function");
      let chainSummary: ChainSummary | undefined;
      if (rocky) {
        const { events, summary: cs } = await validateProcessChains(merged.forensicTimeline, {
          check: (p, c) => rocky.checkParentChild(p, c),
          delayMs: options.enrichProviderDelayMs?.["RockyRaccoon"] ?? options.enrichDelayMs,
          jitterMs: options.enrichJitterMs,
          retry: { retries: options.enrichRetries, backoffMs: options.enrichRetryBackoffMs },
          maxChecks: options.enrichMaxIocs,
          force,
        });
        merged = { ...merged, forensicTimeline: events };
        chainSummary = cs;
      }

        await options.stateStore!.save(merged);
        options.onState?.(merged);
        return { chainSummary };
      });
      const chainNote = chainSummary ? `; chains ${chainSummary.anomalies} anomalous/${chainSummary.checked}` : "";
      const skipNote = summary.unavailable.length ? `; skipped ${summary.unavailable.join(", ")} (unreachable — will retry)` : "";
      if (job) options.jobManager?.finish(job.jobId); // no-op if a cancel already marked it cancelled
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `enriched ${summary.withHits}/${summary.queried} (errors ${summary.errors})${chainNote}${skipNote}` });
    })().catch((err) => {
      if (job) options.jobManager?.fail(job.jobId, err); // no-op if already terminal (cancelled)
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
    });
  }

  // After IOCs change (synthesis/import), enrich the new ones if the toggle is on. The
  // cache means already-enriched IOCs are skipped, so this only queries fresh indicators.
  function autoEnrichIfEnabled(caseId: string): void {
    if (allProviders.length === 0) return;
    enabledProvidersFor(caseId).then((ps) => { if (ps.length > 0) enrichInBackground(caseId); }).catch(() => {});
  }

  // Background reachability poller (opt-in via enrichHealthPollMs, set by startServer). It only
  // runs while a case is actually waiting on a down provider to recover (enrichPending non-empty):
  // its sole purpose is to resume those cases, so when enrichment is off everywhere it probes
  // nothing and emits no "[enrich] health … DOWN" noise. When it does run it re-probes only the
  // providers currently known-down — cheap — and, when one recovers, resumes the cases that had to
  // skip it. `.unref()` so it never holds the process open; tests don't set the option, so no timer starts.
  if (options.enrichHealthPollMs && options.enrichHealthPollMs > 0 && allProviders.some((p) => p.probe)) {
    let polling = false;   // guard against overlap if a probe round runs long
    const timer = setInterval(() => {
      if (polling) return;
      if (enrichPending.size === 0) return;   // no case waiting on a down provider — nothing to resume, so don't probe (or log)
      const down = allProviders.filter((p) => enrichHealth.peek(p.name)?.ok === false);
      if (down.length === 0) return;   // nothing to recover
      polling = true;
      void (async () => {
        for (const p of down) { enrichHealth.invalidate(p.name); await enrichHealth.check(p); }
        const recovered = down.some((p) => enrichHealth.peek(p.name)?.ok === true);
        if (recovered && enrichPending.size > 0) {
          const cases = [...enrichPending];
          enrichPending.clear();
          logLine(`[enrich] health recovered — resuming ${cases.length} case(s)`);
          for (const c of cases) enrichInBackground(c);
        }
      })().catch(() => {}).finally(() => { polling = false; });
    }, options.enrichHealthPollMs);
    timer.unref?.();
  }

  function resynthesizeInBackground(caseId: string): void {
    const pipeline = options.pipeline;
    if (!pipeline) return;
    // synthesize() is TEXT work — gate on the synthesis provider (which falls back to the vision
    // provider), not hasAiProvider(): an OCR-less install (only DFIR_AI_SYNTH_PROVIDER set) must
    // still re-synthesize after imports/mutations.
    if (!pipeline.hasSynthesisProvider()) { autoEnrichIfEnabled(caseId); return; }
    void (async () => {
      // Synthesis is an LLM call — respect the per-case AI toggle, exactly like the /captures
      // path (AI analysis only runs when enabled for the case). With AI off, a deterministic
      // import still populates the forensic timeline + IOCs; it just doesn't trigger LLM
      // synthesis — findings / attacker-path / MITRE wait until AI is turned on and the case is
      // re-synthesized. Enrichment is a separate, independently-gated feature (threat-intel
      // lookups, not an LLM call), so it still runs regardless of the AI toggle.
      if (!(await getControl(caseId)).enabled) { autoEnrichIfEnabled(caseId); return; }
      // #225: track synthesis as a cancellable job so the dashboard can list it + abort a long/stuck run.
      const job = options.jobManager?.register({ caseId, kind: "synthesis", label: "re-synthesis", cancellable: true });
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "re-synthesizing without legitimate items" });
      try {
        await pipeline.synthesize(caseId, job?.signal ? { signal: job.signal } : {});
        if (job) options.jobManager?.finish(job.jobId);
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        autoEnrichIfEnabled(caseId);
      } catch (err) {
        const aborted = job?.signal?.aborted === true;
        if (job) options.jobManager?.fail(job.jobId, err); // no-op if the job was already cancelled
        options.onAiStatus?.(caseId, aborted
          ? { status: "idle", at: new Date().toISOString(), detail: "synthesis cancelled" }
          : { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      }
    })();
  }

  // #76: snapshot the PRE-import investigation state (findings + IOCs + timeline + MITRE + attacker
  // path — everything the import and its synthesis change) onto the per-case undo stack so the whole
  // import can be rolled back. Best-effort — undo is a convenience and must NEVER break the import.
  // Callers gate on whether the import actually changed anything (no checkpoint for a no-op re-import).
  async function pushImportCheckpoint(caseId: string, beforeState: InvestigationState, label: string): Promise<void> {
    if (!options.importUndoStore) return;
    try {
      const stack = await options.importUndoStore.load(caseId);
      const next = pushCheckpoint(stack, { label, at: new Date().toISOString(), state: beforeState }, options.importUndoStore.depth());
      await options.importUndoStore.save(caseId, next);
      options.onImportUndo?.(caseId);
    } catch { /* non-fatal */ }
  }

  // ── IOC whitelist (Phase 2 of #35) ─────────────────────────────────────────────────────────
  // A GLOBAL, environment-level set of "known-good" patterns the analyst maintains (internal IP
  // ranges as CIDR, known-good hashes, regexes for internal domains). An IOC matching a rule is
  // auto-marked a FALSE POSITIVE — reusing the false-positive machinery, so it's reversible and
  // shows in the "False Positives" panel. Auto-applied on import; also on demand per case.

  // Apply the whitelist to a case's current IOCs: add a false-positive marker for each match that
  // isn't already marked. Pure read-modify-write on false-positive.json (no re-synthesis here —
  // the caller decides). Returns how many IOCs matched and how many NEW markers were added.
  async function applyWhitelistToCase(caseId: string): Promise<{ matched: number; added: number }> {
    if (!options.iocWhitelistStore || !options.stateStore) return { matched: 0, added: 0 };
    const rules = await options.iocWhitelistStore.load();
    if (rules.length === 0) return { matched: 0, added: 0 };
    const state = await options.stateStore.load(caseId);
    const matches = whitelistMatches(state.iocs, rules);
    if (matches.length === 0) return { matched: 0, added: 0 };
    const markers = await falsePositives.load(caseId);
    const byId = new Map<string, FalsePositiveMarker>(markers.map((m) => [m.id, m]));
    let added = 0;
    for (const { ioc, rule } of matches) {
      const id = markerId("ioc", ioc.value);
      if (byId.has(id)) continue;
      byId.set(id, {
        id, kind: "ioc", ref: ioc.value, reason: "known-good-tool",
        note: `auto-whitelist: ${rule.match} ${rule.pattern}${rule.note ? ` — ${rule.note}` : ""}`,
        markedAt: new Date().toISOString(), markedBy: "anonymous", label: ioc.value,
      });
      added++;
    }
    if (added > 0) await falsePositives.save(caseId, [...byId.values()]);
    return { matched: matches.length, added };
  }

  // Apply the deobfuscation pass to a case: scan the forensic timeline for obfuscated command
  // lines (PowerShell -enc, base64 blobs), decode them, extract hidden IOCs, and persist.
  // Pure read-modify-write on state.json (no re-synthesis here — the caller decides).
  // Returns how many events were decoded and how many new IOCs were extracted.
  async function applyDeobfuscationToCase(caseId: string): Promise<{ deobfuscated: number; newIocs: number }> {
    if (!options.stateStore) return { deobfuscated: 0, newIocs: 0 };
    return runStateExclusive(caseId, async () => {
      const state = await options.stateStore!.load(caseId);
      const result = applyDeobfuscation(state);
      if (result.deobfuscated === 0 && result.newIocs === 0) return { deobfuscated: 0, newIocs: 0 };
      await options.stateStore!.save(result.state);
      options.onState?.(result.state);
      return { deobfuscated: result.deobfuscated, newIocs: result.newIocs };
    });
  }

  // ── NSRL known-good hashes (#63) ───────────────────────────────────────────────────────────────
  // A GLOBAL set of known-software file hashes (NIST NSRL / RDS). A forensic event whose file hash —
  // or an IOC whose value — is in the set is a known-good file, auto-marked a FALSE POSITIVE to
  // reduce noise. Reuses the false-positive machinery (reversible, shown in "False Positives").
  // Auto-applied on import; also on demand per case. Opt-in (the set starts empty).

  // Sweep a case's current IOCs + forensic events for NSRL matches, adding a false-positive marker
  // for each that isn't already marked (ioc → by value, event → by id, so the raw evidence is
  // preserved and un-marking restores it). Pure read-modify-write on false-positive.json (no
  // re-synthesis here — the caller decides). Returns how many IOCs/events matched and how many NEW
  // markers were added.
  async function applyNsrlToCase(caseId: string): Promise<{ matchedIocs: number; matchedEvents: number; added: number }> {
    if (!options.stateStore) return { matchedIocs: 0, matchedEvents: 0, added: 0 };
    // A hash is known-good if EITHER backend has it: the flat in-memory set (small custom lists) or
    // the on-demand SQLite RDS (the full ~160 GB set).
    const flat = options.nsrlStore ? await options.nsrlStore.load() : undefined;
    const haveFlat = Boolean(flat && flat.size > 0);
    if (!haveFlat && !nsrlDb) return { matchedIocs: 0, matchedEvents: 0, added: 0 };
    const lookup = (h: string): boolean => (flat?.has(h) ?? false) || (nsrlDb?.has(h) ?? false);
    const state = await options.stateStore.load(caseId);
    const iocMatches = nsrlMatchIocs(state.iocs, lookup);
    const eventMatches = nsrlMatchEvents(state.forensicTimeline, lookup);
    if (iocMatches.length === 0 && eventMatches.length === 0) return { matchedIocs: 0, matchedEvents: 0, added: 0 };
    const markers = await falsePositives.load(caseId);
    const byId = new Map<string, FalsePositiveMarker>(markers.map((m) => [m.id, m]));
    const now = new Date().toISOString();
    let added = 0;
    for (const { ioc, hash } of iocMatches) {
      const id = markerId("ioc", ioc.value);
      if (byId.has(id)) continue;
      byId.set(id, { id, kind: "ioc", ref: ioc.value, reason: "known-good-tool", note: `NSRL known-good hash (${hash})`, markedAt: now, markedBy: "anonymous", label: ioc.value });
      added++;
    }
    for (const { event, hash } of eventMatches) {
      const id = markerId("event", event.id);
      if (byId.has(id)) continue;
      byId.set(id, { id, kind: "event", ref: event.id, reason: "known-good-tool", note: `NSRL known-good file (${hash})`, markedAt: now, markedBy: "anonymous", label: event.description });
      added++;
    }
    if (added > 0) await falsePositives.save(caseId, [...byId.values()]);
    return { matchedIocs: iocMatches.length, matchedEvents: eventMatches.length, added };
  }

  // Per-case playbook derivation helpers (issue #36). The playbook + hunt-suggestion/outcome ROUTES
  // moved to routes/playbookHunts.ts; these two helpers stay because the POST /cases/:id/push/iris
  // route below also calls syncPlaybook. Hoisted `function` declarations so they can be bound onto ctx
  // (above, before their textual definition) as stable methods for the moved routes.
  async function loadPlaybookControl(caseId: string): Promise<PlaybookControl> {
    return options.playbookControlStore ? options.playbookControlStore.load(caseId) : { ...DEFAULT_PLAYBOOK_CONTROL };
  }

  // Re-derive against current state honoring the case's template setting (no-op-safe write).
  async function syncPlaybook(caseId: string): Promise<PlaybookTask[]> {
    if (!options.playbookStore || !options.stateStore) return options.playbookStore ? options.playbookStore.load(caseId) : [];
    const state = await options.stateStore.load(caseId);
    const { useTemplates } = await loadPlaybookControl(caseId);
    return options.playbookStore.sync(caseId, state, { useTemplates });
  }

  // Re-arm any persisted live Velociraptor monitors so streaming survives a restart (#84). Fire-and-
  // forget + self-gating (no store/client or no persisted monitors → no-op), so it's a safe no-op for
  // tests and embeddings that don't use monitoring.
  void resumeVeloMonitors();
  void resumeVeloHuntStatusPolls();

  // Arm the evidence drop-folder watcher (auto-import inbox). Gated on the status store being wired
  // (startServer), so createApp-only unit tests never start a filesystem poller.
  if (dropWatchEnabled && options.dropStatusStore) startDropWatcher();

  // Whitelisted static client assets: vendored libraries (Leaflet for the Geographic map, #133;
  // cytoscape+dagre for the graphs) plus first-party browser modules (the shared graph-view module
  // used by the Login/Assets/Evidence graphs). Whitelisted paths only.
  // Registered inside createApp so the routes are available in tests (startServer calls createApp).
  const vendorFiles: Record<string, string> = {
    "/vendor/leaflet/leaflet.js": "application/javascript; charset=utf-8",
    "/vendor/leaflet/leaflet.css": "text/css; charset=utf-8",
    "/vendor/cytoscape/cytoscape.min.js": "application/javascript; charset=utf-8",
    "/vendor/cytoscape/dagre.min.js": "application/javascript; charset=utf-8",
    "/vendor/cytoscape/cytoscape-dagre.js": "application/javascript; charset=utf-8",
    "/js/graph-view.js": "application/javascript; charset=utf-8",
  };
  for (const [route, type] of Object.entries(vendorFiles)) {
    app.get(route, async (_req, res) => {
      try {
        const buf = await readPublicAsset(route.slice(1)); // strip leading "/"
        res.type(type).set("Cache-Control", "public, max-age=86400").send(buf);
      } catch {
        res.status(404).end();
      }
    });
  }

  // Terminal error handler (4-arg, last-registered so it runs after every route). express-async-errors
  // forwards any error thrown or rejected inside an async route here; explicit next(err) calls land here
  // too. Without it, Express 4 would fall through to its default handler and leak an HTML stack-trace page
  // — or, for async routes it never catches, hang the connection. The failure is always logged (never
  // silently swallowed); ZodError/CaseNotFoundError keep their conventional 400/404 for routes that forgot
  // their own try/catch, and everything else becomes a generic JSON 500 so the client always gets a clean,
  // closed response. Per-route try/catch blocks still handle their own errors and never reach this.
  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    if (err instanceof ZodError) return res.status(400).json({ error: "invalid payload", details: err.issues });
    if (err instanceof CaseNotFoundError) {
      return res.status(404).json({ error: `case ${err.caseId} does not exist — create it in the dashboard first` });
    }
    const message = err instanceof Error ? err.message : String(err);
    serverLogger.error(`unhandled error on ${req.method} ${req.path}: ${message}`);
    return res.status(500).json({ error: "internal server error" });
  });

  return app;
}

import { StateStore as StateStoreImpl } from "./analysis/stateStore.js";
import { AnalysisPipeline as AnalysisPipelineImpl } from "./analysis/pipeline.js";
import { makeImageLoader } from "./analysis/imageLoader.js";
import { ProviderRegistry, ProviderError } from "./providers/provider.js";
import type { AIProvider as AnalyzeProvider } from "./providers/provider.js";
import { visionEnv } from "./config/aiEnv.js";
import { OpenAIProvider } from "./providers/openai.js";
import { OpenRouterProvider } from "./providers/openrouter.js";
import { OllamaCloudProvider } from "./providers/ollama.js";
import { LiteLlmProvider } from "./providers/litellm.js";
import { GeminiProvider } from "./providers/gemini.js";
import { AnthropicProvider } from "./providers/anthropic.js";
import { ClaudeCodeProvider } from "./providers/claudeCode.js";
import { CodexProvider } from "./providers/codex.js";
import { WebSocketServer } from "ws";
import { LiveHub } from "./live/hub.js";
import { ReportWriter as ReportWriterImpl } from "./reports/reportWriter.js";

export interface ProviderParams {
  provider?: string;
  model?: string;
  apiKey?: string;
  imageDetail?: "high" | "low" | "auto";
  timeoutMs?: number;
  maxTokens?: number;
  // The model's context window (tokens) for the provider's pre-flight guard. Defaults from
  // DFIR_AI_CONTEXT_TOKENS (or 128000) so an oversized prompt is trimmed/clearly-errored.
  contextTokens?: number;
  // Override the provider's API base URL. Required for a self-hosted LiteLLM proxy
  // (and any OpenAI-compatible local endpoint); each provider keeps its own default
  // when this is unset. Empty string is treated as unset.
  baseUrl?: string;
}

// Build a provider from explicit params (so callers can build more than one,
// e.g. a cheap extraction model + a stronger synthesis model).
export function buildProviderFrom(params: ProviderParams): AnalyzeProvider | undefined {
  const name = params.provider;
  if (!name) return undefined;
  const model = params.model ?? "";
  const apiKey = params.apiKey ?? "";
  const imageDetail = params.imageDetail ?? "high";
  // Empty string → undefined so each provider falls back to its built-in default.
  const baseUrl = params.baseUrl?.trim() || undefined;
  // Strong models over a large timeline can take >60s — make the request timeout tunable.
  const timeoutMs = params.timeoutMs ?? (Number(process.env.DFIR_AI_TIMEOUT_MS) || 180_000);
  // Bound completion tokens. Without this, OpenRouter reserves the model's full max
  // output for its per-request credit check and can 402 a large request (e.g. THOR
  // synthesis) even when the account has credits. Tunable via DFIR_AI_MAX_TOKENS.
  const maxTokens = params.maxTokens ?? (Number(process.env.DFIR_AI_MAX_TOKENS) || 16000);
  // Context window for the pre-flight guard — same default the pipeline budgets against, so
  // a too-big prompt is trimmed by the pipeline and, as a backstop, caught here before the API.
  const contextTokens = params.contextTokens ?? resolveContextTokens();
  const registry = new ProviderRegistry();
  registry.register(new OpenAIProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new OpenRouterProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new OllamaCloudProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new LiteLlmProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new GeminiProvider({ apiKey, model, baseUrl, timeoutMs, maxTokens }));
  registry.register(new AnthropicProvider({ apiKey, model, baseUrl, timeoutMs, maxTokens }));
  registry.register(new ClaudeCodeProvider({ model, timeoutMs, bin: process.env.DFIR_AI_CLAUDE_CODE_BIN }));
  registry.register(new CodexProvider({ model, timeoutMs, bin: process.env.DFIR_AI_CODEX_BIN }));
  return registry.get(name);
}

export function buildProvider(): AnalyzeProvider | undefined {
  // Vision/screenshot model — DFIR_VISION_* (legacy DFIR_AI_* still honored via visionEnv).
  return buildProviderFrom({
    provider: visionEnv(process.env, "PROVIDER"),
    model: visionEnv(process.env, "MODEL"),
    apiKey: visionEnv(process.env, "KEY"),
    baseUrl: visionEnv(process.env, "BASE_URL"),
    imageDetail: visionEnv(process.env, "IMAGE_DETAIL") as "high" | "low" | "auto" | undefined,
  });
}

// Synthesis model: dedicated DFIR_AI_SYNTH_* vars, falling back to the main model.
export function buildSynthesisProvider(): AnalyzeProvider | undefined {
  // Text model — DFIR_AI_SYNTH_*, falling back to the vision model's config (DFIR_VISION_*, legacy
  // DFIR_AI_* via visionEnv) when a dedicated synth var is unset.
  return buildProviderFrom({
    provider: process.env.DFIR_AI_SYNTH_PROVIDER ?? visionEnv(process.env, "PROVIDER"),
    model: process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL"),
    apiKey: process.env.DFIR_AI_SYNTH_KEY ?? visionEnv(process.env, "KEY"),
    baseUrl: process.env.DFIR_AI_SYNTH_BASE_URL ?? visionEnv(process.env, "BASE_URL"),
    imageDetail: visionEnv(process.env, "IMAGE_DETAIL") as "high" | "low" | "auto" | undefined,
  });
}

// Second-opinion model (issue #116): a DEDICATED, DIFFERENT model for the on-demand QA cross-check.
// Returns undefined UNLESS DFIR_AI_SECOND_OPINION_MODEL is set — that env var IS the opt-in, and its
// absence disables the feature (route 501, dashboard button hidden). Recommend a model from a
// DIFFERENT provider than the primary synthesis model so the opinion is genuinely independent; the
// key/provider/baseUrl fall back to the main AI config so it works out of the box on one account.
export function buildSecondOpinionProvider(): AnalyzeProvider | undefined {
  const model = process.env.DFIR_AI_SECOND_OPINION_MODEL?.trim();
  if (!model) return undefined;
  return buildProviderFrom({
    provider: process.env.DFIR_AI_SECOND_OPINION_PROVIDER ?? visionEnv(process.env, "PROVIDER"),
    model,
    apiKey: process.env.DFIR_AI_SECOND_OPINION_KEY ?? visionEnv(process.env, "KEY"),
    baseUrl: process.env.DFIR_AI_SECOND_OPINION_BASE_URL ?? visionEnv(process.env, "BASE_URL"),
  });
}

// Velociraptor-hunt model (issue #70): a DEDICATED model just for generating Velociraptor VQL hunts
// (suggestPlaybookHunts + suggestHunts), since many models botch VQL. Defaults to openrouter /
// anthropic/claude-haiku-latest regardless of the main/synth provider; the key falls back to the main
// AI key (so it works out of the box when the main provider is openrouter). The pipeline uses this
// over the synthesis/main provider for hunt generation only.
export const DEFAULT_VELO_PROVIDER = "openrouter";
export const DEFAULT_VELO_MODEL = "anthropic/claude-haiku-4.5";   // latest Haiku; a VALID OpenRouter id (claude-haiku-latest 400s there)
export function buildVelociraptorProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_VELO_PROVIDER?.trim() || DEFAULT_VELO_PROVIDER,
    model: process.env.DFIR_AI_VELO_MODEL?.trim() || DEFAULT_VELO_MODEL,
    apiKey: process.env.DFIR_AI_VELO_KEY ?? visionEnv(process.env, "KEY"),
    baseUrl: process.env.DFIR_AI_VELO_BASE_URL ?? visionEnv(process.env, "BASE_URL"),
  });
}

// Build the threat-intel enrichment providers from env. Each is added only when its key
// is present (MalwareBazaar needs DFIR_MB_KEY for its API). Empty array → enrichment off.
// Optional per-provider TLS trust for a self-hosted intel host with an internal-CA or
// self-signed cert. Returns undefined (→ default, fully-verified global fetch) unless a
// DFIR_<NAME>_CA bundle or DFIR_<NAME>_INSECURE flag is set. Scoped to that provider only.
function tlsFetchFor(name: "MISP" | "YETI" | "OPENCTI" | "IRIS" | "TIMESKETCH" | "NOTION" | "CLICKUP" | "NOTIFY") {
  return buildTlsFetch({
    caCertPath: process.env[`DFIR_${name}_CA`],
    insecureSkipVerify: isEnvFlag(process.env[`DFIR_${name}_INSECURE`]),
    onWarn: (m) => warnLine(`[DFIR] ${name}: ${m}`),
  });
}

function isEnvFlag(value: string | undefined): boolean {
  return /^(1|true|yes|on)$/i.test(value ?? "");
}

// Build the DFIR-IRIS push client from env (DFIR_IRIS_URL + DFIR_IRIS_KEY). Returns
// undefined when not configured, which hides the dashboard's "Push to IRIS" button.
// TLS trust for a self-hosted IRIS honors DFIR_IRIS_CA / DFIR_IRIS_INSECURE.
export function buildIrisClient(): IrisClient | undefined {
  const baseUrl = process.env.DFIR_IRIS_URL;
  const apiKey = process.env.DFIR_IRIS_KEY;
  if (!baseUrl || !apiKey) return undefined;
  return new IrisClient({ baseUrl, apiKey, fetchFn: tlsFetchFor("IRIS") });
}

export function irisPushOptions(): IrisPushOptions {
  return {
    baseUrl: process.env.DFIR_IRIS_URL,
    customerId: Number(process.env.DFIR_IRIS_CUSTOMER_ID) || undefined,
    classificationId: Number(process.env.DFIR_IRIS_CLASSIFICATION_ID) || undefined,
  };
}

// Build the Timesketch push client from env (DFIR_TIMESKETCH_URL + USER + PASSWORD). Returns
// undefined when not configured, which hides the dashboard's "Push to Timesketch" button. TLS
// trust for a self-hosted Timesketch honors DFIR_TIMESKETCH_CA / DFIR_TIMESKETCH_INSECURE.
export function buildTimesketchClient(): TimesketchClient | undefined {
  const baseUrl = process.env.DFIR_TIMESKETCH_URL;
  const username = process.env.DFIR_TIMESKETCH_USER;
  const password = process.env.DFIR_TIMESKETCH_PASSWORD;
  if (!baseUrl || !username || !password) return undefined;
  return new TimesketchClient({ baseUrl, username, password, fetchFn: tlsFetchFor("TIMESKETCH") });
}

export function timesketchPushOptions(): TimesketchPushOptions {
  return {
    baseUrl: process.env.DFIR_TIMESKETCH_URL,
    timelineName: process.env.DFIR_TIMESKETCH_TIMELINE || undefined,
  };
}

// Build the MISP push client from env (DFIR_MISP_URL + DFIR_MISP_KEY). Returns undefined
// when not configured, which hides the dashboard's "Push to MISP" button. TLS trust for a
// self-hosted MISP honors DFIR_MISP_CA / DFIR_MISP_INSECURE (same env vars as enrichment).
export function buildMispPushClient(): MispPushClient | undefined {
  const baseUrl = process.env.DFIR_MISP_URL;
  const apiKey = process.env.DFIR_MISP_KEY;
  if (!baseUrl || !apiKey) return undefined;
  return new MispPushClient({ baseUrl, apiKey, fetchFn: tlsFetchFor("MISP") });
}

export function mispPushOptions(): MispPushOptions {
  return {
    baseUrl: process.env.DFIR_MISP_URL,
    distribution: process.env.DFIR_MISP_DISTRIBUTION || undefined,
    analysis: process.env.DFIR_MISP_ANALYSIS || undefined,
  };
}

// Build the Notion export client from env (DFIR_NOTION_TOKEN). Returns undefined when not
// configured, which hides the dashboard's "Export to Notion" option. Notion is public SaaS, so
// tlsFetchFor("NOTION") is a no-op unless DFIR_NOTION_CA / DFIR_NOTION_INSECURE are set.
export function buildNotionClient(): NotionClient | undefined {
  const token = process.env.DFIR_NOTION_TOKEN;
  if (!token) return undefined;
  return new NotionClient({ token, fetchFn: tlsFetchFor("NOTION") });
}

export function notionPushOptions(): NotionPushOptions {
  return {
    baseUrl: "https://www.notion.so",
    // Same normalization the request-body page/parent/database fields go through
    // (routes/caseLifecycle.ts parseNotionPageId calls) — an operator's .env value is commonly a
    // full Notion URL, not a bare id, and the client-facing API rejects the unparsed URL.
    parentPageId: parseNotionPageId(process.env.DFIR_NOTION_PARENT_PAGE_ID ?? "") ?? undefined,
    databaseId: parseNotionPageId(process.env.DFIR_NOTION_DATABASE_ID ?? "") ?? undefined,
    containerTitle: process.env.DFIR_NOTION_CONTAINER_TITLE || undefined,
    maxTimelineRows: Number(process.env.DFIR_NOTION_MAX_TIMELINE) || undefined,
  };
}

// Build the ClickUp client from env (DFIR_CLICKUP_TOKEN). Returns undefined when not configured,
// which hides the dashboard's "Push to ClickUp" option. An optional DFIR_CLICKUP_LIST_ID is the
// default target list (the analyst can still override it per push).
export function buildClickUpClient(): ClickUpClient | undefined {
  const token = process.env.DFIR_CLICKUP_TOKEN;
  if (!token) return undefined;
  return new ClickUpClient({ token, fetchFn: tlsFetchFor("CLICKUP") });
}

export function clickupOptions(): { defaultListId?: string } {
  return { defaultListId: process.env.DFIR_CLICKUP_LIST_ID || undefined };
}

export function buildEnrichmentProviders(): EnrichmentProvider[] {
  const providers: EnrichmentProvider[] = [];
  if (process.env.DFIR_VT_KEY) providers.push(new VirusTotalProvider({ apiKey: process.env.DFIR_VT_KEY }));
  // Hunting.ch — the abuse.ch unified hunt (MalwareBazaar + ThreatFox + URLhaus + YARAify).
  // There's no separate MalwareBazaar source anymore: MalwareBazaar is one of its back-ends.
  // Uses the ONE abuse.ch Auth-Key; DFIR_MB_KEY (the legacy name for that key) still works.
  const abuseChKey = process.env.DFIR_HUNTINGCH_KEY || process.env.DFIR_MB_KEY;
  if (abuseChKey) providers.push(new HuntingChProvider({ apiKey: abuseChKey }));
  // CrowdStrike Falcon — Threat Intelligence only (Falcon Intelligence Indicators + MalQuery).
  if (process.env.DFIR_CROWDSTRIKE_CLIENT_ID && process.env.DFIR_CROWDSTRIKE_CLIENT_SECRET) {
    providers.push(new CrowdStrikeProvider({
      clientId: process.env.DFIR_CROWDSTRIKE_CLIENT_ID,
      clientSecret: process.env.DFIR_CROWDSTRIKE_CLIENT_SECRET,
      cloud: process.env.DFIR_CROWDSTRIKE_CLOUD,
      baseUrl: process.env.DFIR_CROWDSTRIKE_BASE_URL,
    }));
  }
  if (process.env.DFIR_ABUSEIPDB_KEY) providers.push(new AbuseIpdbProvider({ apiKey: process.env.DFIR_ABUSEIPDB_KEY }));
  if (process.env.DFIR_MISP_URL && process.env.DFIR_MISP_KEY) providers.push(new MispProvider({ baseUrl: process.env.DFIR_MISP_URL, apiKey: process.env.DFIR_MISP_KEY, fetchFn: tlsFetchFor("MISP") }));
  if (process.env.DFIR_ROCKYRACCOON_KEY) providers.push(new RockyRaccoonProvider({ apiKey: process.env.DFIR_ROCKYRACCOON_KEY }));
  if (process.env.DFIR_YETI_URL && process.env.DFIR_YETI_KEY) providers.push(new YetiProvider({ baseUrl: process.env.DFIR_YETI_URL, apiKey: process.env.DFIR_YETI_KEY, fetchFn: tlsFetchFor("YETI") }));
  if (process.env.DFIR_OPENCTI_URL && process.env.DFIR_OPENCTI_KEY) {
    const octiScore = Number(process.env.DFIR_OPENCTI_MALICIOUS_SCORE);
    providers.push(new OpenCtiProvider({
      baseUrl: process.env.DFIR_OPENCTI_URL,
      apiKey: process.env.DFIR_OPENCTI_KEY,
      fetchFn: tlsFetchFor("OPENCTI"),
      maliciousScore: Number.isFinite(octiScore) && octiScore > 0 ? octiScore : undefined,
    }));
  }
  // CIRCL hashlookup (#154): free, keyless KNOWN-FILE lookup for hash IOCs — the known-good
  // angle that complements VirusTotal / Hunting.ch (a hit confirms a known, legitimate file).
  // Always available; `external` scope → opt-in per case. Base URL overridable for a self-hosted
  // / air-gapped mirror via DFIR_HASHLOOKUP_URL.
  providers.push(new HashlookupProvider({ baseUrl: process.env.DFIR_HASHLOOKUP_URL }));
  // IP-infrastructure context providers (#134): reverse DNS, WHOIS-over-RDAP, and GeoIP need
  // NO API key, so they're always available — but, like all `external` providers, they're
  // opt-in per case (default OFF), so nothing is looked up off-box without analyst approval.
  // Base/endpoint overridable via env for self-hosted/paid backends or an air-gapped mirror.
  providers.push(new ReverseDnsProvider());
  // Offline lookalike / typosquat domain check — local scope (nothing leaves the box), so it is
  // enabled by default and flags domain IOCs that imitate a bundled brand list (+ env extras).
  providers.push(new LookalikeDomainProvider());
  providers.push(new RdapProvider({ baseUrl: process.env.DFIR_RDAP_URL }));
  providers.push(new GeoIpProvider({ baseUrl: process.env.DFIR_GEOIP_URL, apiKey: process.env.DFIR_GEOIP_KEY }));
  // Shodan host lookup (hosted domains / open ports / services / CVEs) reuses the existing
  // DFIR_SHODAN_KEY (also used by the customer-exposure attack-surface check).
  if (process.env.DFIR_SHODAN_KEY) providers.push(new ShodanProvider({ apiKey: process.env.DFIR_SHODAN_KEY }));
  return providers;
}

// Build a per-provider delay map from `DFIR_ENRICH_DELAY_MS_<PROVIDER>` env vars.
// Keys must match the `provider.name` strings used in enrichService.
export function buildEnrichProviderDelayMap(): Record<string, number> | undefined {
  const entries: Array<[string, string]> = [
    ["VIRUSTOTAL", "VirusTotal"],
    ["ABUSEIPDB", "AbuseIPDB"],
    ["HUNTINGCH", "Hunting.ch"],
    ["CROWDSTRIKE", "CrowdStrike"],
    ["ROCKYRACCOON", "RockyRaccoon"],
    ["MISP", "MISP"],
    ["YETI", "YETI"],
    ["OPENCTI", "OpenCTI"],
    ["REVERSE_DNS", "Reverse DNS"],
    ["WHOIS", "WHOIS"],
    ["GEOIP", "GeoIP"],
    ["SHODAN", "Shodan"],
    ["HASHLOOKUP", "Hashlookup"],
  ];
  const map: Record<string, number> = {};
  for (const [suffix, name] of entries) {
    const v = Number(process.env[`DFIR_ENRICH_DELAY_MS_${suffix}`]);
    if (v > 0) map[name] = v;
  }
  return Object.keys(map).length > 0 ? map : undefined;
}

export function buildCustomerExposureProviders(): CustomerExposureProvider[] {
  const providers: CustomerExposureProvider[] = [];
  if (process.env.DFIR_LEAKCHECK_KEY) {
    providers.push(new LeakCheckExposureProvider({
      apiKey: process.env.DFIR_LEAKCHECK_KEY,
      domainLimit: Number(process.env.DFIR_LEAKCHECK_DOMAIN_LIMIT) || undefined,
    }));
  }
  if (process.env.DFIR_DEHASHED_KEY) {
    providers.push(new DeHashedExposureProvider({
      apiKey: process.env.DFIR_DEHASHED_KEY,
      baseUrl: process.env.DFIR_DEHASHED_BASE_URL,
    }));
  }
  if (process.env.DFIR_HIBP_KEY) {
    providers.push(new HaveIBeenPwnedExposureProvider({
      apiKey: process.env.DFIR_HIBP_KEY,
      userAgent: process.env.DFIR_HIBP_USER_AGENT || "DFIR Companion",
    }));
  }
  if (process.env.DFIR_SHODAN_KEY) {
    providers.push(new ShodanExposureProvider({ apiKey: process.env.DFIR_SHODAN_KEY }));
  }
  return providers;
}

export interface RuntimePipelineParams {
  provider?: AnalyzeProvider;
  synthesisProvider?: AnalyzeProvider;
  // Dedicated model for Velociraptor VQL hunt generation (#70); falls back to synthesis/main.
  velociraptorProvider?: AnalyzeProvider;
  stateStore: StateStoreImpl;
  store: CaseStore;
  imageLoader?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["imageLoader"];
  onState?: (state: InvestigationState) => void;
  // Fired after a real synthesis run with the findings diff + new state (issue #58 notifications).
  onSynth?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["onSynth"];
  // Provided only when the AI vision provider is external (not local). See ocrRedact.ts.
  ocrRunner?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["ocrRunner"];
  // Shared logger so AI/OCR/anonymization debug traces land in the same session + per-case logs.
  logger?: Logger;
  // CISA KEV catalog (issue #99): passed to the pipeline so synthesis context includes KEV hits.
  kevStore?: KevStore;
  // Second LLM opinion (issue #116): a different model + its persistence store, plus the model
  // labels for the comparison header. Absent → the feature is disabled (route 501).
  secondOpinionProvider?: AnalyzeProvider;
  secondOpinionStore?: SecondOpinionStore;
  synthesisModelLabel?: string;
  secondOpinionModelLabel?: string;
  stateLock?: StateLock;
}

export function buildRuntimePipeline(params: RuntimePipelineParams): AnalysisPipelineImpl {
  return new AnalysisPipelineImpl({
    provider: params.provider,
    synthesisProvider: params.synthesisProvider,
    velociraptorProvider: params.velociraptorProvider,
    secondOpinionProvider: params.secondOpinionProvider,
    secondOpinionStore: params.secondOpinionStore,
    synthesisModelLabel: params.synthesisModelLabel,
    secondOpinionModelLabel: params.secondOpinionModelLabel,
    stateLock: params.stateLock,
    stateStore: params.stateStore,
    falsePositiveStore: new FalsePositiveStore(params.store),
    scopeStore: new ScopeStore(params.store),
    imageLoader: params.imageLoader ?? makeImageLoader(params.store),
    onState: params.onState,
    onSynth: params.onSynth,
    anonStore: new AnonControlStore(params.store),
    customEntitiesStore: new CustomEntitiesStore(params.store),
    discoveredStore: new DiscoveredEntitiesStore(params.store),
    synthMetaStore: new SynthMetaStore(params.store),
    aiCostStore: new AiCostStore(params.store),
    correlationProfileStore: new CorrelationProfileStore(params.store),
    notebookStore: new NotebookStore(params.store),
    hypothesisStore: new HypothesisStore(params.store),     // #140 auto-generate hypotheses on synthesis
    learnedPatternStore: new LearnedPatternStore(params.store), // #65 feed learned dismissal patterns into synthesis
    sourceTrustStore: new SourceTrustStore(params.store),   // #66 per-source trust weights for merge + confidence
    playbookStore: new PlaybookStore(params.store),         // #2 feed DONE/SKIPPED task status into synthesis
    importMetaStore: new ImportMetaStore(params.store),      // #10 flag a zero-yield AI import as a coverage gap
    aiControlStore: new AiControlStore(params.store),
    huntOutcomeStore: new HuntOutcomeStore(params.store),   // #157 hunting feedback loop
    superTimelineStore: new SuperTimelineStore(params.store, Number(process.env.DFIR_SUPERTIMELINE_MAX) || undefined),  // explainEvent falls back here for raw super-only events
    ocrRunner: params.ocrRunner,
    logger: params.logger,
    kevStore: params.kevStore,
    iocAliasStore: new IocAliasStore(params.store),  // #82: keep analyst IOC merges applied across re-synthesis
  });
}

export function startServer(casesRoot: string, port = 4773, host = "127.0.0.1", logDir?: string): void {
  const demoMode = process.env.DFIR_DEMO_MODE === "true" || process.env.DFIR_DEMO_MODE === "1";
  const store = new CaseStore(casesRoot);
  // File-backed logging: a fresh global SESSION log per server run (session-<ts>.log) PLUS a
  // per-CASE log (cases/<id>/logs/session-<ts>.log) — the investigation audit trail that travels
  // with the case. The global log dir defaults to logs/ beside the cases root but is overridable
  // with DFIR_LOG_DIR (resolved by the caller). Per-case logs always live inside the case dir so
  // the audit trail stays with the case. Colons/dots are stripped from the timestamp so the
  // filename is valid on Windows; a logs/ subdir is always creatable (even when DFIR_CASES_ROOT
  // is a drive-root child like C:\cases). The Settings → Logging toggle changes the level live;
  // DFIR_LOG_LEVEL sets the default.
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
  const stateStore = new StateStoreImpl(store, (caseId, retries) =>
    warnLine(`[state] ${caseId}: investigation.json save needed ${retries} rename retr${retries === 1 ? "y" : "ies"} — the state dir is contended (antivirus / search indexer / sync client). Consider excluding the cases root from real-time scanning, or raise DFIR_ATOMIC_WRITE_RETRIES.`),
  );
  const templateStore = new TemplateStore(join(dirname(casesRoot), "templates"));
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
  const iocWhitelistStore = new IocWhitelistStore(join(dirname(casesRoot), "whitelist", "ioc-whitelist.json"));
  // User-authored declarative importers (#: external plugin layer) — its own subdir beside cases/
  // (same drive-root rationale as the whitelist). Each *.json is one importer spec. The folder is
  // overridable with DFIR_IMPORTERS_DIR (absolute used as-is; relative anchors to the cases-root
  // parent, where the default importers/ lives); unset → importers/ beside the cases root.
  const rawImportersDir = process.env.DFIR_IMPORTERS_DIR;
  const importersDir = rawImportersDir && rawImportersDir.trim() !== ""
    ? (isAbsolute(rawImportersDir) ? rawImportersDir : resolve(dirname(casesRoot), rawImportersDir))
    : join(dirname(casesRoot), "importers");
  const importerStore = new ImporterStore(importersDir);
  // NSRL known-good hash set (#63) — its own subdir next to cases/ (same drive-root rationale as the
  // whitelist). Optionally pre-loaded at startup from file(s) named in DFIR_NSRL_FILE (; separated):
  // an NSRLFile.txt RDS export, a hashdeep CSV, or a plain hash-per-line list. Ingest is idempotent.
  const nsrlStore = new NsrlStore(join(dirname(casesRoot), "nsrl", "known-hashes.txt"));
  // Custom external tools (#211) — a global JSON store in its own subdir beside cases/ (drive-root-safe).
  const customToolStore = new CustomToolStore(join(dirname(casesRoot), "tools", "custom-tools.json"));
  const nsrlFiles = splitNsrlPaths(process.env.DFIR_NSRL_FILE);
  if (nsrlFiles.length > 0) {
    // Fire-and-forget (startServer is sync): ingest in the background via the same helper the
    // Settings → NSRL "Load from file" route uses. The set is opt-in and the auto-apply sweep loads
    // it fresh, so a late finish just means later imports pick it up.
    void ingestNsrlFiles(nsrlStore, nsrlFiles).then((results) => {
      for (const r of results) {
        logLine(r.error
          ? `[nsrl] could not load ${r.file}: ${r.error}`
          : `[nsrl] loaded ${r.file} — +${r.added} new (${r.total} total known-good hashes)`);
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
      logLine(`[nsrl] connected RDS DB ${resolvedNsrlDbPath} — table ${nsrlDb.table}, columns ${nsrlDb.columns.join("/")}`);
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
  const notificationStore = new NotificationConfigStore(join(dirname(casesRoot), "notifications", "config.json"));
  const notifier = createNotifier({
    store: notificationStore,
    fetchFn: tlsFetchFor("NOTIFY") ?? fetch,
    smtpConnect: nodeSmtpConnect,
    log: (m) => logLine(m),
  });
  // Deep-link notifications back to the dashboard. Override the host/port guess with DFIR_PUBLIC_URL.
  const dashboardBaseUrl = (process.env.DFIR_PUBLIC_URL || `http://${host}:${port}`).replace(/\/+$/, "");
  const veloHuntStore = new VeloHuntStore(store);
  const huntOutcomeStore = new HuntOutcomeStore(store);   // #157 hunting feedback loop ledger
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
  const velociraptorClientStore = new VelociraptorClientStore(join(dirname(casesRoot), "velociraptor", "clients.json"));
  const hub = new LiveHub();
  // #225: background-job registry. onJob WS-broadcasts job_changed so the dashboard Jobs panel
  // re-fetches; capped by DFIR_JOBS_MAX (oldest terminal jobs evicted).
  const jobManager = new JobManager({
    onJob: (caseId) => hub.broadcastTo(caseId, { type: "job_changed" }),
    max: Number(process.env.DFIR_JOBS_MAX) || undefined,
  });
  const reportMetaStore = new ReportMetaStore(store);
  const reportTemplateControlStore = new ReportTemplateControlStore(store);
  const activityLogStore = new ActivityLogStore(store);
  const commentsStore = new CommentsStore(store);
  const tagsStore = new TagsStore(store);
  const pinnedFindingsStore = new PinnedFindingsStore(store, Number(process.env.DFIR_MAX_PINNED_FINDINGS) || undefined);
  const findingWorkflowStore = new FindingWorkflowStore(store);
  const notebookStore = new NotebookStore(store);
  const hypothesisStore = new HypothesisStore(store);
  const learnedPatternStore = new LearnedPatternStore(store);
  const sourceTrustStore = new SourceTrustStore(store);
  const dwellWindowStore = new DwellWindowStore(store);
  const superTimelineStore = new SuperTimelineStore(store, Number(process.env.DFIR_SUPERTIMELINE_MAX) || undefined);
  const starredReportStore = new StarredReportStore(store);
  const forensicGateControlStore = new ForensicGateControlStore(store);
  const confidenceControlStore = new ConfidenceControlStore(store);
  const playbookStore = new PlaybookStore(store);
  const playbookHuntStore = new PlaybookHuntStore(store);
  const playbookControlStore = new PlaybookControlStore(store);
  const assetOverridesStore = new AssetOverridesStore(store);
  const iocAliasStore = new IocAliasStore(store);   // #82: analyst IOC merges (survive re-synthesis)
  const synthMetaStore = new SynthMetaStore(store);
  const aiCostStore = new AiCostStore(store);
  const correlationProfileStore = new CorrelationProfileStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const dropStatusStore = new DropStatusStore(store);   // evidence drop-folder last-sweep summary
  // #76: import undo/redo. Depth is the number of import levels kept (each = a full timeline+IOC copy).
  const importUndoStore = new ImportUndoStore(store, Number(process.env.DFIR_IMPORT_UNDO_DEPTH) || undefined);
  const notionExportStore = new NotionExportStore(store);
  const clickupExportStore = new ClickUpExportStore(store);
  const irisExportStore = new IrisExportStore(store);
  const lateralPathDismissStore = new LateralPathDismissStore(store);
  const reportWriter = new ReportWriterImpl(store, stateStore, new ScopeStore(store), new FalsePositiveStore(store), reportMetaStore, new CustomerExposureStore(store), notebookStore, assetOverridesStore, playbookStore, reportTemplateStore, reportTemplateControlStore, kevStore, hypothesisStore, synthMetaStore, lateralPathDismissStore);

  // Automatic state backup (#180): snapshot SNAPSHOT_STATE_FILES before synthesis + on a timer.
  const backupConfig = resolveBackupConfig(process.env);
  const backupManager = new BackupManager(store, backupConfig);
  if (backupConfig.intervalMs > 0) {
    // Time-based: only back up cases that have changed since the last scheduled backup.
    const lastScheduledBackupAt = new Map<string, number>();
    const runScheduledBackups = async (): Promise<void> => {
      const cases = await store.listCases().catch(() => []);
      for (const c of cases) {
        const invPath = join(store.stateDir(c.caseId), "investigation.json");
        let mtime: number;
        try {
          mtime = (await stat(invPath)).mtimeMs;
        } catch {
          continue; // case has no investigation.json yet
        }
        const lastAt = lastScheduledBackupAt.get(c.caseId) ?? 0;
        if (mtime > lastAt) {
          try {
            await backupManager.createBackup(c.caseId, "scheduled");
            lastScheduledBackupAt.set(c.caseId, Date.now());
          } catch (e) {
            logLine(`[backup] scheduled backup for ${c.caseId} failed: ${(e as Error).message}`);
          }
        }
      }
    };
    const backupTimer = setInterval(() => { void runScheduledBackups(); }, backupConfig.intervalMs);
    backupTimer.unref();
    logLine(`[backup] automatic backups every ${backupConfig.intervalMs / 1000}s (retain ${backupConfig.retain})`);
  }

  const provider = buildProvider();
  const synthesisProvider = buildSynthesisProvider();
  const velociraptorProvider = buildVelociraptorProvider();   // dedicated VQL-hunt model (#70)
  const secondOpinionProvider = buildSecondOpinionProvider(); // dedicated second-opinion model (#116)
  // Model labels for the second-opinion comparison header (fall back to provider name in the pipeline).
  const synthesisModelLabel = process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL") ?? undefined;
  const secondOpinionModelLabel = process.env.DFIR_AI_SECOND_OPINION_MODEL?.trim() || undefined;
  if (secondOpinionProvider) logLine(`[second-opinion] enabled — model "${secondOpinionModelLabel}" (${secondOpinionProvider.name})`);
  // Provide the Tesseract OCR runner only when the vision model is on an external (cloud)
  // provider — if the model is local, screenshots never leave the machine so redaction is
  // optional. Evidence-first: the runner only redacts the in-memory copy sent to the model.
  const visionIsLocalForPipeline = isLocalAiProvider(visionEnv(process.env, "PROVIDER"), visionEnv(process.env, "BASE_URL"));
  const ocrRunner = !visionIsLocalForPipeline ? new TesseractOcrRunner() : undefined;
  const wiredPipeline = buildRuntimePipeline({
    provider, synthesisProvider, velociraptorProvider, stateStore, store, stateLock, onState: (s) => hub.broadcast(s), ocrRunner, logger, kevStore,
    secondOpinionProvider, secondOpinionStore, synthesisModelLabel, secondOpinionModelLabel,
    // After a real synthesis, page the matching channels for each new/escalated finding (#58).
    // Fully guarded — notifications are a side channel and must NEVER break synthesis.
    onSynth: (caseId, diff, state) => {
      try {
        const url = `${dashboardBaseUrl}/dashboard?caseId=${encodeURIComponent(caseId)}`;
        for (const ev of findingEventsFromDiff(caseId, diff, state.findings, state.updatedAt)) {
          notifier.dispatch({ ...ev, url }).catch((err) => logLine(`[notify] dispatch error: ${(err as Error).message}`));
        }
      } catch (err) {
        logLine(`[notify] onSynth error: ${(err as Error).message}`);
      }
    },
  });

  // Pre-flight (#179): createApp calls onPreflightReady with runPreflightChecks; we store it
  // here and fire it after app.listen() so probes don't run before the server is ready.
  let scheduledPreflight: (() => Promise<PreflightReport>) | null = null;

  // Live synthesis on by default — set DFIR_AI_AUTO_SYNTHESIZE=off to disable.
  const autoSynthesize = (process.env.DFIR_AI_AUTO_SYNTHESIZE ?? "on").toLowerCase() !== "off";
  const autoSynthesizeDebounceMs = Number(process.env.DFIR_AI_AUTO_SYNTHESIZE_MS) || 8000;

  // Safety-net flush: drain any non-empty capture buffer on this interval so a lone
  // `timer`/`click` screenshot is still analyzed instead of waiting for a full window.
  // Default 5 min; set DFIR_FLUSH_INTERVAL_MS=0 to disable.
  const flushIntervalMs = process.env.DFIR_FLUSH_INTERVAL_MS === "0"
    ? 0
    : (Number(process.env.DFIR_FLUSH_INTERVAL_MS) || undefined);

  const app = createApp(store, {
    pipeline: wiredPipeline,
    aiConfigured: Boolean(provider),
    flushIntervalMs,
    stateStore,
    stateLock,
    reportWriter,
    // The redacted-export route needs OCR even when the vision model is local (the pipeline's
    // ocrRunner is undefined in that case), so give createApp its own always-available runner.
    ocrRunner: ocrRunner ?? new TesseractOcrRunner(),
    reportMetaStore,
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
    onSourceTrust: (caseId) => hub.broadcastTo(caseId, { type: "source_trust_changed" }),
    dwellWindowStore,
    onDwellWindow: (caseId) => hub.broadcastTo(caseId, { type: "dwell_window_changed" }),
    superTimelineStore,
    onSuperTimeline: (caseId) => hub.broadcastTo(caseId, { type: "super_timeline_changed" }),
    starredReportStore,
    forensicGateControlStore,
    onForensicGate: (caseId) => hub.broadcastTo(caseId, { type: "forensic_gate_changed" }),
    confidenceControlStore,
    onConfidenceControl: (caseId) => hub.broadcastTo(caseId, { type: "confidence_control_changed" }),
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
    enrichJitterMs: Number(process.env.DFIR_ENRICH_JITTER_MS) || undefined,
    enrichRetries: Number(process.env.DFIR_ENRICH_RETRIES) || undefined,
    enrichRetryBackoffMs: Number(process.env.DFIR_ENRICH_RETRY_BACKOFF_MS) || undefined,
    enrichMaxIocs: Number(process.env.DFIR_ENRICH_MAX) || undefined,
    customerExposureProviders: buildCustomerExposureProviders(),
    customerExposureDelayMs: Number(process.env.DFIR_EXPOSURE_DELAY_MS) || undefined,
    // Reachability gate: probe a self-hosted MISP/YETI before sending IOCs, cached this long
    // (default 60s in the cache). The poller re-checks down servers on the same cadence and
    // auto-resumes skipped cases on recovery — set DFIR_ENRICH_HEALTH_POLL_MS=0 to disable it.
    enrichHealthTtlMs: Number(process.env.DFIR_ENRICH_HEALTH_TTL_MS) || undefined,
    enrichHealthPollMs: process.env.DFIR_ENRICH_HEALTH_POLL_MS === "0" ? 0 : (Number(process.env.DFIR_ENRICH_HEALTH_POLL_MS) || 60_000),
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
    mispPushClient: buildMispPushClient(),
    mispPushOptions: mispPushOptions(),
    notionClient: buildNotionClient(),
    notionOptions: notionPushOptions(),
    notionExportStore,
    clickupClient: buildClickUpClient(),
    clickupExportStore,
    clickupOptions: clickupOptions(),
    notificationStore,
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
    // Pre-flight (#179): fire the checks once the server is listening (see below).
    onPreflightReady: (run) => { scheduledPreflight = run; },
  });

  // Serve the logo + favicons from public/ (the dashboard <head> links these). Whitelisted
  // filenames only; browsers that auto-request /favicon.ico get the crisp 32px PNG.
  const iconFiles: Record<string, string> = {
    "/dfir-companion-logo.jpg": "image/jpeg",
    "/favicon-16.png": "image/png",
    "/favicon-32.png": "image/png",
    "/apple-touch-icon.png": "image/png",
    "/favicon.ico": "image/png",            // alias → favicon-32.png
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
      void scheduledPreflight().then((r) => {
        if (r.disabled) { logLine("[preflight] checks disabled"); return; }
        const status = r.anyCriticalFailed ? "CRITICAL" : r.anyFailed ? "WARN" : "OK";
        logLine(`[preflight] ${status} (${r.durationMs}ms) — ${r.items.map((i) => `${i.name}:${i.ok ? "ok" : "FAIL"}`).join(", ")}`);
        if (r.anyCriticalFailed) {
          const failed = r.items.filter((i) => !i.ok && i.critical).map((i) => `  ✗ ${i.name}: ${i.detail}`).join("\n");
          warnLine(`[preflight] CRITICAL — open the dashboard → Settings → Diagnostics for details:\n${failed}`);
        }
      }).catch((e) => warnLine(`[preflight] error: ${(e as Error).message}`));
    }
  });

  // Demo mode: seed the demo case immediately on startup so it's always present, then reset it
  // on a fixed interval so visitor edits don't accumulate. Best-effort — a seed failure is logged
  // but never fatal. The timer is .unref()'d so it doesn't block a clean process exit.
  if (demoMode) {
    const resetHours = Math.max(1, Number(process.env.DFIR_DEMO_RESET_HOURS) || 1);
    const seedDemo = (): void => {
      void seedDemoCase(store.casesRoot, { force: true })
        .then((r) => logLine(`[demo] demo case seeded — ${r.stats.events} events, ${r.stats.findings} findings, ${r.stats.iocs} IOCs`))
        .catch((e) => logLine(`[demo] demo case seed failed: ${(e as Error).message}`));
    };
    seedDemo();
    const t = setInterval(seedDemo, resetHours * 60 * 60 * 1000);
    t.unref();
    logLine(`[demo] demo mode active — writes blocked, case resets every ${resetHours}h`);
  }

  // Snapshot the enrolled Velociraptor fleet into the client inventory at startup (#70), so a single-
  // endpoint collection can resolve a host → client_id from the file. RETRY WITH BACKOFF: if the
  // Velociraptor server is down when the companion boots (a common ordering), keep retrying for a while
  // so the inventory self-heals once it comes up — the analyst shouldn't have to restart the companion
  // (Settings → Velociraptor → Reconnect also forces it). Best-effort; timers .unref() so they never
  // block exit. Live monitors self-heal on their own poll timers, so this only covers the inventory.
  if (velociraptorClient) {
    const backoffMs = [0, 30_000, 60_000, 120_000, 300_000, 600_000];   // ~18 min of attempts
    const attempt = (i: number): void => {
      velociraptorClient.listClients()
        .then((clients) => velociraptorClientStore.save(clients, new Date().toISOString()))
        .then((inv) => logLine(`[velociraptor] client inventory: ${inv.clients.length} enrolled client(s)`))
        .catch((e) => {
          const next = i + 1;
          if (next < backoffMs.length) {
            logLine(`[velociraptor] startup inventory refresh failed (${(e as Error).message}) — retrying in ${backoffMs[next] / 1000}s`);
            const t = setTimeout(() => attempt(next), backoffMs[next]);
            t.unref?.();
          } else {
            logLine(`[velociraptor] startup inventory refresh still failing — use Settings → Velociraptor → Reconnect once the server is up`);
          }
        });
    };
    attempt(0);
  }

  // Opt-in update check (issue #127): when enabled (and not env-locked), check GitHub at most
  // once / 24h on startup and on a daily timer. Best-effort, never blocks startup, never throws.
  void (async () => {
    const stored = (await updateCheckStore.load()).enabled;
    const mode = resolveUpdateMode(process.env.DFIR_UPDATE_CHECK, stored);
    if (!mode.enabled || mode.locked) return;
    const runIfStale = async () => {
      const prev = (await updateCheckStore.load()).result;
      if (prev && !prev.error && Date.now() - prev.checkedAt < UPDATE_CHECK_THROTTLE_MS) return;
      await performUpdateCheck({ store: updateCheckStore, repo: updateRepo, fetchFn: fetch, now: Date.now() });
      logLine(`[update] checked ${updateRepo} for a newer release`);
    };
    await runIfStale().catch((e) => warnLine(`[update] check failed: ${(e as Error).message}`));
    const timer = setInterval(() => { void runIfStale().catch(() => {}); }, UPDATE_CHECK_THROTTLE_MS);
    timer.unref?.();
  })();

  // Friendly message instead of an unhandled-error stack trace when the port is taken.
  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(
        `\n[DFIR] Port ${port} is already in use — a DFIR companion is probably already running.\n` +
          `       Use the existing one (http://127.0.0.1:${port}/dashboard), or stop it first:\n` +
          `       PowerShell:  Get-NetTCPConnection -LocalPort ${port} -State Listen | ` +
          `ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }\n`,
      );
      process.exit(1);
    }
    throw err;
  });

  const wss = new WebSocketServer({ server, path: "/ws" });
  wss.on("connection", (socket, req) => {
    const caseId = new URL(req.url ?? "", "http://localhost").searchParams.get("caseId") ?? "";
    hub.subscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike);
    socket.on("close", () => hub.unsubscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike));
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
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
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
  const rawLogDir = process.env.DFIR_LOG_DIR;
  const logDir = rawLogDir && rawLogDir.trim() !== ""
    ? (isAbsolute(rawLogDir) ? rawLogDir : resolve(companionDir, rawLogDir))
    : undefined;

  startServer(casesRoot, port, host, logDir);
}
