import express, { type Express, type Request, type Response, type NextFunction } from "express";
import { config as loadDotenv } from "dotenv";
import { join, isAbsolute, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile, readFile, rm, readdir, stat } from "node:fs/promises";
import { ZodError } from "zod";
import { CaseStore, isValidCaseId } from "./storage/caseStore.js";
import { ingestCapture, CaseNotFoundError } from "./ingest/captureIngest.js";
import { AiControlStore, type AiControl } from "./analysis/aiControl.js";
import { AnonControlStore, type AnonControl } from "./analysis/anonControl.js";
import { CustomEntitiesStore, sanitizeCustomEntities } from "./analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "./analysis/anonDiscovered.js";
import type { AnonTokenCategory } from "./analysis/anonymize.js";
import { isLocalAiProvider, deriveKnownEntities } from "./analysis/anonymize.js";
import { TesseractOcrRunner, type OcrRunner } from "./analysis/ocrRedact.js";
import { resolveRedactedExportOptions, redactedExportFilename } from "./analysis/redactedExport.js";
import { buildRedactedExport } from "./reports/redactedExportBuilder.js";
import { LegitimateStore, markerId, type LegitimateMarker } from "./analysis/legitimate.js";
import { ScopeStore, type ScopeWindow } from "./analysis/scope.js";
import { parseSnapshot } from "./analysis/snapshot.js";
import { exportCaseSnapshot, importCaseSnapshot, SnapshotImportConflictError } from "./analysis/snapshotIo.js";
import { parseCsv } from "./analysis/csvImport.js";
import { contextTokens as resolveContextTokens } from "./analysis/promptBudget.js";
import { resolveHuntPlatforms, normalizeHuntPlatform, HUNT_PLATFORMS, type HuntPlatform } from "./analysis/huntPlatforms.js";
import { parseLogLines } from "./analysis/logImport.js";
import { parseThorReport } from "./analysis/thorImport.js";
import { parseSiemExport } from "./analysis/siemImport.js";
import type { SiemImportOptions } from "./analysis/siemImport.js";
import { parseChainsawReport } from "./analysis/chainsawImport.js";
import type { ChainsawImportOptions } from "./analysis/chainsawImport.js";
import { parseHayabusaTimeline } from "./analysis/hayabusaImport.js";
import type { HayabusaImportOptions } from "./analysis/hayabusaImport.js";
import { parseVelociraptorJson } from "./analysis/velociraptorImport.js";
import type { VelociraptorImportOptions } from "./analysis/velociraptorImport.js";
import { parseNetworkLogs } from "./analysis/networkImport.js";
import type { NetworkImportOptions } from "./analysis/networkImport.js";
import { parseKapeCsv } from "./analysis/kapeImport.js";
import type { KapeImportOptions } from "./analysis/kapeImport.js";
import { parseCybertriage } from "./analysis/cybertriageImport.js";
import type { CybertriageImportOptions } from "./analysis/cybertriageImport.js";
import { parseM365Audit } from "./analysis/m365Import.js";
import type { M365ImportOptions } from "./analysis/m365Import.js";
import { parseCloudTrail } from "./analysis/awsImport.js";
import type { AwsImportOptions } from "./analysis/awsImport.js";
import { parseCloudActivity } from "./analysis/cloudActivityImport.js";
import type { CloudActivityImportOptions } from "./analysis/cloudActivityImport.js";
import { parsePlasoCsv } from "./analysis/plasoImport.js";
import type { PlasoImportOptions } from "./analysis/plasoImport.js";
import { parseSandboxReport } from "./analysis/sandboxImport.js";
import type { SandboxImportOptions } from "./analysis/sandboxImport.js";
import { parseMemory } from "./analysis/memoryImport.js";
import type { MemoryImportOptions } from "./analysis/memoryImport.js";
import { parseEmail } from "./analysis/emailImport.js";
import type { EmailImportOptions } from "./analysis/emailImport.js";
import { parseTheHive } from "./analysis/theHiveImport.js";
import { fetchIrisCase } from "./integrations/iris/irisImportFetch.js";
import { parseAuditdLog } from "./analysis/auditdImport.js";
import type { AuditdImportOptions } from "./analysis/auditdImport.js";
import { parseJournald } from "./analysis/journaldImport.js";
import type { JournaldImportOptions } from "./analysis/journaldImport.js";
import { parseSysdig } from "./analysis/sysdigImport.js";
import type { SysdigImportOptions } from "./analysis/sysdigImport.js";
import { parseWazuhAlerts } from "./analysis/wazuhImport.js";
import type { WazuhImportOptions } from "./analysis/wazuhImport.js";
import { detectImportWithCustom } from "./analysis/importDetect.js";
import { ImporterStore, type ImporterRegistry, type ImporterPrecedence } from "./analysis/importerStore.js";
import { parseImporterSpec } from "./analysis/importerSpec.js";
import { getImporterPrompt } from "./analysis/pipeline.js";
import { getEnvForSettings, updateEnv as updateEnvFile, reloadEnvPrefix } from "./settings/envManager.js";
import { parseMinSeverity } from "./analysis/severityFloor.js";
import { enrichIocs, type EnrichLookupEvent } from "./enrichment/enrichService.js";
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
import { buildTlsFetch } from "./enrichment/tlsFetch.js";
import { validateProcessChains, type ChainSummary } from "./enrichment/chainValidate.js";
import type { AnalysisPipeline } from "./analysis/pipeline.js";
import type { InvestigationState, InvestigationQuestion, QuestionStatus, Severity, ForensicEvent, IOC } from "./analysis/stateTypes.js";
import type { CaptureMetadata } from "./types.js";
import type { StateStore } from "./analysis/stateStore.js";
import type { ReportWriter } from "./reports/reportWriter.js";
import type { IocBlocklistFormat, IocBlocklistOptions, BlocklistIocType } from "./reports/iocBlocklist.js";
import { ReportMetaStore } from "./reports/reportMeta.js";
import { ReportTemplateStore } from "./reports/reportTemplateStore.js";
import { ReportTemplateControlStore } from "./reports/reportTemplateControl.js";
import { injectPrintTrigger } from "./reports/html.js";
import { CommentsStore } from "./analysis/comments.js";
import { TagsStore, type Tag } from "./analysis/tags.js";
import { NotebookStore, type NotebookEntryType, NOTEBOOK_ENTRY_TYPES } from "./analysis/notebookStore.js";
import { PlaybookStore, type NewPlaybookTask, type PlaybookTaskPatch } from "./analysis/playbookStore.js";
import { PLAYBOOK_STATUSES, playbookStats, type PlaybookStatus, type PlaybookTask } from "./analysis/playbook.js";
import { PlaybookHuntStore } from "./analysis/playbookHuntStore.js";
import { selectFreshHunts, pendingHuntTasks, mergePersistedHunts, EMPTY_PERSISTED_HUNTS, PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT } from "./analysis/playbookHunt.js";
import { PlaybookControlStore, DEFAULT_PLAYBOOK_CONTROL, type PlaybookControl } from "./analysis/playbookControl.js";
import { AssetOverridesStore } from "./analysis/assetOverrides.js";
import type { AssetType } from "./analysis/assetGraph.js";
import { SynthMetaStore } from "./analysis/synthMeta.js";
import { SecondOpinionStore } from "./analysis/secondOpinionStore.js";
import { ImportMetaStore } from "./analysis/importMeta.js";
import { TemplateStore, buildInitialQuestions, buildInitialNextSteps } from "./analysis/templateStore.js";
import { diffTimeline } from "./analysis/timelineDiff.js";
import { diffIocs } from "./analysis/iocsDiff.js";
import { ImportUndoStore, pushCheckpoint, applyUndo, applyRedo, summarizeUndoStack } from "./analysis/importUndo.js";
import { mergeEnrichedSubset } from "./analysis/iocBulkOps.js";
import { IocWhitelistStore } from "./analysis/iocWhitelistStore.js";
import { whitelistMatches, parseWhitelistText, toWhitelistCsv, sanitizeRuleInput } from "./analysis/iocWhitelist.js";
import { NsrlStore, ingestNsrlFiles, splitNsrlPaths } from "./analysis/nsrlStore.js";
import { parseNsrlText, nsrlMatchIocs, nsrlMatchEvents } from "./analysis/nsrl.js";
import { KevStore } from "./analysis/kevStore.js";
import { NsrlDb, loadNsrlDbPath, saveNsrlDbPath, removeNsrlDbPath } from "./analysis/nsrlDb.js";
import { applyDeobfuscation } from "./analysis/applyDeobfuscation.js";
import { readPublicAsset, isSeaRuntime } from "./serverAssets.js";
import { buildManualEvent, buildManualIoc } from "./analysis/manualEntry.js";
import { CustomerStore, parseList, sanitizeTargets } from "./analysis/customerStore.js";
import {
  buildCustomerExposureTargets,
  CustomerExposureStore,
  summarizeExposure,
  type CustomerExposureProvider,
} from "./analysis/customerExposure.js";
import { byEventTime } from "./analysis/forensicSort.js";
import { IrisClient } from "./integrations/iris/irisClient.js";
import { VelociraptorClient, buildVelociraptorClient, matchClient, ALL_CLIENTS, type HuntTarget, type HuntUpload } from "./integrations/velociraptor/velociraptorApi.js";
import { ArtifactBundleStore } from "./analysis/artifactBundleStore.js";
import { VelociraptorClientStore } from "./analysis/velociraptorClientStore.js";
import { VeloHuntStore, type VeloHuntJob } from "./analysis/veloHuntStore.js";
import { VeloMonitorStore, monitorId, type VeloMonitor } from "./analysis/veloMonitorStore.js";
import { pollMonitorOnce, monitorArtifactMap, type PollDeps } from "./integrations/velociraptor/monitorPoller.js";
import { PushTokenStore, generatePushToken } from "./analysis/pushTokenStore.js";
import { resolvePushAuth } from "./analysis/pushAuth.js";
import { extractPushPayload } from "./analysis/pushPayload.js";
import { pushCaseToIris, type IrisPushOptions } from "./integrations/iris/irisPush.js";
import { TimesketchClient } from "./integrations/timesketch/timesketchClient.js";
import { pushCaseToTimesketch, type TimesketchPushOptions } from "./integrations/timesketch/timesketchPush.js";
import { MispPushClient } from "./integrations/misp/mispPushClient.js";
import { pushCaseToMisp, type MispPushOptions } from "./integrations/misp/mispPush.js";
import { NotionClient, parseNotionPageId } from "./integrations/notion/notionClient.js";
import { pushCaseToNotion, type NotionPushOptions, type NotionPushTarget } from "./integrations/notion/notionPush.js";
import { NotionExportStore } from "./integrations/notion/notionExportStore.js";
import { ClickUpClient } from "./integrations/clickup/clickupClient.js";
import { ClickUpExportStore } from "./integrations/clickup/clickupExportStore.js";
import { pushPlaybookToClickUp } from "./integrations/clickup/clickupPush.js";
import { getDiskStats, getDiskWarningLevel, diskWarnEnvThresholds } from "./analysis/diskWarn.js";
import {
  buildAiDiagnostics, summarizeImportAttempts, countByKind, aggregateCaseSizes, buildDiagnosticsText,
  type DiagnosticsReport, type ImporterFailure, type AiError, type ScannedFile,
} from "./analysis/diagnostics.js";
import { archiveCase } from "./analysis/caseArchive.js";
import { NotificationConfigStore } from "./analysis/notificationStore.js";
import { seedDemoCase } from "./analysis/seedDemoCase.js";
import {
  findingEventsFromDiff, milestoneEvent, parseChannelInput, playbookTaskEvent, redactChannel,
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
  isLogLevel,
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
function errLine(msg: string): void { serverLogger.error(msg); }

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
  // Investigator comments on case entities (collaboration). onComments pings dashboard
  // clients over the WS to re-fetch when a comment is added/removed.
  commentsStore?: CommentsStore;
  onComments?: (caseId: string) => void;
  // Analyst triage tags on case entities (hand labels like confirmed-malicious / false-positive
  // / key-evidence, independent of AI severity). onTags pings dashboard clients over the WS to
  // re-fetch when a tag is added/removed.
  tagsStore?: TagsStore;
  onTags?: (caseId: string) => void;
  // Per-case analyst notebook (hypotheses, notes, open questions). onNotebook pings dashboard
  // clients over the WS to re-fetch when an entry is added, updated, or removed.
  notebookStore?: NotebookStore;
  onNotebook?: (caseId: string) => void;
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
  // Confirmed-legitimate markers (false-positive exclusions). onLegitimate pings dashboard
  // clients over the WS so other investigators see the change immediately, before synthesis.
  onLegitimate?: (caseId: string) => void;
  // Investigation time-window changes. onScope pings dashboard clients with the new window so
  // other investigators can apply the same scope instantly, without waiting for re-synthesis.
  onScope?: (caseId: string, scope: ScopeWindow) => void;
  // Last-synthesis record (when it ran + findings diff) for the dashboard's "last synthesized N
  // ago" indicator and what-changed view. Read-only here; the pipeline writes it on each run.
  synthMetaStore?: SynthMetaStore;
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
  // Velociraptor API: a configured client (when DFIR_VELOCIRAPTOR_API_CONFIG is set) lets the
  // dashboard run the generated hunt VQL against the server and show the rows inline.
  velociraptorClient?: VelociraptorClient;
  // Rebuilds the Velociraptor client from current config (used by POST /velociraptor/reconnect so
  // config saved via Settings, or the Velociraptor server coming back online, applies without a server
  // restart). Defaults to the env-based buildVelociraptorClient; tests inject a stub (no spawn).
  rebuildVelociraptorClient?: () => VelociraptorClient | undefined;
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
}

// Content type for an evidence file served back to the dashboard. CSVs/text are
// served as text/plain so a click opens them in a tab rather than downloading.
function evidenceContentType(file: string): string {
  const ext = file.slice(file.lastIndexOf(".")).toLowerCase();
  switch (ext) {
    case ".webp": return "image/webp";
    case ".png": return "image/png";
    case ".jpg":
    case ".jpeg": return "image/jpeg";
    case ".gif": return "image/gif";
    case ".csv":
    case ".log":
    case ".txt": return "text/plain; charset=utf-8";
    case ".json": return "application/json; charset=utf-8";
    default: return "application/octet-stream";
  }
}

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

// Normalize a label/tag input that may arrive as a comma-separated string or an array of strings.
function toStringArray(v: unknown): string[] {
  if (typeof v === "string") return v.split(",").map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(v)) return v.map((s) => String(s).trim()).filter(Boolean);
  return [];
}

export function createApp(store: CaseStore, options: AppOptions = {}): Express {
  const app = express();
  const hasAiProvider = (): boolean => options.aiConfigured ?? Boolean(options.pipeline?.hasAiProvider());

  // ── Diagnostics runtime state (#118) ─────────────────────────────────────────────────
  // In-memory, best-effort rings powering the Health/Diagnostics page. They reset on restart
  // (like `lastCapture` below) — durable history lives in the per-case audit logs. Capped so a
  // long-running server can't grow them unbounded.
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

  // Lightweight reachability check used by the extension's connection status.
  // aiEnabled tells the dashboard whether an AI provider is configured at all.
  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true, service: "dfir-companion", aiEnabled: hasAiProvider(), enrichEnabled: (options.enrichmentProviders?.length ?? 0) > 0, customerExposureEnabled: (options.customerExposureProviders?.length ?? 0) > 0, velociraptorEnabled: !!options.velociraptorClient, notionEnabled: !!options.notionClient, clickupEnabled: !!options.clickupClient, notificationsEnabled: !!options.notificationStore, notifyEmailEnabled: !!options.notifyEmailEnabled, pushEnabled: !!options.pushTokenStore || !!(options.pushToken && options.pushToken.trim()), pushTokenGlobal: !!(options.pushToken && options.pushToken.trim()), huntPlatforms: options.huntPlatforms ?? [...HUNT_PLATFORMS], logLevel: serverLogger.getLevel(), kevEnabled: !!options.kevStore, secondOpinionEnabled: !!options.secondOpinionEnabled, customImporters: importerRegistry.importers.size });
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
    logLine(`[log] level changed ${previous} -> ${level}`);
    return res.status(200).json({ level: serverLogger.getLevel() });
  });

  // Most-recent capture across ALL cases (in-memory; resets on restart). Powers the dashboard's
  // check-on-connect for the cross-case capture warning.
  let lastCapture: { caseId: string; at: number } | null = null;

  // How many captures have been recorded for a case (counts the audit-log lines).
  app.get("/cases/:id/captures/count", async (req: Request, res: Response) => {
    try {
      const log = await readFile(store.capturesLogPath(req.params.id), "utf8");
      const count = log.split("\n").filter((l) => l.trim().length > 0).length;
      return res.status(200).json({ count });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return res.status(200).json({ count: 0 });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The most-recent capture across ALL cases (in-memory; resets on restart) + its age in ms.
  // A freshly-connected dashboard checks this to warn when screenshots are landing on a different
  // case than the one it's viewing — catching the mismatch even without a live capture event.
  app.get("/captures/recent", (_req: Request, res: Response) => {
    if (!lastCapture) return res.status(200).json({ caseId: null });
    return res.status(200).json({ caseId: lastCapture.caseId, ageMs: Date.now() - lastCapture.at });
  });

  const windowSize = options.windowSize ?? 4;
  const buffers = new Map<string, CaptureMetadata[]>();
  const SIGNIFICANT = new Set(["navigation", "tab_switch"]);

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
    if (!autoSynth || !options.pipeline || !hasAiProvider()) return;
    const existing = synthTimers.get(caseId);
    if (existing) clearTimeout(existing);
    synthTimers.set(caseId, setTimeout(() => {
      synthTimers.delete(caseId);
      if (synthInFlight.has(caseId)) { scheduleSynthesis(caseId); return; } // busy — retry after debounce
      synthInFlight.add(caseId);
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "synthesizing conclusions" });
      options.pipeline!.synthesize(caseId)
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); autoEnrichIfEnabled(caseId); })
        .catch((err) => { recordAiError(caseId, "synthesizing", err); options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }); })
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

  // List existing cases (newest first) so the extension can present a picker of cases
  // to attach to — case CREATION lives in the dashboard, the extension only connects.
  app.get("/cases", async (_req: Request, res: Response) => {
    try {
      return res.status(200).json(await store.listCases());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Create a case. This is the one place a case is born (the dashboard's New case form and
  // `npm run`-style tooling call it); the extension no longer creates cases. Rejects a
  // duplicate id so the form can't silently clobber an existing case's metadata/evidence.
  // Optional `templateId`: pre-populates key questions from the named template.
  app.post("/cases", async (req: Request, res: Response) => {
    try {
      const { caseId, name, investigator, aiProvider, templateId } = req.body ?? {};
      if (!caseId || !name) return res.status(400).json({ error: "caseId and name are required" });
      if (typeof caseId !== "string" || !isValidCaseId(caseId)) return res.status(400).json({ error: "caseId must use only letters, numbers, dots, dashes, or underscores, and may not contain path traversal" });
      if (await store.caseExists(caseId)) return res.status(409).json({ error: `case ${caseId} already exists` });
      const meta = await store.createCase({
        caseId, name, investigator: investigator ?? "unknown", aiProvider: aiProvider ?? null,
      });
      if (templateId && options.templateStore && options.stateStore) {
        const template = await options.templateStore.get(String(templateId));
        if (template && (template.initialKeyQuestions.length || template.initialNextSteps?.length)) {
          const state = await options.stateStore.load(caseId);
          if (template.initialKeyQuestions.length) state.keyQuestions = buildInitialQuestions(template);
          if (template.initialNextSteps?.length) state.nextSteps = buildInitialNextSteps(template);
          state.updatedAt = new Date().toISOString();
          await options.stateStore.save(state);
        }
      }
      dispatchNotify(milestoneEvent(caseId, `Investigation opened: ${name}`, [`Investigator: ${investigator ?? "unknown"}`], new Date().toISOString()));
      return res.status(201).json(meta);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Seed the built-in demo case ("GlobalTech Industries — BEC & Ransomware Precursor").
  // Accepts optional { caseId?: string, force?: boolean } in the body.
  // Returns 409 when the case already exists and force is not set; 201 on success.
  // Available in both the dev server and the portable EXE so users don't need tsx/Node installed.
  app.post("/cases/seed-demo", async (req: Request, res: Response) => {
    try {
      const caseId = typeof req.body?.caseId === "string" ? req.body.caseId : undefined;
      const force  = req.body?.force === true;
      const result = await seedDemoCase(store.casesRoot, { caseId, force });
      return res.status(201).json(result);
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "EEXIST") return res.status(409).json({ error: e.message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Disk space stats (#119) ────────────────────────────────────────────────────────────
  // Reports free/total bytes on the cases-root filesystem and the configured warning level.
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
      const open = cases.filter((c) => c.status !== "closed").length;

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
        cases: { count: cases.length, open, closed: cases.length - open },
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
      const result = await provider.analyze({
        systemPrompt: "You are a connectivity probe. Reply with the single word: OK.",
        userPrompt: "ping",
        images: [],
      });
      const latencyMs = Date.now() - startedAt;
      const reply = (result.rawText ?? "").trim().slice(0, 120);
      logLine(`[diagnostics] AI test ok provider=${provider.name} latency=${latencyMs}ms`);
      return res.status(200).json({ ok: true, provider: provider.name, latencyMs, reply });
    } catch (err) {
      const latencyMs = Date.now() - startedAt;
      const kind = err instanceof ProviderError ? err.kind : "other";
      logLine(`[diagnostics] AI test failed provider=${provider.name} kind=${kind}: ${(err as Error).message}`);
      return res.status(200).json({ ok: false, provider: provider.name, latencyMs, kind, error: (err as Error).message });
    }
  });

  // ── Case lifecycle (#119) ──────────────────────────────────────────────────────────────
  // Set a case's lifecycle status (open / closed). A closed case is eligible for archiving.
  app.patch("/cases/:id/status", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      if (!await store.caseExists(id)) return res.status(404).json({ error: `case ${id} not found` });
      const { status } = req.body ?? {};
      if (status !== "open" && status !== "closed") return res.status(400).json({ error: "status must be 'open' or 'closed'" });
      const updated = await store.updateCaseMeta(id, { status });
      logLine(`[lifecycle] case=${id} status=${status}`);
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Archive a case to a ZIP file (<casesRoot>/<caseId>.zip). Intended for closed cases.
  // Returns the archive path and a manifest of archived files + checksums.
  // Never deletes the original folder.
  app.post("/cases/:id/archive", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      if (!await store.caseExists(id)) return res.status(404).json({ error: `case ${id} not found` });
      logLine(`[archive] starting archive for case=${id}`);
      const result = await archiveCase(store.casesRoot, id);
      logLine(`[archive] done case=${id} files=${result.manifest.totalFiles} bytes=${result.manifest.totalBytes} path=${result.archivePath}`);
      return res.status(200).json(result);
    } catch (err) {
      errLine(`[archive] error case=${req.params.id}: ${(err as Error).message}`);
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Case templates ──────────────────────────────────────────────────────────────────────
  // Built-in templates are always available; custom templates are saved to the templates dir.

  app.get("/templates", async (_req: Request, res: Response) => {
    if (!options.templateStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.templateStore.list());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/templates/:id", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(404).json({ error: "template store not configured" });
    try {
      const template = await options.templateStore.get(req.params.id);
      if (!template) return res.status(404).json({ error: `template "${req.params.id}" not found` });
      return res.status(200).json(template);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/templates", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(501).json({ error: "template store not configured" });
    try {
      const { name, description, recommendedImports, initialKeyQuestions, initialNextSteps, severityFloor, huntPlatforms, id } = req.body ?? {};
      if (!name) return res.status(400).json({ error: "name is required" });
      const saved = await options.templateStore.save({ id, name, description, recommendedImports, initialKeyQuestions, initialNextSteps, severityFloor: severityFloor ?? null, huntPlatforms });
      return res.status(201).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/templates/:id", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(501).json({ error: "template store not configured" });
    try {
      const found = await options.templateStore.delete(req.params.id);
      if (!found) return res.status(404).json({ error: `template "${req.params.id}" not found` });
      return res.status(204).send();
    } catch (err) {
      if ((err as Error).message.includes("built-in")) return res.status(400).json({ error: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/captures", async (req: Request, res: Response) => {
    try {
      const rawCaseId = typeof req.body?.caseId === "string" ? req.body.caseId.trim() : "";
      if (rawCaseId) {
        const caseMeta = await store.getCaseMeta(rawCaseId).catch(() => null);
        if (caseMeta?.status === "closed") {
          return res.status(423).json({ error: `Case "${rawCaseId}" is closed — reopen it before adding screenshots` });
        }
      }
      const metadata = await ingestCapture(store, req.body);
      res.status(201).json(metadata);
      serverLogger.debug(
        `screenshot captured seq=${metadata.sequenceNumber} trigger=${metadata.triggerType} ` +
          `file=${metadata.screenshotFile || "(none)"}${metadata.isDuplicate ? " (duplicate — not analyzed)" : ""}`,
        { caseId: metadata.caseId },
      );
      // Cross-case signal: lets a dashboard warn when captures arrive for a case it isn't viewing
      // (live, via the WS broadcast) or detect it on connect (via /captures/recent).
      lastCapture = { caseId: metadata.caseId, at: Date.now() };
      options.onCapture?.(metadata.caseId);
      // Evidence is always stored; AI analysis only runs when enabled for the case.
      if (!metadata.isDuplicate && options.pipeline && hasAiProvider() && (await getControl(metadata.caseId)).enabled) {
        const buf = buffers.get(metadata.caseId) ?? [];
        buf.push(metadata);
        buffers.set(metadata.caseId, buf);
        if (buf.length >= windowSize || SIGNIFICANT.has(metadata.triggerType)) {
          void flush(metadata.caseId);
        }
      }
      return;
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: "invalid payload", details: err.issues });
      if (err instanceof CaseNotFoundError) {
        return res.status(404).json({ error: `case ${err.caseId} does not exist — create it in the dashboard first` });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/state", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      return res.status(200).json(state);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Serve a piece of evidence (a screenshot or an imported CSV) by filename so the
  // dashboard can link findings/events straight to the artifact they came from.
  // Strictly sandboxed: only a bare filename within the case's screenshots/ or
  // imports/ dir is allowed (no path separators, no "..").
  app.get("/cases/:id/evidence/:file", async (req: Request, res: Response) => {
    const file = req.params.file;
    if (!/^[A-Za-z0-9._-]+$/.test(file) || file.includes("..")) {
      return res.status(400).json({ error: "invalid evidence filename" });
    }
    const candidates = [
      join(store.screenshotsDir(req.params.id), file),
      join(store.importsDir(req.params.id), file),
    ];
    for (const path of candidates) {
      try {
        const buf = await readFile(path);
        res.type(evidenceContentType(file));
        res.setHeader("Cache-Control", "private, max-age=300");
        return res.send(buf);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
          return res.status(500).json({ error: (err as Error).message });
        }
      }
    }
    return res.status(404).json({ error: "evidence not found" });
  });

  app.post("/cases/:id/report", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const paths = await options.reportWriter.writeAll(req.params.id);
      dispatchNotify(milestoneEvent(req.params.id, "Report generated", ["The case report (Markdown + HTML) was (re)generated."], new Date().toISOString()));
      return res.status(200).json(paths);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Serve a generated report file for viewing or download (export as Markdown or HTML).
  // Only the known report artifacts are served; `?download=1` forces a save dialog, and
  // `?print=1` (HTML only) injects a print trigger so the browser opens its print dialog —
  // the zero-dependency "Save as PDF" export. The on-disk file is never modified.
  app.get("/cases/:id/report/:file", async (req: Request, res: Response) => {
    const types: Record<string, string> = {
      "report.md": "text/markdown; charset=utf-8",
      "report.html": "text/html; charset=utf-8",
    };
    const file = req.params.file;
    if (!Object.prototype.hasOwnProperty.call(types, file)) {
      return res.status(400).json({ error: "unknown report file" });
    }
    try {
      const buf = await readFile(join(store.reportsDir(req.params.id), file));
      res.type(types[file]);
      const download = req.query.download !== undefined;
      if (download) {
        res.setHeader("Content-Disposition", `attachment; filename="${file}"`);
      }
      res.setHeader("Cache-Control", "private, no-cache");
      // PDF export: an opened-in-browser HTML report that auto-triggers the print dialog.
      // Mutually exclusive with download — the saved PDF must come from the print dialog, not a file.
      if (file === "report.html" && req.query.print !== undefined && !download) {
        return res.send(injectPrintTrigger(buf.toString("utf8")));
      }
      return res.send(buf);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return res.status(404).json({ error: "report not generated yet — POST /cases/:id/report first" });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The asset ↔ IoC graph (compromised assets and the IoCs that touched each), derived on
  // demand from the current state with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/asset-graph", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.assetGraph(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The causal evidence chain graph (process trees + lateral movement), derived on demand
  // from the current state with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/evidence-graph", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.evidenceGraph(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Temporal attack phases — the forensic timeline grouped into bursts of activity by time gap
  // (no AI). Derived on demand with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/phases", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.phases(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Swimlane data for the visual timeline chart — forensic events grouped into lanes by the
  // chosen groupBy axis (asset | severity | tactic). Derived on demand, no AI, same filtering.
  app.get("/cases/:id/swimlane", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const groupBy = (req.query.groupBy as string) === "severity" ? "severity"
      : (req.query.groupBy as string) === "tactic" ? "tactic" : "asset";
    try {
      return res.status(200).json(await options.reportWriter.swimlane(req.params.id, groupBy));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Beacon / C2 candidates (#82): outbound connection channels whose inter-arrival intervals are too
  // regular to be human traffic, derived on demand from the forensic timeline's network events (same
  // scope/legitimate filtering as the report). Hunting leads, not verdicts. Powers the dashboard panel.
  app.get("/cases/:id/beacon-candidates", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.beaconCandidates(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Timeline gaps (#83): suspiciously long silent periods in the forensic timeline — a complete gap
  // (every source dark) is the classic log-tampering signature, a partial gap a single-tool coverage
  // blindspot. Derived on demand, no AI, same scope/legitimate filtering as the report. Powers the
  // dashboard Timeline Gaps panel; thresholds DFIR_GAP_MIN_MINUTES / _DENSITY_FACTOR / _ACTIVE_HOURS.
  app.get("/cases/:id/timeline-gaps", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.timelineGaps(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // AI hypothesis generation for timeline gaps (#96): for each flagged silent period, hypothesise the
  // attacker activity that fits the surrounding events, and pair each gap with the deterministic
  // SHADOW-ARTIFACT collections (USN journal, SRUM, Prefetch, Amcache, …) that reconstruct the missing
  // window. Single text-only AI call, EPHEMERAL (no state change) — the dashboard shows the hypotheses +
  // collections for review, then deploys a chosen shadow-artifact collection via POST /velociraptor/hunt.
  // Needs an AI provider; does NOT need the Velociraptor API (the VQL is useful to copy even when off).
  app.post("/cases/:id/timeline-gaps/hypothesize", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for gap hypotheses" });
    try {
      const result = await options.pipeline.hypothesizeGaps(req.params.id);
      logLine(`[gaps] hypothesised ${result.hypotheses.length} timeline gap(s) for ${req.params.id}`);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-IOC corroboration: { iocId: [tools that observed it] }, derived on demand by matching each
  // IOC value against the forensic events' sources (same scope/legitimate filtering as the report).
  // Powers the dashboard's "⊕ N sources" badge on IOCs (#35 Phase 3).
  app.get("/cases/:id/ioc-sources", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.iocSources(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Adversary group hints (#46): known ATT&CK groups ranked by technique overlap with the case —
  // offline hypothesis fuel (NOT attribution), derived on demand from the bundled MITRE Groups
  // dataset with the same scope/legitimate filtering as the report. Powers the dashboard panel.
  app.get("/cases/:id/adversary-hints", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.adversaryHints(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Mobile companion summary (#59): a compact, READ-ONLY projection of the case for the phone PWA
  // (/mobile) — case status, worst findings, most severe/recent events, IOC list with verdicts.
  // Same scope/legitimate filtering as the report, so the phone view agrees with the dashboard.
  app.get("/cases/:id/mobile-summary", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.mobileSummary(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export just the incident (forensic) timeline as CSV, generated on demand from the
  // current state (same scope/legitimate filtering as the report) — no full report needed.
  app.get("/cases/:id/incident-timeline.csv", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const csv = await options.reportWriter.incidentTimelineCsv(req.params.id);
      res.type("text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="incident-timeline.csv"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(csv);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export a MITRE ATT&CK Navigator layer (JSON) for the case, generated on demand from the
  // current state (same scope/legitimate filtering as the report). Drops straight into the
  // Navigator's "Open Existing Layer → Upload from local"; techniques colored by severity.
  app.get("/cases/:id/attack-layer.json", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const layer = await options.reportWriter.attackLayer(req.params.id);
      res.type("application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="attack-navigator-${req.params.id}.json"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(JSON.stringify(layer, null, 2));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the incident report as a Word (.docx) attachment, generated on demand from the
  // current state (same scope/legitimate filtering as the report). Not persisted on disk —
  // the binary is built fresh per request so it doesn't churn the cases/ folder.
  app.get("/cases/:id/report.docx", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const buf = await options.reportWriter.docx(req.params.id);
      res.type("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
      res.setHeader("Content-Disposition", `attachment; filename="report-${req.params.id}.docx"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(buf);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the incident (forensic) timeline as Timesketch-compatible JSONL, generated on demand
  // from the current state (same scope/legitimate filtering as the report). Upload it into a
  // Timesketch sketch manually, or use the Push-to-Timesketch button below to do it in one click.
  app.get("/cases/:id/timeline.jsonl", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const jsonl = await options.reportWriter.timesketchJsonl(req.params.id);
      res.type("application/x-ndjson; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="timesketch-timeline.jsonl"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(jsonl);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export a STIX 2.1 bundle (JSON) for the case, generated on demand from the current state
  // (same scope/legitimate filtering as the report). Drops straight into any TIP that ingests
  // STIX — OpenCTI, MISP, Anomali, ThreatConnect — making the case portable without lock-in.
  app.get("/cases/:id/export/stix", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const bundle = await options.reportWriter.stixBundle(req.params.id);
      res.type("application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="stix-bundle-${req.params.id}.json"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(JSON.stringify(bundle, null, 2));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export a clean IOC block-list for network/firewall teams (issue #87). Supports three formats:
  // txt (one value per line, grouped by type, with header comments), csv (minimal columnar format
  // for TIP ingestion/ticketing), and stix (indicators-only STIX 2.1 bundle). Severity is derived
  // from the worst enrichment verdict; scope/legitimate filters always apply.
  //
  // Query params: format (txt|csv|stix, default txt), minSeverity (Critical|High|Medium|Low|Info,
  // default Medium), types (comma-separated ip,domain,url,hash,email), verdictOnly (true|false).
  app.get("/cases/:id/export/ioc-blocklist", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const fmt = String(req.query.format ?? "txt");
    if (fmt !== "txt" && fmt !== "csv" && fmt !== "stix") {
      return res.status(400).json({ error: "format must be txt, csv, or stix" });
    }
    const opts: IocBlocklistOptions = {};
    const VALID_SEV: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
    const VALID_TYPES: BlocklistIocType[] = ["ip", "domain", "url", "hash", "email"];
    const { minSeverity, types, verdictOnly } = req.query;
    if (typeof minSeverity === "string" && VALID_SEV.includes(minSeverity as Severity)) {
      opts.minSeverity = minSeverity as Severity;
    }
    if (typeof types === "string" && types) {
      opts.types = types.split(",").filter((t): t is BlocklistIocType => VALID_TYPES.includes(t as BlocklistIocType));
    }
    if (verdictOnly === "true") opts.verdictOnly = true;
    try {
      const data = await options.reportWriter.iocBlocklist(req.params.id, fmt as IocBlocklistFormat, opts);
      const cid = req.params.id;
      res.setHeader("Cache-Control", "private, no-cache");
      if (fmt === "stix") {
        res.type("application/json; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="ioc-blocklist-${cid}.stix.json"`);
        return res.send(JSON.stringify(data, null, 2));
      } else if (fmt === "csv") {
        res.type("text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="ioc-blocklist-${cid}.csv"`);
        return res.send(data as string);
      } else {
        res.type("text/plain; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="ioc-blocklist-${cid}.txt"`);
        return res.send(data as string);
      }
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export a portable INVESTIGATION SNAPSHOT (issue #56): a single JSON bundle of the case's
  // timeline, findings, IOCs, asset-graph state, analyst decisions and evidence REFERENCES, with
  // NO AI keys and no machine-specific config (see analysis/snapshot.ts allowlist). Reads the case
  // directory directly — works regardless of which optional stores are wired — so a teammate can
  // import it on another machine and pick up the investigation without re-running analysis.
  app.get("/cases/:id/export/snapshot", async (req: Request, res: Response) => {
    try {
      const snapshot = await exportCaseSnapshot(store, req.params.id);
      res.type("application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="snapshot-${req.params.id}.json"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(JSON.stringify(snapshot, null, 2));
    } catch (err) {
      if ((err as Error).message.includes("does not exist")) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import an investigation snapshot into a NEW case (issue #56). Body is the snapshot JSON, with an
  // optional `targetCaseId` to import under a different id (resolves a conflict). The snapshot is
  // validated (format/version/allowlist) before any write; a snapshot can ONLY restore allowlisted
  // state files, never machine/account config. 409 if the target id already exists (the dashboard
  // re-prompts), 400 if the payload isn't a valid snapshot.
  app.post("/snapshots/import", async (req: Request, res: Response) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const targetCaseId = typeof body.targetCaseId === "string" && body.targetCaseId.trim()
        ? body.targetCaseId.trim()
        : undefined;
      // The snapshot may be posted bare, or wrapped as { snapshot: {...}, targetCaseId }.
      const rawSnapshot = body.snapshot !== undefined ? body.snapshot : body;
      const snapshot = parseSnapshot(rawSnapshot);
      const meta = await importCaseSnapshot(store, snapshot, { targetCaseId });
      return res.status(201).json({ ...meta, counts: snapshot.counts });
    } catch (err) {
      if (err instanceof SnapshotImportConflictError) {
        return res.status(409).json({ error: err.message, caseId: err.caseId });
      }
      // parseSnapshot throws plain Errors with a human-readable reason → 400 (bad upload).
      const msg = (err as Error).message;
      if (/snapshot|case id/i.test(msg)) return res.status(400).json({ error: msg });
      return res.status(500).json({ error: msg });
    }
  });

  // Human-authored report metadata (title page, distribution, BIA, limitations, glossary,
  // recommendations…). GET returns the stored values (or defaults); PUT replaces them with a
  // normalized payload. These merge into report.md alongside the auto-derived sections.
  app.get("/cases/:id/report-meta", async (req: Request, res: Response) => {
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    try {
      return res.status(200).json(await options.reportMetaStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/report-meta", async (req: Request, res: Response) => {
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    try {
      const saved = await options.reportMetaStore.save(req.params.id, req.body);
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Report templates (issue #60) ─────────────────────────────────────────────────────────
  // Global, shared-across-cases branded layouts: accent colour, cover title/subtitle, running
  // header & footer, and which report sections appear and in what order. Built-ins are editable in
  // place (saving under a built-in id writes an override; DELETE resets it). Mirrors /bundles.
  app.get("/report-templates", async (_req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.reportTemplateStore.list());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/report-templates/:id", async (req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      const tpl = await options.reportTemplateStore.get(req.params.id);
      if (!tpl) return res.status(404).json({ error: `report template "${req.params.id}" not found` });
      return res.status(200).json(tpl);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/report-templates", async (req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
      if (!name) return res.status(400).json({ error: "name is required" });
      const saved = await options.reportTemplateStore.save(req.body);
      return res.status(201).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Delete a custom template, OR reset an edited built-in back to its shipped default (idempotent for
  // a pristine built-in). 404 only for an unknown non-built-in id.
  app.delete("/report-templates/:id", async (req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      const removed = await options.reportTemplateStore.delete(req.params.id);
      if (!removed && !options.reportTemplateStore.isBuiltIn(req.params.id)) {
        return res.status(404).json({ error: `report template "${req.params.id}" not found` });
      }
      return res.status(204).send();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-case selection of which report template renders the report. GET returns { templateId }
  // (default "standard"); PUT sets it and re-broadcasts so other dashboards refresh.
  app.get("/cases/:id/report-template", async (req: Request, res: Response) => {
    if (!options.reportTemplateControlStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      return res.status(200).json(await options.reportTemplateControlStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/report-template", async (req: Request, res: Response) => {
    if (!options.reportTemplateControlStore) return res.status(501).json({ error: "report templates not configured" });
    const templateId = typeof req.body?.templateId === "string" ? req.body.templateId : undefined;
    try {
      const saved = await options.reportTemplateControlStore.set(req.params.id, { templateId });
      options.onReportTemplate?.(req.params.id);
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The active DFIR-IRIS client. Mutable: POST /iris/reconnect can rebuild it at runtime (config
  // saved via Settings, or IRIS coming back online) without a server restart. Starts from options.
  let irisClient = options.irisClient;
  const rebuildIris = options.rebuildIrisClient ?? buildIrisClient;

  // Whether a DFIR-IRIS push/import target is configured (so the dashboard can show/hide the buttons).
  app.get("/iris/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!irisClient, baseUrl: process.env.DFIR_IRIS_URL || options.irisOptions?.baseUrl });
  });

  // Re-read DFIR_IRIS_* from .env (settings saved via the dashboard only write the file), rebuild
  // the client, and ping to verify connectivity. Lets the analyst connect after configuring IRIS —
  // or after IRIS comes back online — without the #1-gotcha restart. Always 200; the body says
  // whether it's configured and reachable.
  app.post("/iris/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_IRIS_");
      irisClient = rebuildIris();
      if (!irisClient) return res.status(200).json({ configured: false, ok: false, error: "DFIR_IRIS_URL and DFIR_IRIS_KEY are not set" });
      try {
        await irisClient.ping();
        return res.status(200).json({ configured: true, ok: true, baseUrl: process.env.DFIR_IRIS_URL });
      } catch (err) {
        return res.status(200).json({ configured: true, ok: false, baseUrl: process.env.DFIR_IRIS_URL, error: (err as Error).message });
      }
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // List the cases on the configured DFIR-IRIS instance — powers the "Import from IRIS" picker
  // (issue #88). 501 when not configured. Errors map to 502 (the remote IRIS is unreachable).
  app.get("/iris/cases", async (_req: Request, res: Response) => {
    if (!irisClient) return res.status(501).json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    try {
      const cases = await irisClient.listCases();
      return res.status(200).json({ cases });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Run a VQL query against the configured Velociraptor server (via its API) and return the rows.
  // Powers the hunt-pivot modal's "Run in Velociraptor" button. 501 when not configured. The VQL is
  // analyst-authored (from the generated pivots) — localhost only, opt-in via DFIR_VELOCIRAPTOR_*.
  app.post("/velociraptor/run", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    try {
      logLine(`[velociraptor] run query (${vql.length} chars)`);
      const result = await options.velociraptorClient.run(vql);
      logLine(`[velociraptor] query DONE -> ${result.total} rows${result.truncated ? " (truncated)" : ""}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] query ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Launch a HUNT that runs the pivot VQL on ALL enrolled endpoints (packages it as a CLIENT
  // artifact, then creates the hunt). This is the dashboard's "Run hunt on all clients" action.
  app.post("/velociraptor/hunt", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    const description = typeof req.body?.description === "string" ? req.body.description : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    try {
      logLine(`[velociraptor] launch hunt: ${description.slice(0, 80)}`);
      const result = await options.velociraptorClient.launchHunt(vql, description);
      logLine(`[velociraptor] hunt launched -> ${result.huntId} (artifact ${result.artifact}, ${result.sources.length} source(s))`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] hunt ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Read a launched hunt's results (rows collected from the endpoints so far). Polled by the dashboard.
  app.post("/velociraptor/hunt-results", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const huntId = typeof req.body?.huntId === "string" ? req.body.huntId.trim() : "";
    const artifact = typeof req.body?.artifact === "string" ? req.body.artifact.trim() : "";
    const sources = Array.isArray(req.body?.sources) ? req.body.sources.filter((s: unknown): s is string => typeof s === "string") : [];
    if (!huntId || !artifact) return res.status(400).json({ error: "huntId and artifact are required" });
    try {
      const result = await options.velociraptorClient.huntResults(huntId, artifact, sources);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

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

  // Read the persisted client inventory (host ↔ client_id map). Empty when never refreshed.
  app.get("/velociraptor/clients", async (_req: Request, res: Response) => {
    if (!options.velociraptorClientStore) return res.status(200).json({ updatedAt: "", clients: [] });
    try {
      return res.status(200).json(await options.velociraptorClientStore.load());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Refresh the client inventory now (Settings → Velociraptor "Refresh client list"). 501 when the
  // API / store isn't configured; 502 on a query failure.
  app.post("/velociraptor/clients/refresh", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.velociraptorClientStore) return res.status(501).json({ error: "client inventory store not configured" });
    try {
      const count = await refreshVeloClients();
      const inv = await options.velociraptorClientStore.load();
      return res.status(200).json({ count, updatedAt: inv.updatedAt, clients: inv.clients });
    } catch (err) {
      logLine(`[velociraptor] client refresh ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Builds the Velociraptor client from current env (used by POST /velociraptor/reconnect). Defaults
  // to the env-based factory; tests inject a stub so no process is spawned.
  const rebuildVelo = options.rebuildVelociraptorClient ?? buildVelociraptorClient;

  // Diagnostics for the live-monitor features when the picker / auto-discovery come back empty on a
  // real server (#84): the actual artifact `type` strings + counts, and the raw
  // GetClientMonitoringState() shape. Hit it in a browser (localhost) and share the JSON to pin down a
  // version's monitoring proto. 501 when the API isn't configured.
  app.get("/velociraptor/diag", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    try {
      return res.status(200).json(await options.velociraptorClient.diagnostics());
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether the Velociraptor API is configured + the inventory's freshness (so the dashboard can show
  // connection state without a probe). `configured` reflects the LIVE client (reconnect can flip it).
  app.get("/velociraptor/status", async (_req: Request, res: Response) => {
    let updatedAt = "", clientCount = 0;
    if (options.velociraptorClientStore) {
      try { const inv = await options.velociraptorClientStore.load(); updatedAt = inv.updatedAt; clientCount = inv.clients.length; } catch { /* empty */ }
    }
    return res.status(200).json({ configured: !!options.velociraptorClient, updatedAt, clients: clientCount });
  });

  // Re-read DFIR_VELOCIRAPTOR_* from .env (settings saved via the dashboard only write the file),
  // REBUILD the client, and refresh the client inventory — which doubles as a reachability probe
  // (`clients()` round-trips to the server). Lets the analyst connect after configuring Velociraptor,
  // or after the Velociraptor server comes back online, WITHOUT the #1-gotcha restart (the client is
  // stateless — it spawns the binary per query — but a rebuild also applies newly-saved config and
  // flips it on if the config path wasn't set at boot). Also re-arms any persisted live monitors that
  // couldn't be scheduled while the client was absent. Always 200; the body says configured/reachable.
  app.post("/velociraptor/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_VELOCIRAPTOR_");
      options.velociraptorClient = rebuildVelo();
      if (!options.velociraptorClient) {
        return res.status(200).json({ configured: false, ok: false, error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
      }
      try {
        const count = await refreshVeloClients();
        const inv = options.velociraptorClientStore ? await options.velociraptorClientStore.load() : { updatedAt: "", clients: [] };
        void resumeVeloMonitors();   // arm monitors that couldn't start while the client was absent
        logLine(`[velociraptor] reconnected — ${count} enrolled client(s)`);
        return res.status(200).json({ configured: true, ok: true, clients: count, updatedAt: inv.updatedAt });
      } catch (err) {
        return res.status(200).json({ configured: true, ok: false, error: (err as Error).message });
      }
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // Launch the VQL as a single-endpoint COLLECTION on ONE host (issue #70 — the playbook-hunt deploy
  // path for a task tied to exactly one endpoint). Resolves the host → client_id from the persisted
  // INVENTORY (refreshing it once on a miss), then runs collect_client on that client; returns the
  // flow + a GUI deep link. 501 when the Velociraptor API is off; 502 when no client matches the host.
  app.post("/velociraptor/collect-host", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const hostname = typeof req.body?.hostname === "string" ? req.body.hostname.trim() : "";
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    const description = typeof req.body?.description === "string" ? req.body.description : "";
    if (!hostname) return res.status(400).json({ error: "hostname is required" });
    if (!vql) return res.status(400).json({ error: "vql is required" });
    try {
      logLine(`[velociraptor] collect on host ${hostname}: ${description.slice(0, 80)}`);
      const store = options.velociraptorClientStore;
      let result;
      if (store) {
        // Resolve from the inventory file; if the host isn't there yet, refresh once and retry (self-healing).
        let rec = matchClient((await store.load()).clients, hostname);
        if (!rec) { await refreshVeloClients(); rec = matchClient((await store.load()).clients, hostname); }
        if (!rec) return res.status(502).json({ error: `No enrolled Velociraptor client matches host "${hostname}" — refresh the client list (Settings → Velociraptor) or run a fleet hunt instead` });
        result = await options.velociraptorClient.collectOnClient(rec.clientId, vql, description, hostname);
      } else {
        result = await options.velociraptorClient.collectFromHost(hostname, vql, description);
      }
      logLine(`[velociraptor] collection launched -> flow ${result.flowId} on ${result.clientId} (${result.hostname})`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] collect ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Read a single COLLECTION flow's result rows so the dashboard can show them inline + auto-poll (the
  // per-flow analog of /velociraptor/hunt-results). Body `{ clientId, flowId, artifact, sources }`.
  app.post("/velociraptor/collect-results", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const clientId = typeof req.body?.clientId === "string" ? req.body.clientId.trim() : "";
    const flowId = typeof req.body?.flowId === "string" ? req.body.flowId.trim() : "";
    const artifact = typeof req.body?.artifact === "string" ? req.body.artifact.trim() : "";
    const sources = Array.isArray(req.body?.sources) ? req.body.sources.filter((s: unknown): s is string => typeof s === "string") : [];
    if (!clientId || !flowId || !artifact) return res.status(400).json({ error: "clientId, flowId and artifact are required" });
    try {
      const result = await options.velociraptorClient.collectionResults(clientId, flowId, artifact, sources);
      // Also report the flow's terminal STATE so the dashboard can surface an endpoint-side failure
      // (e.g. a bad plugin arg) instead of polling "no results yet". Best-effort — never fail the read.
      let flowState = "";
      let flowError = "";
      try {
        const st = await options.velociraptorClient.flowStatus(clientId, flowId);
        flowState = st.state;
        flowError = st.error;
      } catch { /* status read is best-effort */ }
      return res.status(200).json({ ...result, flowState, flowError });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // AI-suggest proactive Velociraptor VQL fleet-hunts from the case findings (issue #57). Single
  // text-only AI call, EPHEMERAL (no state change) — the dashboard shows each hunt's VQL + rationale
  // for review, then deploys the chosen one through POST /velociraptor/hunt (launchHunt). Needs an AI
  // provider; does NOT need the Velociraptor API (the VQL is useful to copy even when deploy is off).
  app.post("/cases/:id/velociraptor/suggest-hunts", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for hunt suggestions" });
    try {
      const suggestions = await options.pipeline.suggestHunts(req.params.id);
      logLine(`[velociraptor] suggested ${suggestions.length} fleet-hunt(s) for ${req.params.id}`);
      return res.status(200).json({ suggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // AI-suggest a Velociraptor VQL hunt for ONE adversary-emulation "likely next technique" (issue
  // #121). The technique hasn't been observed yet; this turns the suggestion into a runnable, fleet-
  // wide hunt to proactively detect it. Single text-only AI call, EPHEMERAL (no state change) — the
  // dashboard shows the VQL + rationale for review, then deploys via POST /velociraptor/hunt.
  app.post("/cases/:id/adversary-hints/hunt-technique", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for hunt suggestions" });
    const techniqueId = String((req.body as { techniqueId?: unknown })?.techniqueId ?? "").trim();
    const techniqueName = String((req.body as { techniqueName?: unknown })?.techniqueName ?? "").trim() || undefined;
    if (!/^T\d{4}(?:\.\d{3})?$/i.test(techniqueId)) return res.status(400).json({ error: "valid ATT&CK techniqueId required" });
    try {
      const suggestions = await options.pipeline.suggestTechniqueHunts(req.params.id, techniqueId, techniqueName);
      logLine(`[adversary] suggested ${suggestions.length} hunt(s) for technique ${techniqueId} (${req.params.id})`);
      return res.status(200).json({ suggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Memory-forensics "Next-Step" agent (issue #101). When the case has Volatility 3 / Rekall output
  // imported, this makes ONE text-only AI call that reads the memory evidence (process tree, malfind,
  // connections, command lines), spots anomalies, and proposes the exact next Volatility command to
  // run. EPHEMERAL (no state change). Needs an AI provider; returns [] when the case has no memory
  // evidence (the dashboard hides the panel in that case).
  app.post("/cases/:id/memory/next-steps", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for memory next-step suggestions" });
    try {
      const suggestions = await options.pipeline.suggestMemoryNextSteps(req.params.id);
      logLine(`[memory] suggested ${suggestions.length} next step(s) for ${req.params.id}`);
      return res.status(200).json({ suggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Velociraptor triage bundles ───────────────────────────────────────────────────────────
  // On-demand: list collectable CLIENT artifacts → build/save named bundles → run a bundle as a hunt
  // → after a delay, collect results, auto-import (deterministic Velociraptor importer) + synthesize.

  // List the server's collectable CLIENT artifacts (the bundle builder's picker source).
  app.get("/velociraptor/artifacts", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    try {
      const artifacts = await options.velociraptorClient.listClientArtifacts();
      return res.status(200).json({ artifacts });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Bundle CRUD (global / shared across cases). GET works even without a Velociraptor client so an
  // analyst can assemble bundles before connecting a server.
  app.get("/bundles", async (_req: Request, res: Response) => {
    if (!options.artifactBundleStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.artifactBundleStore.list());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/bundles", async (req: Request, res: Response) => {
    if (!options.artifactBundleStore) return res.status(501).json({ error: "bundle store not configured" });
    try {
      const { id, name, description, artifacts, defaultWaitMinutes } = req.body ?? {};
      if (!name) return res.status(400).json({ error: "name is required" });
      if (!Array.isArray(artifacts) || artifacts.length === 0) return res.status(400).json({ error: "at least one artifact is required" });
      const saved = await options.artifactBundleStore.save({ id, name, description, artifacts, defaultWaitMinutes });
      return res.status(201).json(saved);
    } catch (err) {
      if ((err as Error).message.includes("built-in")) return res.status(400).json({ error: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Delete a custom bundle, OR reset an edited built-in back to its shipped default (idempotent for a
  // pristine built-in). 404 only for an unknown non-built-in id.
  app.delete("/bundles/:id", async (req: Request, res: Response) => {
    if (!options.artifactBundleStore) return res.status(501).json({ error: "bundle store not configured" });
    try {
      const removed = await options.artifactBundleStore.delete(req.params.id);
      if (!removed && !options.artifactBundleStore.isBuiltIn(req.params.id)) {
        return res.status(404).json({ error: `bundle "${req.params.id}" not found` });
      }
      return res.status(204).send();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // In-memory auto-collect timers, keyed by HUNT id (globally unique) so concurrent hunts each get
  // their own. Lost on a server restart BY DESIGN — the jobs are persisted (veloHuntStore), so after a
  // restart the dashboard still shows them and the analyst triggers "Collect now". .unref() so a
  // pending timer never blocks exit.
  const veloHuntTimers = new Map<string, NodeJS.Timeout>();

  type ImportBase = { label: string; idPrefix: string; importedAt: string; onProgress?: (done: number, total: number) => void; minSeverity?: Severity };

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
    if (custom) return pipeline.importDeclarative(caseId, text, { importer: custom, ...base });
    switch (kind) {
      case "thor": return pipeline.importThor(caseId, text, base);
      case "siem": return pipeline.importSiem(caseId, text, base);
      case "chainsaw": return pipeline.importChainsaw(caseId, text, base);
      case "hayabusa": return pipeline.importHayabusa(caseId, text, base);
      case "velociraptor": return pipeline.importVelociraptor(caseId, text, base);
      case "network": return pipeline.importNetwork(caseId, text, base);
      case "kape": return pipeline.importKape(caseId, text, base);
      case "cybertriage": return pipeline.importCybertriage(caseId, text, base);
      case "m365": return pipeline.importM365(caseId, text, base);
      case "aws": return pipeline.importAws(caseId, text, base);
      case "cloud": return pipeline.importCloudActivity(caseId, text, base);
      case "plaso": return pipeline.importPlaso(caseId, text, base);
      case "sandbox": return pipeline.importSandbox(caseId, text, base);
      case "memory": return pipeline.importMemory(caseId, text, base);
      case "email": return pipeline.importEmail(caseId, text, base);
      case "thehive": return pipeline.importTheHive(caseId, text, base);
      case "auditd": return pipeline.importAuditd(caseId, text, base);
      case "journald": return pipeline.importJournald(caseId, text, base);
      case "sysdig": return pipeline.importSysdig(caseId, text, base);
      case "wazuh": return pipeline.importWazuh(caseId, text, base);
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
        const s = await options.stateStore.load(caseId);
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
    const pending = veloHuntTimers.get(huntId);
    if (pending) { clearTimeout(pending); veloHuntTimers.delete(huntId); }

    let job = await huntStore.get(caseId, huntId);
    if (!job) return;
    if (job.status === "collecting") return;   // a collection of this hunt is already in flight
    try {
      job = { ...job, status: "collecting" };
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

      // 1) Result ROWS → the Velociraptor importer (detections + telemetry). Resilient: an artifact
      // whose output is too large to fetch is skipped (logged), not fatal — the rest still import, and
      // its uploaded JSON (if any) is still picked up in step 2.
      const { results: map, skipped } = await client.huntResultsByArtifact(job.huntId, job.artifacts, job.filters);
      if (skipped.length) logLine(`[velociraptor] hunt ${job.huntId}: skipped ${skipped.length} oversized/failed artifact(s): ${skipped.join(", ")} — raise DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT / DFIR_VELOCIRAPTOR_MAX_ROWS to include them`);
      const totalRows = Object.values(map).reduce((n, rows) => n + rows.length, 0);
      if (totalRows > 0) {
        const json = JSON.stringify(map);
        const { storedName, importedAt, seq } = await persistEvidence(caseId, `velo-hunt_${job.huntId}.json`, json);
        lastFile = storedName;
        options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing Velociraptor hunt ${job.huntId} rows (${Object.keys(map).length} artifact(s), ${totalRows} row(s))` });
        await pipeline.importVelociraptor(caseId, json, { label: storedName, idPrefix: `${seq}`, importedAt, minSeverity });
        importedAny = true;
      }

      // 2) Uploaded JSON reports (e.g. THOR/Hayabusa) → detect + dispatch. Best-effort: a wrong upload
      // VQL for the server version must not break the rows import (set DFIR_VELOCIRAPTOR_UPLOAD_VQL).
      let uploads: HuntUpload[] = [];
      try { uploads = await client.huntUploads(job.huntId); }
      catch (e) { logLine(`[velociraptor] hunt uploads read failed (override DFIR_VELOCIRAPTOR_UPLOAD_VQL?): ${(e as Error).message}`); }
      for (const up of uploads) {
        const upKind = resolveImportKind(up.name, up.content);   // honor custom importers like /import + /push
        if (upKind === "unknown") continue;
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
          const s = await options.stateStore.load(caseId);
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

      job = { ...job, status: "imported", importedAt: new Date().toISOString(), importFile: lastFile, addedEvents, addedIocs, error: undefined };
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
  }

  // Run a saved bundle as a hunt (optionally scoped by label/OS), schedule auto-collect after
  // waitMinutes (default DFIR_VELO_HUNT_WAIT_MIN / bundle default / 10; clamped 1..1440), and respond
  // immediately. The hunt stays open on the server until its expiry — we just snapshot results later.
  app.post("/cases/:id/velociraptor/run-bundle", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.artifactBundleStore || !options.veloHuntStore) return res.status(501).json({ error: "bundle store not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const bundleId = String(req.body?.bundleId ?? "").trim();
    if (!bundleId) return res.status(400).json({ error: "bundleId is required" });
    try {
      const bundle = await options.artifactBundleStore.get(bundleId);
      if (!bundle) return res.status(404).json({ error: `bundle "${bundleId}" not found` });
      if (!bundle.artifacts.length) return res.status(400).json({ error: "bundle has no artifacts" });

      const fallback = Number(process.env.DFIR_VELO_HUNT_WAIT_MIN) || bundle.defaultWaitMinutes || 10;
      const reqWait = Number(req.body?.waitMinutes);
      const waitMinutes = Math.min(1440, Math.max(1, Number.isFinite(reqWait) && reqWait > 0 ? reqWait : fallback));
      const os = ["windows", "linux", "darwin"].includes(String(req.body?.os)) ? (req.body.os as HuntTarget["os"]) : undefined;
      const target: HuntTarget = {
        includeLabels: toStringArray(req.body?.includeLabels),
        excludeLabels: toStringArray(req.body?.excludeLabels),
        os,
      };
      const minSeverity = parseMinSeverity(req.body?.minSeverity);   // applied to the import at collect time
      // Per-collection timeout (seconds): run override > bundle default > Velociraptor's own default (600s).
      const reqTimeout = Number(req.body?.timeoutSeconds);
      const rawTimeout = Number.isFinite(reqTimeout) && reqTimeout > 0 ? reqTimeout : bundle.timeoutSeconds;
      const timeoutSeconds = typeof rawTimeout === "number" && rawTimeout > 0 ? Math.min(86_400, Math.max(60, Math.floor(rawTimeout))) : undefined;

      logLine(`[velociraptor] run bundle "${bundle.name}" (${bundle.artifacts.length} artifact(s)), collect in ${waitMinutes}m${minSeverity ? `, min severity ${minSeverity}` : ""}${timeoutSeconds ? `, timeout ${timeoutSeconds}s` : ""}`);
      const launch = await options.velociraptorClient.launchArtifactHunt(bundle.artifacts, bundle.name, target, { timeoutSeconds, params: bundle.params });
      const collectAt = new Date(Date.now() + waitMinutes * 60_000).toISOString();
      const job: VeloHuntJob = {
        bundleId: bundle.id, bundleName: bundle.name, artifacts: launch.artifacts,
        huntId: launch.huntId, guiUrl: launch.guiUrl,
        launchedAt: new Date().toISOString(), waitMinutes, collectAt,
        status: "running", target, minSeverity, timeoutSeconds, filters: bundle.filters,
      };
      // Append this hunt (concurrent hunts are kept side by side, keyed by huntId) + its own timer.
      await options.veloHuntStore.upsert(caseId, job);
      options.onVeloHunt?.(caseId);

      const timer = setTimeout(() => { void importVeloHuntResults(caseId, launch.huntId); }, waitMinutes * 60_000);
      timer.unref?.();
      veloHuntTimers.set(launch.huntId, timer);

      return res.status(202).json({ huntId: launch.huntId, guiUrl: launch.guiUrl, collectAt, waitMinutes, artifacts: launch.artifacts });
    } catch (err) {
      logLine(`[velociraptor] run bundle ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // All bundle hunts for a case (newest first) — status + countdown + outcome per hunt. [] when none.
  app.get("/cases/:id/velociraptor/hunt-jobs", async (req: Request, res: Response) => {
    if (!options.veloHuntStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.veloHuntStore.list(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Collect a specific hunt NOW (don't wait for its timer). Body `{ huntId }`; defaults to the most
  // recent hunt when omitted. Runs in the background; poll hunt-jobs. 404 when there's nothing to collect.
  app.post("/cases/:id/velociraptor/collect", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloHuntStore) return res.status(501).json({ error: "hunt store not configured" });
    const caseId = req.params.id;
    const wantedHuntId = String(req.body?.huntId ?? "").trim();
    const jobs = await options.veloHuntStore.list(caseId);
    const job = wantedHuntId ? jobs.find((j) => j.huntId === wantedHuntId) : jobs[0];
    if (!job) return res.status(404).json({ error: wantedHuntId ? `no Velociraptor hunt ${wantedHuntId} for this case` : "no Velociraptor hunt to collect for this case" });
    res.status(202).json({ accepted: true, huntId: job.huntId });
    void importVeloHuntResults(caseId, job.huntId);
  });

  // ── Live Velociraptor CLIENT_EVENT monitoring (#84) ───────────────────────────────────────────

  // List the server's CLIENT_EVENT (continuous monitoring) artifacts for the Monitor-mode picker.
  app.get("/velociraptor/event-artifacts", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    try {
      return res.status(200).json({ artifacts: await options.velociraptorClient.listClientArtifacts("client_event") });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // All live monitors for a case (with status + running stats). [] when monitoring isn't configured.
  app.get("/cases/:id/velociraptor/monitors", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.veloMonitorStore.list(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Start a live monitor: poll a CLIENT_EVENT artifact on one client and stream new rows into the case.
  // Body `{ clientId, artifact, pollSeconds?, hostname?, minSeverity? }`. Idempotent per (client,
  // artifact) — re-adding the same pair updates it in place. The cursor starts at "now" so only events
  // that arrive AFTER the monitor is created are ingested (no history backfill).
  app.post("/cases/:id/velociraptor/monitors", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });
    // `allClients` (or clientId === "*") watches the artifact across EVERY enrolled client in one
    // monitor — no specific endpoint to pick. Otherwise a real client id is required.
    const wantsAll = req.body?.allClients === true || String(req.body?.clientId ?? "").trim() === ALL_CLIENTS;
    const clientId = wantsAll ? ALL_CLIENTS : String(req.body?.clientId ?? "").trim();
    const artifact = String(req.body?.artifact ?? "").trim();
    if (!wantsAll && !/^C\.[A-Za-z0-9]+$/.test(clientId)) return res.status(400).json({ error: "a valid Velociraptor clientId (C....) is required, or set allClients:true" });
    if (!/^[A-Za-z0-9._]+$/.test(artifact)) return res.status(400).json({ error: "a valid CLIENT_EVENT artifact name is required" });
    try {
      const fallback = Number(options.veloMonitorPollSeconds) || 30;
      const reqPoll = Number(req.body?.pollSeconds);
      const pollSeconds = Math.min(3600, Math.max(5, Number.isFinite(reqPoll) && reqPoll > 0 ? Math.floor(reqPoll) : fallback));
      const hostname = String(req.body?.hostname ?? "").trim() || undefined;
      const minSeverity = parseMinSeverity(req.body?.minSeverity);
      const monitor = await createVeloMonitor(caseId, { clientId, artifact, pollSeconds, hostname, minSeverity, allClients: wantsAll });
      return res.status(202).json({ accepted: true, monitor });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Auto-monitor every client-event artifact ALREADY enabled in Velociraptor's client monitoring table
  // (#84 follow-up) — discovers them via GetClientMonitoringState() and starts an ALL-clients monitor
  // for each (idempotent: an existing monitor for the same artifact is refreshed, not duplicated). 422
  // with guidance when nothing is configured / the version's proto differs (set the override env var).
  app.post("/cases/:id/velociraptor/monitors/auto", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });
    try {
      const discovered = await options.velociraptorClient.listMonitoredArtifacts();
      if (!discovered.length) {
        // Capture the RAW monitoring-state shape (which varies by version) — logged AND returned in the
        // response so the analyst can see it in the dashboard and we can model DFIR_VELOCIRAPTOR_MONITORED_VQL.
        let rawSample = "";
        try {
          const raw = await options.velociraptorClient.monitoringStateRaw();
          rawSample = JSON.stringify(raw).slice(0, 2000);
          logLine(`[velo-monitor] auto: monitoring table returned no artifacts. Raw get_client_monitoring() shape: ${rawSample}`);
        } catch (e) { rawSample = `(read failed: ${(e as Error).message})`; logLine(`[velo-monitor] auto: monitoring-state read failed: ${(e as Error).message}`); }
        return res.status(422).json({ error: "no client-event artifacts found in Velociraptor's client monitoring table — enable some in Velociraptor → Client Monitoring first, or (if your version's monitoring proto differs) open /velociraptor/diag and share the output to set DFIR_VELOCIRAPTOR_MONITORED_VQL", discovered: [], rawSample });
      }
      const fallback = Number(options.veloMonitorPollSeconds) || 30;
      const reqPoll = Number(req.body?.pollSeconds);
      const pollSeconds = Math.min(3600, Math.max(5, Number.isFinite(reqPoll) && reqPoll > 0 ? Math.floor(reqPoll) : fallback));
      const minSeverity = parseMinSeverity(req.body?.minSeverity);
      const started: VeloMonitor[] = [];
      for (const artifact of discovered) {
        started.push(await createVeloMonitor(caseId, { clientId: ALL_CLIENTS, artifact, pollSeconds, minSeverity, allClients: true }));
      }
      logLine(`[velo-monitor] auto-started ${started.length} all-clients monitor(s) from the Velociraptor monitoring table for case ${caseId}`);
      return res.status(202).json({ accepted: true, discovered, started });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Stop a monitor (clears its timer + marks it stopped, but keeps the row so it can be resumed).
  app.post("/cases/:id/velociraptor/monitors/:mid/stop", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    stopVeloMonitorTimer(caseId, id);
    await options.veloMonitorStore.upsert(caseId, { ...monitor, status: "stopped" });
    options.onVeloMonitor?.(caseId);
    return res.status(200).json({ ok: true });
  });

  // Resume a stopped monitor (re-arms its timer; keeps the persisted cursor so no re-ingest).
  app.post("/cases/:id/velociraptor/monitors/:mid/start", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    const resumed = { ...monitor, status: "active" as const, lastError: undefined };
    await options.veloMonitorStore.upsert(caseId, resumed);
    scheduleVeloMonitor(caseId, resumed);
    options.onVeloMonitor?.(caseId);
    return res.status(200).json({ ok: true });
  });

  // Poll a monitor NOW (don't wait for its timer) — a "check now" for the analyst. Runs one poll cycle
  // (which also re-arms an active monitor's timer) and returns the updated monitor.
  app.post("/cases/:id/velociraptor/monitors/:mid/poll", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    await pollVeloMonitor(caseId, id);
    return res.status(200).json({ ok: true, monitor: await options.veloMonitorStore.get(caseId, id) });
  });

  // Delete a monitor entirely (stop + remove the row).
  app.delete("/cases/:id/velociraptor/monitors/:mid", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    stopVeloMonitorTimer(caseId, id);
    await options.veloMonitorStore.remove(caseId, id);
    options.onVeloMonitor?.(caseId);
    return res.status(204).end();
  });

  // ── Generic push ingest (#84) ─────────────────────────────────────────────────────────────────
  // An external tool (SIEM webhook, Velociraptor client-event poller, custom script) POSTs an alert
  // payload here with an X-DFIR-Key token. The body is any importDetect-routable shape (artifact-map,
  // SIEM alert, Hayabusa line, { source, events }, raw text…). Runs the SAME import → diff →
  // re-synthesize pipeline as the file Import button; responds 202 immediately, imports in background.
  app.post("/cases/:id/push", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    // Auth: global DFIR_PUSH_TOKEN and/or a per-case token. 403 when push is unconfigured, 401 on a bad key.
    let caseToken: string | undefined;
    if (options.pushTokenStore) { try { caseToken = (await options.pushTokenStore.get(caseId))?.token; } catch { /* none */ } }
    const bearer = (req.get("authorization") || "").replace(/^Bearer\s+/i, "");
    const presented = String(req.get("x-dfir-key") || bearer || "");
    const auth = resolvePushAuth({ globalToken: options.pushToken, caseToken, presented });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });

    const { text, source, filename } = extractPushPayload(req.body);
    if (!text.trim()) return res.status(400).json({ error: "empty push payload" });
    const kind = resolveImportKind(filename, text);
    if (kind === "unknown") return res.status(400).json({ error: "could not detect the payload type — not recognized as any supported import shape" });
    if ((kind === "csv" || kind === "log") && !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for CSV/log analysis" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    logLine(`[push] case ${caseId}: received "${source}" → ${kind}`);
    res.status(202).json({ accepted: true, kind, source });
    // Import in the background; the 202 already went out.
    ingestStreamed(caseId, kind, text, filename, minSeverity)
      .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: `push import failed: ${(err as Error).message}` }));
  });

  // Per-case push token management (#84). GET returns the case token's existence (NOT the secret on a
  // plain GET — it's shown once on generate) plus whether a global token covers every case and the
  // push URL. POST generates/rotates one; DELETE clears it.
  app.get("/cases/:id/push-token", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const globalConfigured = !!(options.pushToken && options.pushToken.trim());
    let rec: { token: string; createdAt: string } | null = null;
    if (options.pushTokenStore) { try { rec = await options.pushTokenStore.get(caseId); } catch { /* none */ } }
    const base = (options.dashboardBaseUrl || "").replace(/\/+$/, "");
    return res.status(200).json({
      configured: !!rec,
      token: rec?.token ?? "",          // shown so Settings can display the active token + curl example
      createdAt: rec?.createdAt ?? "",
      globalConfigured,
      storeAvailable: !!options.pushTokenStore,
      pushUrl: `${base}/cases/${encodeURIComponent(caseId)}/push`,
    });
  });

  app.post("/cases/:id/push-token/generate", async (req: Request, res: Response) => {
    if (!options.pushTokenStore) return res.status(501).json({ error: "push token store not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });
    try {
      const token = generatePushToken();
      const rec = await options.pushTokenStore.set(caseId, token, new Date().toISOString());
      options.onPushToken?.(caseId);
      return res.status(201).json({ token: rec.token, createdAt: rec.createdAt });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/push-token", async (req: Request, res: Response) => {
    if (!options.pushTokenStore) return res.status(501).json({ error: "push token store not configured" });
    try {
      await options.pushTokenStore.clear(req.params.id);
      options.onPushToken?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Push a case to DFIR-IRIS: find-or-create the case by name, then push assets→assets,
  // IOCs→IOCs, forensic timeline→timeline, executive summary→case summary, everything else→notes.
  app.post("/cases/:id/push/iris", async (req: Request, res: Response) => {
    if (!irisClient) return res.status(501).json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const meta = options.reportMetaStore ? await options.reportMetaStore.load(caseId) : undefined;
      // Push the analyst-curated playbook (status-aware) when available, else the raw next steps.
      const playbookTasks = options.playbookStore ? await syncPlaybook(caseId) : undefined;
      logLine(`[iris] ${caseId} push START`);
      const result = await pushCaseToIris(
        irisClient,
        { caseName: caseId, state, meta, playbookTasks: playbookTasks?.length ? playbookTasks : undefined },
        options.irisOptions,
      );
      logLine(`[iris] ${caseId} push DONE -> case ${result.caseId} (${result.created ? "created" : "updated"}); ` +
        `assets +${result.assets.added}/${result.assets.existing}, iocs +${result.iocs.added}/${result.iocs.existing}, ` +
        `timeline +${result.timeline.added}/${result.timeline.existing}, tasks +${result.tasks.added}/${result.tasks.existing}, ` +
        `notes ${result.notes}, warnings ${result.warnings.length}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[iris] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Import an EXISTING DFIR-IRIS case into this Companion case (issue #88) — the reverse of the
  // push. Pull the IRIS case's assets/IOCs/timeline (by IRIS case id or exact name), persist the
  // fetched payload as an evidence-first audit file, then map it DETERMINISTICALLY (no AI call)
  // into the forensic timeline + IOCs and re-synthesize. The fetched payload is the imported
  // "file" so the case keeps a faithful import audit row.
  app.post("/cases/:id/iris-import", async (req: Request, res: Response) => {
    if (!irisClient) return res.status(501).json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const irisCaseId = Number(req.body?.irisCaseId);
    const irisCaseName = typeof req.body?.irisCaseName === "string" ? req.body.irisCaseName.trim() : "";
    if (!Number.isFinite(irisCaseId) && !irisCaseName) {
      return res.status(400).json({ error: "irisCaseId or irisCaseName is required" });
    }

    try {
      logLine(`[iris] ${caseId} import START (iris case ${irisCaseName || `#${irisCaseId}`})`);
      const data = await fetchIrisCase(irisClient, {
        irisCaseId: Number.isFinite(irisCaseId) ? irisCaseId : undefined,
        caseName: irisCaseName || undefined,
      });
      if (data.assets.length === 0 && data.iocs.length === 0 && data.timeline.length === 0) {
        return res.status(400).json({ error: "the IRIS case has no assets, IOCs or timeline events to import" });
      }

      const payload = JSON.stringify(data, null, 2);
      const seq = await store.nextImportSeq(caseId);
      const safeBase = (data.caseName || `iris-case-${data.irisCaseId}`).replace(/[^\w.\-]+/g, "_").slice(0, 60) || "iris-case";
      const storedName = `${String(seq).padStart(4, "0")}_${safeBase}.json`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, payload);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName: `DFIR-IRIS case ${data.caseName ?? `#${data.irisCaseId}`}`,
        rows: data.timeline.length + data.assets.length, bytes: Buffer.byteLength(payload, "utf8"),
      });

      res.status(202).json({
        accepted: true, file: storedName,
        irisCaseId: data.irisCaseId, caseName: data.caseName,
        timeline: data.timeline.length, assets: data.assets.length, iocs: data.iocs.length,
      });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing DFIR-IRIS case ${data.caseName ?? `#${data.irisCaseId}`}` });
      void options.pipeline.importIris(caseId, data, { label: storedName, idPrefix: `iris${seq}`, importedAt })
        .then(() => {
          logLine(`[iris] ${caseId} import DONE (iris case ${data.caseName ?? `#${data.irisCaseId}`})`);
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
          resynthesizeInBackground(caseId);
        })
        .catch((err) => {
          logLine(`[iris] ${caseId} import ERROR: ${(err as Error).message}`);
          options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
        });
      return;
    } catch (err) {
      logLine(`[iris] ${caseId} import ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a Timesketch push target is configured (so the dashboard can show/hide the button).
  app.get("/timesketch/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.timesketchClient, baseUrl: options.timesketchOptions?.baseUrl });
  });

  // Push a case to Timesketch: log in, find-or-create the sketch by name (= the Companion case id),
  // then upload the forensic timeline as a timeline. The managed timeline is clean-replaced so a
  // re-push never duplicates events.
  app.post("/cases/:id/push/timesketch", async (req: Request, res: Response) => {
    if (!options.timesketchClient) return res.status(501).json({ error: "Timesketch not configured (set DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD)" });
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.reportWriter.filteredState(caseId);
      logLine(`[timesketch] ${caseId} push START`);
      const result = await pushCaseToTimesketch(options.timesketchClient, { sketchName: caseId, state }, options.timesketchOptions);
      logLine(`[timesketch] ${caseId} push DONE -> sketch ${result.sketchId} (${result.created ? "created" : "updated"}); ` +
        `timeline "${result.timelineName}" events ${result.events}${result.replacedTimeline ? " (replaced)" : ""}, warnings ${result.warnings.length}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[timesketch] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a MISP push target is configured (so the dashboard can show/hide the button).
  app.get("/misp/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.mispPushClient, baseUrl: options.mispPushOptions?.baseUrl });
  });

  // Push a case to MISP: find-or-create the event by the idempotency tag, then push
  // IOCs as attributes and MITRE techniques as tags. Idempotent: re-push adds only
  // what's missing (attributes deduplicated by value).
  app.post("/cases/:id/push/misp", async (req: Request, res: Response) => {
    if (!options.mispPushClient) return res.status(501).json({ error: "MISP not configured (set DFIR_MISP_URL and DFIR_MISP_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      logLine(`[misp] ${caseId} push START`);
      const result = await pushCaseToMisp(options.mispPushClient, { caseId, state }, options.mispPushOptions);
      logLine(`[misp] ${caseId} push DONE -> event ${result.eventId} (${result.created ? "created" : "updated"}); ` +
        `attributes +${result.attributes.added}/${result.attributes.existing}, tags +${result.tags}, warnings ${result.warnings.length}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[misp] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a Notion export target is configured (so the dashboard can show/hide the option and
  // decide whether to ask for a parent in the "new page" modal).
  app.get("/notion/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.notionClient,
      hasDatabase: !!options.notionOptions?.databaseId,
      hasParent: !!options.notionOptions?.parentPageId,
    });
  });

  // Export a case into a Notion page. The Companion writes ALL its content inside ONE managed
  // toggle block it owns; a re-export refreshes that block and never touches the investigators'
  // own notes/screenshots. Body: { mode: "new"|"existing", page?, parent?, database? }.
  app.post("/cases/:id/push/notion", async (req: Request, res: Response) => {
    if (!options.notionClient) return res.status(501).json({ error: "Notion not configured (set DFIR_NOTION_TOKEN)" });
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    if (!options.notionExportStore) return res.status(501).json({ error: "notion export store not configured" });
    const caseId = req.params.id;
    const body = req.body ?? {};
    const mode = body.mode === "existing" ? "existing" : "new";

    const target: NotionPushTarget = { mode };
    if (mode === "existing") {
      const pageId = parseNotionPageId(typeof body.page === "string" ? body.page : "");
      if (!pageId) return res.status(400).json({ error: "could not read a Notion page id from the supplied page URL/ID" });
      target.pageId = pageId;
    } else {
      const parent = typeof body.parent === "string" ? parseNotionPageId(body.parent) : null;
      const database = typeof body.database === "string" ? parseNotionPageId(body.database) : null;
      if (parent) target.parentPageId = parent;
      if (database) target.databaseId = database;
    }

    try {
      const state = await options.reportWriter.filteredState(caseId);
      const meta = options.reportMetaStore ? await options.reportMetaStore.load(caseId) : undefined;
      logLine(`[notion] ${caseId} export START (${mode})`);
      const result = await pushCaseToNotion(
        options.notionClient,
        { caseName: caseId, state, meta },
        target,
        options.notionOptions,
        options.notionExportStore,
      );
      logLine(`[notion] ${caseId} export DONE -> page ${result.pageId} (${result.created ? "created" : "updated"}); ` +
        `+${result.blocksAppended} block(s) in ${result.batches} batch(es), archived ${result.blocksArchived}, warnings ${result.warnings.length}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[notion] ${caseId} export ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a ClickUp push target is configured (so the dashboard can show/hide the option).
  app.get("/clickup/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.clickupClient,
      hasDefaultList: !!options.clickupOptions?.defaultListId,
      defaultListId: options.clickupOptions?.defaultListId ?? "",
    });
  });

  // The last ClickUp export pointer (saved list id) so the modal can prefill it.
  app.get("/cases/:id/clickup-export", async (req: Request, res: Response) => {
    if (!options.clickupExportStore) return res.status(501).json({ error: "ClickUp not configured" });
    try {
      return res.status(200).json(await options.clickupExportStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Push the Response Playbook to a ClickUp list as tasks. Body { listId? } — falls back to the
  // saved list, then the configured default. Re-export UPDATES the tasks it created (by remembered
  // id) instead of duplicating.
  app.post("/cases/:id/push/clickup", async (req: Request, res: Response) => {
    if (!options.clickupClient) return res.status(501).json({ error: "ClickUp not configured (set DFIR_CLICKUP_TOKEN)" });
    if (!options.clickupExportStore) return res.status(501).json({ error: "clickup export store not configured" });
    if (!options.playbookStore || !options.stateStore) return res.status(501).json({ error: "playbook not configured" });
    const caseId = req.params.id;
    try {
      const saved = await options.clickupExportStore.load(caseId);
      const requested = typeof req.body?.listId === "string" ? req.body.listId.trim() : "";
      const listId = requested || saved.listId || options.clickupOptions?.defaultListId || "";
      if (!listId) return res.status(400).json({ error: "a ClickUp list id is required" });
      const tasks = await syncPlaybook(caseId);
      if (!tasks.length) return res.status(400).json({ error: "the playbook is empty — run synthesis or add tasks first" });
      logLine(`[clickup] ${caseId} push START -> list ${listId} (${tasks.length} tasks)`);
      const result = await pushPlaybookToClickUp(
        options.clickupClient,
        { caseId, listId, tasks },
        options.clickupExportStore,
        new Date().toISOString(),
      );
      logLine(`[clickup] ${caseId} push DONE: +${result.created} created, ${result.updated} updated, ${result.skipped} skipped, warnings ${result.warnings.length}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[clickup] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // ── Notifications (issue #58) ─────────────────────────────────────────────────────────────
  // Global channel config: Slack/Teams webhooks + SMTP email, with per-channel severity threshold
  // and per-event-kind toggles. Opt-in (the store starts empty). Secrets (webhook URLs, SMTP
  // passwords) are REDACTED in every response — the browser only learns whether each is set.

  app.get("/notifications/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.notificationStore, emailEnabled: !!options.notifyEmailEnabled });
  });

  app.get("/notifications", async (_req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(200).json([]);
    try {
      return res.status(200).json((await options.notificationStore.load()).map(redactChannel));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/notifications", async (req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(501).json({ error: "notifications not configured" });
    const parsed = parseChannelInput(req.body);
    if (!parsed.ok || !parsed.draft) return res.status(400).json({ error: parsed.error ?? "invalid channel" });
    try {
      const channel = await options.notificationStore.add(parsed.draft);
      logLine(`[notify] channel added: ${channel.type} "${channel.name}" (${channel.id})`);
      return res.status(201).json(redactChannel(channel));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/notifications/:id", async (req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(501).json({ error: "notifications not configured" });
    try {
      const existing = await options.notificationStore.get(req.params.id);
      if (!existing) return res.status(404).json({ error: "notification channel not found" });
      // Pass `existing` so a blank (redacted) webhook URL keeps the saved one.
      const parsed = parseChannelInput(req.body, existing);
      if (!parsed.ok || !parsed.draft) return res.status(400).json({ error: parsed.error ?? "invalid channel" });
      const channel = await options.notificationStore.update(req.params.id, parsed.draft);
      if (!channel) return res.status(404).json({ error: "notification channel not found" });
      return res.status(200).json(redactChannel(channel));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/notifications/:id", async (req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(501).json({ error: "notifications not configured" });
    try {
      const removed = await options.notificationStore.remove(req.params.id);
      if (!removed) return res.status(404).json({ error: "notification channel not found" });
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Send a test notification to one channel ({ channelId }) or all configured channels. Bypasses
  // the enable/threshold/kind filters so a disabled or high-threshold channel can be verified.
  app.post("/notifications/test", async (req: Request, res: Response) => {
    if (!options.notificationStore || !options.notifier) return res.status(501).json({ error: "notifications not configured" });
    try {
      const channelId = typeof req.body?.channelId === "string" ? req.body.channelId : undefined;
      const results = await options.notifier.test(channelId, new Date().toISOString());
      if (!results.length) return res.status(404).json({ error: "no matching channel to test" });
      return res.status(200).json({ results });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // AI analysis on/off per case. GET reads it; POST { enabled } sets it. Turning it
  // ON triggers a background backfill of everything captured while it was off.
  app.get("/cases/:id/ai-control", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await getControl(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/ai-control", async (req: Request, res: Response) => {
    try {
      const body = req.body ?? {};
      const enabled = Boolean(body.enabled);
      const patch: Parameters<typeof setControl>[1] = { enabled };
      // Optional: toggle whether the analyst notebook is sent to the synthesis prompt.
      if (typeof body.includeNotebook === "boolean") patch.includeNotebook = body.includeNotebook;
      const prev = await getControl(req.params.id);
      const next = await setControl(req.params.id, patch);
      if (!enabled) {
        buffers.set(req.params.id, []); // drop pending buffer when pausing
        options.onAiStatus?.(req.params.id, { status: "idle", at: new Date().toISOString(), detail: "AI paused" });
      } else if (!prev.enabled) {
        void backfill(req.params.id); // resumed → analyze the gap
      }
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Client-confirmed legitimate findings/IOCs (false positives). Marking one
  // re-runs synthesis so the AI re-derives its conclusions without it.
  const legitimate = new LegitimateStore(store);
  // The active NSRL RDS SQLite connection (#63). Mutable: the Settings → NSRL connect/disconnect
  // routes can swap it at runtime (unless env-managed). Starts from the startup-resolved DB.
  let nsrlDb = options.nsrlDb;

  // Per-case anonymization control (default ON) + the analyst-added entity list. Screenshots are
  // OCR-redacted (best-effort) when the vision provider is external, so the dashboard warns (anon on
  // + external) that residual text may survive — `screenshotWarning` gates that notice.
  const anonControl = new AnonControlStore(store);
  const customEntities = new CustomEntitiesStore(store);
  const discoveredEntities = new DiscoveredEntitiesStore(store);
  const visionIsLocal = isLocalAiProvider(process.env.DFIR_AI_PROVIDER, process.env.DFIR_AI_BASE_URL);

  // Anonymization control: GET reports the control + whether screenshots are exposed (anon on +
  // external vision). POST updates it and, when `enabled` flips, forces a re-synth so conclusions
  // reflect the new wire policy (the skip-if-unchanged hash is keyed on real inputs and won't notice).
  app.get("/cases/:id/anon-control", async (req: Request, res: Response) => {
    try {
      const c = await anonControl.load(req.params.id);
      return res.status(200).json({ ...c, screenshotWarning: c.enabled && !visionIsLocal });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-control", async (req: Request, res: Response) => {
    try {
      const cur = await anonControl.load(req.params.id);
      // Only accept KNOWN category keys with BOOLEAN values; anything else keeps the current value.
      // (A blind spread would let `{categories:{IP:null}}` persist a falsy non-boolean and silently
      // disable a category while `enabled` stays true.)
      const reqCats = (req.body?.categories ?? {}) as Record<string, unknown>;
      const categories = { ...cur.categories };
      for (const k of Object.keys(categories) as (keyof AnonControl["categories"])[]) {
        if (typeof reqCats[k] === "boolean") categories[k] = reqCats[k] as boolean;
      }
      const next: AnonControl = {
        enabled: typeof req.body?.enabled === "boolean" ? req.body.enabled : cur.enabled,
        categories,
        redactSecrets: typeof req.body?.redactSecrets === "boolean" ? req.body.redactSecrets : cur.redactSecrets,
      };
      await anonControl.save(req.params.id, next);
      if (next.enabled !== cur.enabled && options.pipeline && hasAiProvider()) {
        void options.pipeline.synthesize(req.params.id, { force: true }).catch(() => {});
      }
      return res.status(200).json({ ...next, screenshotWarning: next.enabled && !visionIsLocal });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The entities that will be anonymized for a case: `auto` (auto-discovery — derived from the
  // timeline PLUS entities the OCR pass tokenized out of screenshots, grouped by category, with
  // analyst-suppressed values removed) + `custom` (analyst-added) + `suppressed` (removed values).
  // POST replaces the custom list; the /suppress + /unsuppress routes manage auto-discovery removals.
  app.get("/cases/:id/anon-entities", async (req: Request, res: Response) => {
    try {
      const custom = await customEntities.load(req.params.id);
      const disc = await discoveredEntities.load(req.params.id);
      const suppressed = new Set(disc.suppressed);
      const groups: Record<AnonTokenCategory, string[]> = { IP: [], EMAIL: [], USER: [], HOST: [], DOMAIN: [], PATH: [], OTHER: [] };
      if (options.stateStore) {
        const d = deriveKnownEntities(await options.stateStore.load(req.params.id));
        groups.HOST.push(...d.hosts);
        groups.USER.push(...d.accounts);
        groups.DOMAIN.push(...d.internalDomains);
      }
      for (const e of disc.discovered) groups[e.category]?.push(e.value);
      // Per group: drop suppressed values + dedupe case-insensitively (keep first spelling).
      const clean = (arr: string[]): string[] => {
        const seen = new Set<string>();
        const out: string[] = [];
        for (const v of arr) {
          const k = v.toLowerCase();
          if (suppressed.has(k) || seen.has(k)) continue;
          seen.add(k);
          out.push(v);
        }
        return out;
      };
      const auto = {
        hosts: clean(groups.HOST), accounts: clean(groups.USER), internalDomains: clean(groups.DOMAIN),
        ips: clean(groups.IP), emails: clean(groups.EMAIL), paths: clean(groups.PATH), other: clean(groups.OTHER),
      };
      return res.status(200).json({ auto, custom, suppressed: disc.suppressed });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-entities", async (req: Request, res: Response) => {
    try {
      const entities = sanitizeCustomEntities(req.body?.entities);
      await customEntities.save(req.params.id, entities);
      return res.status(200).json({ custom: entities });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  // Remove a wrong entity from auto-discovery: it's hidden from the list AND never anonymized again
  // (the anonymizer's suppression set), reversible via /unsuppress.
  app.post("/cases/:id/anon-entities/suppress", async (req: Request, res: Response) => {
    try {
      const value = typeof req.body?.value === "string" ? req.body.value.trim() : "";
      if (!value) return res.status(400).json({ error: "value is required" });
      const next = await discoveredEntities.suppress(req.params.id, value);
      return res.status(200).json({ suppressed: next.suppressed });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-entities/unsuppress", async (req: Request, res: Response) => {
    try {
      const value = typeof req.body?.value === "string" ? req.body.value.trim() : "";
      if (!value) return res.status(400).json({ error: "value is required" });
      const next = await discoveredEntities.unsuppress(req.params.id, value);
      return res.status(200).json({ suppressed: next.suppressed });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Redacted case package (#54): a shareable ZIP for external parties. Internal IPs / hosts /
  // usernames / emails / paths in the report (and CSVs / state JSON) are tokenized, secrets are
  // one-way redacted, screenshot EXIF is stripped, and detectable PII text in screenshots is
  // blurred (best-effort OCR). AI provider keys + per-case config are NEVER included — the package
  // is built from a curated allowlist, not a copy of the case folder. Built fresh per request; the
  // canonical on-disk report (which keeps the REAL values) is never touched. Query flags
  // (?screenshots=0 / ?blur=0 / ?csvs=0 / ?state=0 / ?report=0) opt parts out.
  app.get("/cases/:id/export/redacted", async (req: Request, res: Response) => {
    if (!options.reportWriter || !options.stateStore) {
      return res.status(501).json({ error: "report writer not configured" });
    }
    if (!isValidCaseId(req.params.id)) {
      return res.status(400).json({ error: "invalid case id" });
    }
    try {
      const exportOptions = resolveRedactedExportOptions(req.query as Record<string, unknown>);
      const { zip } = await buildRedactedExport(
        {
          store,
          reportWriter: options.reportWriter,
          stateStore: options.stateStore,
          customEntities,
          discoveredEntities,
          // Victim org domains/emails the analyst entered for the exposure check are PII too —
          // feed them to the anonymizer so they're tokenized even when absent from the timeline.
          customerStore: new CustomerStore(store),
          ocrRunner: options.ocrRunner ?? new TesseractOcrRunner(),
        },
        req.params.id,
        exportOptions,
      );
      res.type("application/zip");
      res.setHeader("Content-Disposition", `attachment; filename="${redactedExportFilename(req.params.id)}"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(zip);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Customer exposure / breach-data lookups. This is deliberately NOT IOC enrichment:
  // only manually entered customer domains/emails plus observed emails under those customer
  // domains are sent to providers. Remote domains collected as IOCs are never queried here.
  const customerStore = new CustomerStore(store);
  const customerExposureStore = new CustomerExposureStore(store);
  const customerExposureProviders = options.customerExposureProviders ?? [];

  app.get("/cases/:id/customer-exposure", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      const targets = await customerStore.load(req.params.id);
      return res.status(200).json({
        anyConfigured: customerExposureProviders.length > 0,
        providers: customerExposureProviders.map((p) => p.name),
        targets,
        effectiveTargets: buildCustomerExposureTargets(state, targets),
        exposure: await customerExposureStore.load(req.params.id),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/customer-exposure/targets", async (req: Request, res: Response) => {
    try {
      const targets = sanitizeTargets(req.body ?? {});
      await customerStore.save(req.params.id, targets);
      return res.status(200).json({ targets });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/customer-exposure/check", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    if (customerExposureProviders.length === 0) {
      return res.status(501).json({ error: "no customer exposure providers configured (set DFIR_LEAKCHECK_KEY / DFIR_DEHASHED_KEY / DFIR_HIBP_KEY / DFIR_SHODAN_KEY)" });
    }
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const targets = await customerStore.load(caseId);
      // Provider selection (like the enrichment per-source picker): a `providers` list in the
      // request body wins (one-off run), else the saved selection (customer.json), else all
      // configured. A name not matching a configured provider is simply ignored.
      const requested = parseList(req.body?.providers).map((s) => s.trim()).filter(Boolean);
      const selection = requested.length ? requested : (targets.providers?.length ? targets.providers : null);
      const active = selection ? customerExposureProviders.filter((p) => selection.includes(p.name)) : customerExposureProviders;
      if (active.length === 0) return res.status(400).json({ error: "no matching exposure providers selected" });
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: "checking customer exposure" });
      const summary = await summarizeExposure(state, targets, active, {
        delayMs: options.customerExposureDelayMs,
      });
      await customerExposureStore.save(caseId, summary);
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `customer exposure: ${summary.results.length} hit(s), ${summary.errors.length} error(s)` });
      logLine(`[exposure] ${caseId} providers=[${summary.providers.join(", ")}] domains=${summary.targets.domains.length} emails=${summary.targets.emails.length} hits=${summary.results.length} errors=${summary.errors.length}`);
      return res.status(200).json(summary);
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

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
    void (async () => {
      const providers = await enabledProvidersFor(caseId);
      if (providers.length === 0) { enrichPending.delete(caseId); return; }     // nothing enabled — drop any stale pending mark so the poller can idle
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `enriching IOCs (${providers.map((p) => p.name).join(", ")})` });
      const state = await options.stateStore!.load(caseId);
      logLine(`[enrich] ${caseId} START providers=[${providers.map((p) => p.name).join(", ")}] force=${force} iocs=${state.iocs.length}`);
      const { iocs, summary } = await enrichIocs(state.iocs, {
        providers,
        delayMs: options.enrichDelayMs,
        perProviderDelayMs: options.enrichProviderDelayMs,
        maxIocs: options.enrichMaxIocs,
        force,
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
          maxChecks: options.enrichMaxIocs,
          force,
        });
        merged = { ...merged, forensicTimeline: events };
        chainSummary = cs;
      }

      await options.stateStore!.save(merged);
      options.onState?.(merged);
      const chainNote = chainSummary ? `; chains ${chainSummary.anomalies} anomalous/${chainSummary.checked}` : "";
      const skipNote = summary.unavailable.length ? `; skipped ${summary.unavailable.join(", ")} (unreachable — will retry)` : "";
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `enriched ${summary.withHits}/${summary.queried} (errors ${summary.errors})${chainNote}${skipNote}` });
    })().catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
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
    if (!hasAiProvider()) { autoEnrichIfEnabled(caseId); return; }
    void (async () => {
      // Synthesis is an LLM call — respect the per-case AI toggle, exactly like the /captures
      // path (AI analysis only runs when enabled for the case). With AI off, a deterministic
      // import still populates the forensic timeline + IOCs; it just doesn't trigger LLM
      // synthesis — findings / attacker-path / MITRE wait until AI is turned on and the case is
      // re-synthesized. Enrichment is a separate, independently-gated feature (threat-intel
      // lookups, not an LLM call), so it still runs regardless of the AI toggle.
      if (!(await getControl(caseId)).enabled) { autoEnrichIfEnabled(caseId); return; }
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "re-synthesizing without legitimate items" });
      try {
        await pipeline.synthesize(caseId);
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        autoEnrichIfEnabled(caseId);
      } catch (err) {
        options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
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

  // #76: restore a full investigation state from an undo/redo checkpoint, verbatim — findings, IOCs,
  // timeline, MITRE, attacker path, the lot (no AI re-synthesis; the snapshot already holds the exact
  // prior conclusions). Keeps the case id, stamps updatedAt. Returns the saved state so the caller
  // can broadcast it (null when no state store is wired — routes gate on this).
  async function restoreImportState(caseId: string, snapState: InvestigationState): Promise<InvestigationState | null> {
    if (!options.stateStore) return null;
    const next: InvestigationState = { ...snapState, caseId, updatedAt: new Date().toISOString() };
    await options.stateStore.save(next);
    return next;
  }

  app.get("/cases/:id/legitimate", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await legitimate.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Build a marker from one request item (kind/ref/note/label). Returns null when ref is empty
  // so the caller can reject (single) or skip (batch). Shared by the single + batch routes.
  const buildLegitMarker = (item: {
    kind?: unknown; ref?: unknown; note?: unknown; label?: unknown;
  }): LegitimateMarker | null => {
    const rawKind = item?.kind;
    const kind: LegitimateMarker["kind"] =
      rawKind === "ioc" ? "ioc" : rawKind === "event" ? "event" : "finding";
    const ref = String(item?.ref ?? "").trim();
    if (!ref) return null;
    const note = String(item?.note ?? "");
    // Optional human-readable label (e.g. a forensic event's description) so the
    // "Confirmed Legitimate" panel can show something meaningful for opaque ids.
    const label = item?.label != null ? String(item.label) : undefined;
    return { id: markerId(kind, ref), kind, ref, note, markedAt: new Date().toISOString(), ...(label ? { label } : {}) };
  };

  app.post("/cases/:id/legitimate", async (req: Request, res: Response) => {
    try {
      const marker = buildLegitMarker(req.body ?? {});
      if (!marker) return res.status(400).json({ error: "ref is required" });
      const markers = await legitimate.load(req.params.id);
      const next = [...markers.filter((m) => m.id !== marker.id), marker];
      await legitimate.save(req.params.id, next);
      options.onLegitimate?.(req.params.id);
      resynthesizeInBackground(req.params.id); // re-derive conclusions without it
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Mark MANY entities legitimate in one shot — one read-modify-write + a SINGLE re-synthesis,
  // instead of N concurrent /legitimate calls that would race on legitimate.json (last write wins)
  // and each kick off their own re-synthesis. The dashboard's bulk "Mark Legitimate" uses this.
  // Body: { items: [{ kind, ref, note?, label? }, …], note? } — a top-level note is the fallback
  // reason for items that don't carry their own.
  app.post("/cases/:id/legitimate/batch", async (req: Request, res: Response) => {
    try {
      const rawItems = Array.isArray(req.body?.items) ? req.body.items : [];
      const fallbackNote = req.body?.note != null ? String(req.body.note) : "";
      const built = rawItems
        .map((it: { kind?: unknown; ref?: unknown; note?: unknown; label?: unknown }) =>
          buildLegitMarker({ ...it, note: it?.note ?? fallbackNote }))
        .filter((m: LegitimateMarker | null): m is LegitimateMarker => m !== null);
      if (!built.length) return res.status(400).json({ error: "at least one valid item (with a ref) is required" });
      const markers = await legitimate.load(req.params.id);
      // De-dupe within the batch and against existing markers (last occurrence wins) by id.
      const byId = new Map<string, LegitimateMarker>(markers.map((m) => [m.id, m]));
      for (const m of built) byId.set(m.id, m);
      const next = [...byId.values()];
      await legitimate.save(req.params.id, next);
      options.onLegitimate?.(req.params.id);
      resynthesizeInBackground(req.params.id); // ONE re-synthesis for the whole batch
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manually add a forensic event the AI didn't catch. Appended to the timeline (kept sorted by
  // event time), then re-synthesized so it weaves into findings/MITRE (a high-severity manual
  // event earns a finding via the backfill). Synthesis preserves the timeline, so it survives.
  app.post("/cases/:id/events", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const event = buildManualEvent(req.body);
      const state = await options.stateStore.load(caseId);
      const forensicTimeline = [...state.forensicTimeline, event].sort(byEventTime);
      const next = { ...state, forensicTimeline, updatedAt: new Date().toISOString() };
      await options.stateStore.save(next);
      options.onState?.(next);
      resynthesizeInBackground(caseId);
      logLine(`[manual] ${caseId} added event ${event.id} (${event.severity})`);
      return res.status(201).json(event);
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: err.issues.map((i) => i.message).join("; ") });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manually add an IOC the AI didn't catch. Appended to the case IOCs (deduped by value) and
  // enriched if enrichment is enabled for the case.
  app.post("/cases/:id/iocs", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const ioc = buildManualIoc(req.body);
      const state = await options.stateStore.load(caseId);
      if (state.iocs.some((i) => i.value.toLowerCase() === ioc.value.toLowerCase())) {
        return res.status(409).json({ error: `IOC already exists: ${ioc.value}` });
      }
      const next = { ...state, iocs: [...state.iocs, ioc], updatedAt: new Date().toISOString() };
      await options.stateStore.save(next);
      options.onState?.(next);
      autoEnrichIfEnabled(caseId);
      logLine(`[manual] ${caseId} added ioc ${ioc.id} (${ioc.type})`);
      return res.status(201).json(ioc);
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: err.issues.map((i) => i.message).join("; ") });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/legitimate/remove", async (req: Request, res: Response) => {
    try {
      const id = String(req.body?.id ?? "");
      const markers = await legitimate.load(req.params.id);
      const next = markers.filter((m) => m.id !== id);
      await legitimate.save(req.params.id, next);
      options.onLegitimate?.(req.params.id);
      resynthesizeInBackground(req.params.id);
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Enrich a specific subset of the case's IOCs — identified by ID — without touching the
  // rest. Runs enrichIocs on the selected subset, then merges the results back. This is the
  // backend for the dashboard bulk-select "Enrich selected" action. Runs in the background
  // (202 accepted) so the caller isn't blocked on N provider round-trips.
  // Body: { iocIds: string[], force?: boolean }
  app.post("/cases/:id/iocs/bulk-enrich", async (req: Request, res: Response) => {
    const providers = options.enrichmentProviders ?? [];
    if (providers.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET / DFIR_MISP_* / DFIR_YETI_*)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const rawIds = Array.isArray(req.body?.iocIds) ? req.body.iocIds : [];
    const iocIds = (rawIds as unknown[]).map(String).filter(Boolean);
    if (!iocIds.length) return res.status(400).json({ error: "iocIds must be a non-empty array" });
    const force = req.body?.force === true;
    try {
      const state = await options.stateStore.load(caseId);
      const targetSet = new Set<string>(iocIds);
      const subset = state.iocs.filter((i) => targetSet.has(i.id));
      if (subset.length === 0) return res.status(404).json({ error: "none of the specified IOC IDs were found in this case" });
      const enabledProviders = await enabledProvidersFor(caseId);
      if (enabledProviders.length === 0) return res.status(422).json({ error: "no enrichment providers enabled for this case — enable providers in the enrichment panel first" });
      void (async () => {
        options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `enriching ${subset.length} selected IOC(s)` });
        const { iocs: enrichedSubset, summary } = await enrichIocs(subset, {
          providers: enabledProviders,
          delayMs: options.enrichDelayMs,
          perProviderDelayMs: options.enrichProviderDelayMs,
          maxIocs: options.enrichMaxIocs,
          force,
          health: enrichHealth,
          onProgress: (done, total) => options.onAiStatus?.(caseId, {
            status: "analyzing", phase: "extracting", at: new Date().toISOString(),
            detail: `enriching selected IOC ${done}/${total}`,
          }),
        });
        const current = await options.stateStore!.load(caseId);
        const merged = mergeEnrichedSubset(current.iocs, enrichedSubset);
        const next = { ...current, iocs: merged, updatedAt: new Date().toISOString() };
        await options.stateStore!.save(next);
        options.onState?.(next);
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `enriched ${summary.withHits}/${summary.queried} selected IOC(s) (errors ${summary.errors})` });
        logLine(`[enrich] ${caseId} bulk ids=${iocIds.length} queried=${summary.queried} hits=${summary.withHits} errors=${summary.errors}`);
      })().catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return res.status(202).json({ accepted: true, iocCount: subset.length, providers: enabledProviders.map((p) => p.name) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add a triage label to many IOCs in one request. Serializes the TagsStore writes so
  // concurrent requests don't clobber each other's read-modify-write on tags.json.
  // Body: { iocIds: string[], label: string, author?: string }
  app.post("/cases/:id/iocs/bulk-tag", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const rawIds = Array.isArray(req.body?.iocIds) ? req.body.iocIds : [];
    const iocIds = (rawIds as unknown[]).map(String).filter(Boolean);
    const label = typeof req.body?.label === "string" ? req.body.label.trim() : "";
    const author = typeof req.body?.author === "string" ? req.body.author.trim() : "";
    if (!iocIds.length) return res.status(400).json({ error: "iocIds must be a non-empty array" });
    if (!label) return res.status(400).json({ error: "label is required" });
    const caseId = req.params.id;
    try {
      const tags: Tag[] = [];
      for (const id of iocIds) {
        tags.push(await options.tagsStore.add(caseId, { targetType: "ioc", targetId: id, label, author }));
      }
      options.onTags?.(caseId);
      return res.status(200).json(tags);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── IOC whitelist (Phase 2 of #35) ─────────────────────────────────────────────────────────
  // A GLOBAL, environment-level set of "known-good" patterns the analyst maintains (internal IP
  // ranges as CIDR, known-good hashes, regexes for internal domains). An IOC matching a rule is
  // auto-marked LEGITIMATE — reusing the legitimate machinery, so it's reversible and shows in the
  // "Confirmed Legitimate" panel. Auto-applied on import; also on demand per case.

  // Apply the whitelist to a case's current IOCs: add a legitimate marker for each match that isn't
  // already marked. Pure read-modify-write on legitimate.json (no re-synthesis here — the caller
  // decides). Returns how many IOCs matched and how many NEW markers were added.
  async function applyWhitelistToCase(caseId: string): Promise<{ matched: number; added: number }> {
    if (!options.iocWhitelistStore || !options.stateStore) return { matched: 0, added: 0 };
    const rules = await options.iocWhitelistStore.load();
    if (rules.length === 0) return { matched: 0, added: 0 };
    const state = await options.stateStore.load(caseId);
    const matches = whitelistMatches(state.iocs, rules);
    if (matches.length === 0) return { matched: 0, added: 0 };
    const markers = await legitimate.load(caseId);
    const byId = new Map<string, LegitimateMarker>(markers.map((m) => [m.id, m]));
    let added = 0;
    for (const { ioc, rule } of matches) {
      const id = markerId("ioc", ioc.value);
      if (byId.has(id)) continue;
      byId.set(id, {
        id, kind: "ioc", ref: ioc.value,
        note: `auto-whitelist: ${rule.match} ${rule.pattern}${rule.note ? ` — ${rule.note}` : ""}`,
        markedAt: new Date().toISOString(), label: ioc.value,
      });
      added++;
    }
    if (added > 0) await legitimate.save(caseId, [...byId.values()]);
    return { matched: matches.length, added };
  }

  // Apply the deobfuscation pass to a case: scan the forensic timeline for obfuscated command
  // lines (PowerShell -enc, base64 blobs), decode them, extract hidden IOCs, and persist.
  // Pure read-modify-write on state.json (no re-synthesis here — the caller decides).
  // Returns how many events were decoded and how many new IOCs were extracted.
  async function applyDeobfuscationToCase(caseId: string): Promise<{ deobfuscated: number; newIocs: number }> {
    if (!options.stateStore) return { deobfuscated: 0, newIocs: 0 };
    const state = await options.stateStore.load(caseId);
    const result = applyDeobfuscation(state);
    if (result.deobfuscated === 0 && result.newIocs === 0) return { deobfuscated: 0, newIocs: 0 };
    await options.stateStore.save(result.state);
    options.onState?.(result.state);
    return { deobfuscated: result.deobfuscated, newIocs: result.newIocs };
  }

  app.get("/ioc-whitelist", async (_req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.iocWhitelistStore.load());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add one rule. Body: { match: "cidr"|"regex"|"exact", pattern, iocType?, note? }
  app.post("/ioc-whitelist", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    const input = sanitizeRuleInput(req.body ?? {});
    if (!input) return res.status(400).json({ error: "invalid rule — need match (cidr|regex|exact) and a valid pattern (valid CIDR for cidr, valid regex for regex)" });
    try {
      const rule = await options.iocWhitelistStore.add(input);
      return res.status(201).json(rule);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/ioc-whitelist/:ruleId", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    try {
      const removed = await options.iocWhitelistStore.remove(req.params.ruleId);
      if (!removed) return res.status(404).json({ error: "rule not found" });
      return res.status(200).json({ removed: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import rules from pasted CSV or JSON. Body: { text }. Returns { added, total }.
  app.post("/ioc-whitelist/import", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    if (!text.trim()) return res.status(400).json({ error: "text is required (CSV or JSON)" });
    try {
      const parsed = parseWhitelistText(text);
      if (parsed.length === 0) return res.status(400).json({ error: "no valid rules found — expected JSON array or CSV with a 'pattern' column" });
      const added = await options.iocWhitelistStore.addMany(parsed);
      return res.status(200).json({ added: added.length, parsed: parsed.length, total: (await options.iocWhitelistStore.load()).length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the whitelist as CSV or JSON (?format=csv|json, default json) for backup / sharing.
  app.get("/ioc-whitelist/export", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    try {
      const rules = await options.iocWhitelistStore.load();
      if (String(req.query.format) === "csv") {
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", 'attachment; filename="ioc-whitelist.csv"');
        return res.status(200).send(toWhitelistCsv(rules));
      }
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", 'attachment; filename="ioc-whitelist.json"');
      return res.status(200).send(JSON.stringify(rules, null, 2));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // User-authored declarative importers (external plugin layer). GLOBAL, shared across cases — these
  // CRUD the registry of import shapes the analyst can add without code. Unconfigured ⇒ empty list /
  // 501 on writes. A save/delete/reload re-reads the on-disk registry (reloadImporters) so the in-
  // memory copy + the detection seam (resolveImportKind) stay current without the #1-gotcha restart.
  app.get("/importers", async (_req: Request, res: Response) => {
    if (!options.importerStore) return res.status(200).json({ importers: [], precedence: "builtin-first", errors: [] });
    return res.status(200).json({ importers: importerRegistry.meta, precedence: importerPrecedence, errors: importerRegistry.errors });
  });

  app.get("/importers/prompt", (_req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "pipeline not configured" });
    return res.status(200).json({ prompt: getImporterPrompt() });
  });

  app.post("/importers", async (req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    const body = req.body?.spec ?? req.body;
    const parsed = parseImporterSpec(body);
    if (!parsed.ok) return res.status(400).json({ error: "invalid importer", errors: parsed.errors });
    try {
      await options.importerStore.save(parsed.spec);
      await reloadImporters();
      return res.status(201).json({ id: parsed.spec.id });
    } catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });

  app.delete("/importers/:id", async (req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    try {
      const removed = await options.importerStore.delete(req.params.id);
      if (!removed) return res.status(404).json({ error: "importer not found" });
      await reloadImporters();
      return res.status(200).json({ removed: true });
    } catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });

  app.post("/importers/reload", async (_req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    try { await reloadImporters(); return res.status(200).json({ importers: importerRegistry.meta, errors: importerRegistry.errors }); }
    catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });

  app.put("/importers/precedence", async (req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    const p = req.body?.precedence;
    if (p !== "builtin-first" && p !== "external-first") return res.status(400).json({ error: "precedence must be 'builtin-first' or 'external-first'" });
    try { await options.importerStore.setPrecedence(p); importerPrecedence = p; options.onImporters?.(); return res.status(200).json({ precedence: p }); }
    catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });

  // Apply the whitelist to THIS case's current IOCs now (the analyst just added rules, or wants to
  // sweep an already-imported case). Marks matches legitimate, then re-synthesizes so they drop.
  app.post("/cases/:id/ioc-whitelist/apply", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const result = await applyWhitelistToCase(caseId);
      if (result.added > 0) resynthesizeInBackground(caseId);
      logLine(`[whitelist] ${caseId} apply — matched ${result.matched}, added ${result.added}`);
      return res.status(200).json({ ...result, legitimate: await legitimate.load(caseId) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── NSRL known-good hashes (#63) ───────────────────────────────────────────────────────────────
  // A GLOBAL set of known-software file hashes (NIST NSRL / RDS). A forensic event whose file hash —
  // or an IOC whose value — is in the set is a known-good file, auto-marked LEGITIMATE to reduce
  // false positives. Reuses the legitimate machinery (reversible, shown in "Confirmed Legitimate").
  // Auto-applied on import; also on demand per case. Opt-in (the set starts empty).

  // Sweep a case's current IOCs + forensic events for NSRL matches, adding a legitimate marker for
  // each that isn't already marked (ioc → by value, event → by id, so the raw evidence is preserved
  // and un-marking restores it). Pure read-modify-write on legitimate.json (no re-synthesis here —
  // the caller decides). Returns how many IOCs/events matched and how many NEW markers were added.
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
    const markers = await legitimate.load(caseId);
    const byId = new Map<string, LegitimateMarker>(markers.map((m) => [m.id, m]));
    const now = new Date().toISOString();
    let added = 0;
    for (const { ioc, hash } of iocMatches) {
      const id = markerId("ioc", ioc.value);
      if (byId.has(id)) continue;
      byId.set(id, { id, kind: "ioc", ref: ioc.value, note: `NSRL known-good hash (${hash})`, markedAt: now, label: ioc.value });
      added++;
    }
    for (const { event, hash } of eventMatches) {
      const id = markerId("event", event.id);
      if (byId.has(id)) continue;
      byId.set(id, { id, kind: "event", ref: event.id, note: `NSRL known-good file (${hash})`, markedAt: now, label: event.description });
      added++;
    }
    if (added > 0) await legitimate.save(caseId, [...byId.values()]);
    return { matchedIocs: iocMatches.length, matchedEvents: eventMatches.length, added };
  }

  // Stats for the Settings → NSRL panel: the flat set count + the RDS DB connection status. Degrades
  // to "not configured" (200) like /ioc-whitelist. `enabled` = either backend is usable.
  app.get("/nsrl", async (_req: Request, res: Response) => {
    const db = nsrlDb ? nsrlDb.status() : { connected: false };
    const dbConfigurable = Boolean(options.nsrlDbConfigFile) && !options.nsrlDbEnvManaged;
    const dbEnvManaged = Boolean(options.nsrlDbEnvManaged);
    if (!options.nsrlStore) return res.status(200).json({ count: 0, enabled: db.connected, db, dbConfigurable, dbEnvManaged });
    try {
      const count = await options.nsrlStore.count();
      return res.status(200).json({ count, enabled: count > 0 || db.connected, db, dbConfigurable, dbEnvManaged });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Connect (or swap) the NSRL RDS SQLite database at runtime. Body: { path } (the RDS .db on the
  // server). Opens read-only, validates it has a sha256/md5 column, persists the path so it survives
  // a restart. Rejected when env-managed (DFIR_NSRL_DB owns the path). Localhost-only tool: opening a
  // path the operator typed is intended (same trust as the env var).
  app.post("/nsrl/db", async (req: Request, res: Response) => {
    if (options.nsrlDbEnvManaged) return res.status(400).json({ error: "the NSRL RDS path is managed by the DFIR_NSRL_DB env var — unset it to configure here" });
    if (!options.nsrlDbConfigFile) return res.status(501).json({ error: "NSRL RDS database not configured" });
    const path = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!path) return res.status(400).json({ error: "path is required (the NSRL RDS .db file on the server)" });
    try {
      const opened = NsrlDb.open(path); // throws on bad file / no usable hash column
      if (nsrlDb) nsrlDb.close();
      nsrlDb = opened;
      await saveNsrlDbPath(options.nsrlDbConfigFile, path);
      logLine(`[nsrl] connected RDS DB ${path} — table ${opened.table}, columns ${opened.columns.join("/")}`);
      return res.status(200).json(opened.status());
    } catch (err) {
      return res.status(400).json({ error: `could not open NSRL RDS: ${(err as Error).message}` });
    }
  });

  // Disconnect the RDS database (the flat set is unaffected).
  app.delete("/nsrl/db", async (_req: Request, res: Response) => {
    if (options.nsrlDbEnvManaged) return res.status(400).json({ error: "the NSRL RDS path is managed by the DFIR_NSRL_DB env var" });
    if (!options.nsrlDbConfigFile) return res.status(501).json({ error: "NSRL RDS database not configured" });
    try {
      if (nsrlDb) { nsrlDb.close(); nsrlDb = undefined; }
      await removeNsrlDbPath(options.nsrlDbConfigFile);
      logLine(`[nsrl] disconnected RDS DB`);
      return res.status(200).json({ connected: false });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import known-good hashes from pasted text or a loaded file: NSRLFile.txt (RDS CSV), a hashdeep
  // CSV, or a plain hash-per-line / comma-separated list. Body: { text }. Returns { added, parsed, total }.
  app.post("/nsrl/import", async (req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    if (!text.trim()) return res.status(400).json({ error: "text is required (NSRL CSV or a hash list)" });
    try {
      const parsed = parseNsrlText(text);
      if (parsed.length === 0) return res.status(400).json({ error: "no valid hashes found — expected MD5/SHA-1/SHA-256 hashes (NSRLFile.txt, a hashdeep CSV, or a hash-per-line list)" });
      const { added, total } = await options.nsrlStore.addMany(parsed);
      logLine(`[nsrl] import — +${added} new (${parsed.length} parsed, ${total} total)`);
      return res.status(200).json({ added, parsed: parsed.length, total });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Load known-good hashes from file(s) on the SERVER's filesystem — the in-UI equivalent of
  // DFIR_NSRL_FILE, for big RDS sets you don't want to paste. Body: { path } (a file path, or several
  // `;`-separated). Best-effort per file (a bad path is reported, not fatal). Loaded hashes persist in
  // the store, so unlike the env var this is a one-shot — no restart, and it survives one. Returns
  // { added, total, files[] }. Localhost-only tool: reading a path the operator typed is intended
  // (same trust as the env var); the response carries counts + errors only, never file contents.
  app.post("/nsrl/import-file", async (req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    const paths = splitNsrlPaths(typeof req.body?.path === "string" ? req.body.path : "");
    if (paths.length === 0) return res.status(400).json({ error: "path is required (a file on the server; ; -separated for multiple)" });
    try {
      const files = await ingestNsrlFiles(options.nsrlStore, paths);
      for (const r of files) logLine(r.error ? `[nsrl] could not load ${r.file}: ${r.error}` : `[nsrl] loaded ${r.file} — +${r.added} new (${r.total} total known-good hashes)`);
      const added = files.reduce((n, r) => n + r.added, 0);
      const total = await options.nsrlStore.count();
      // All paths failed → 400 (nothing loaded), like the paste import's no-valid-hashes 400.
      const allFailed = files.every((r) => r.error);
      return res.status(allFailed ? 400 : 200).json({ added, total, files });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Wipe the set (e.g. swapping in a different RDS release).
  app.post("/nsrl/clear", async (_req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    try {
      await options.nsrlStore.clear();
      return res.status(200).json({ cleared: true, count: 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the set as a newline-delimited hash list for backup / sharing.
  app.get("/nsrl/export", async (_req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    try {
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", 'attachment; filename="nsrl-known-hashes.txt"');
      return res.status(200).send(await options.nsrlStore.exportText());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Apply the NSRL set to THIS case now (the analyst just loaded a set, or wants to sweep an
  // already-imported case). Marks matches legitimate, then re-synthesizes so they drop from findings.
  app.post("/cases/:id/nsrl/apply", async (req: Request, res: Response) => {
    if (!options.nsrlStore && !nsrlDb) return res.status(501).json({ error: "NSRL not configured (no hash set or RDS database)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const result = await applyNsrlToCase(caseId);
      if (result.added > 0) resynthesizeInBackground(caseId);
      logLine(`[nsrl] ${caseId} apply — matched ${result.matchedIocs} IOC(s) + ${result.matchedEvents} event(s), added ${result.added}`);
      return res.status(200).json({ ...result, legitimate: await legitimate.load(caseId) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // On-demand deobfuscation (#97): scan the case's forensic timeline for obfuscated command
  // lines, decode them, extract hidden IOCs, and re-synthesize so findings reflect the decoded
  // content. Idempotent: already-decoded events are skipped.
  app.post("/cases/:id/deobfuscate", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const result = await applyDeobfuscationToCase(caseId);
      if (result.deobfuscated > 0) resynthesizeInBackground(caseId);
      logLine(`[deobfuscate] ${caseId} apply — decoded ${result.deobfuscated} event(s), +${result.newIocs} new IOC(s)`);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // CISA KEV catalog routes (issue #99). The catalog is global (like NSRL/whitelist).
  // GET /kev — stats for the Settings → KEV panel.
  // POST /kev/import-url — fetch the CISA feed from a URL (body: { url }).
  // POST /kev/import-file — load the feed from a server-side file path (body: { path }).
  // DELETE /kev — wipe the catalog.
  app.get("/kev", async (_req: Request, res: Response) => {
    if (!options.kevStore) return res.status(200).json({ count: 0, enabled: false });
    try {
      const m = await options.kevStore.meta();
      return res.status(200).json({ ...m, enabled: m.count > 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Fetch the CISA KEV feed from a URL and ingest it. Body: { url? } (defaults to the CISA feed).
  // Passes the raw JSON through so meta() can read catalogVersion/dateReleased.
  app.post("/kev/import-url", async (req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const url = typeof req.body?.url === "string" && req.body.url.trim() ? req.body.url.trim() : CISA_KEV_URL;
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(30_000) });
      if (!resp.ok) return res.status(502).json({ error: `fetch failed: HTTP ${resp.status}` });
      const json: unknown = await resp.json();
      const { total } = await options.kevStore.ingestRaw(json);
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] imported ${total} entries from ${url}`);
      return res.status(200).json({ total, source: url });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Load the CISA KEV feed JSON from a file on the server filesystem. Body: { path }.
  // Localhost-only tool: reading an operator-specified path is intentional (like NSRL import-file).
  app.post("/kev/import-file", async (req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    const path = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!path) return res.status(400).json({ error: "path is required (a local copy of the CISA KEV JSON)" });
    try {
      const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
      const { total } = await options.kevStore.ingestRaw(raw);
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] loaded ${total} entries from file ${path}`);
      return res.status(200).json({ total, source: path });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Wipe the KEV catalog.
  app.delete("/kev", async (_req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    try {
      await options.kevStore.clear();
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] catalog cleared`);
      return res.status(200).json({ cleared: true, count: 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Investigation time-window. Setting it re-synthesizes so out-of-scope events
  // (and the findings/IOCs derived from them) drop out of the analysis.
  const scopeStore = new ScopeStore(store);

  app.get("/cases/:id/scope", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await scopeStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/scope", async (req: Request, res: Response) => {
    try {
      const norm = (v: unknown): string | null => {
        const s = String(v ?? "").trim();
        if (!s) return null;
        const t = Date.parse(s);
        return Number.isNaN(t) ? null : new Date(t).toISOString();
      };
      const scope: ScopeWindow = { start: norm(req.body?.start), end: norm(req.body?.end) };
      await scopeStore.save(req.params.id, scope);
      options.onScope?.(req.params.id, scope);
      resynthesizeInBackground(req.params.id); // re-derive within the window
      return res.status(200).json(scope);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Unified import: ONE endpoint the dashboard's single "Import" button posts any data file to.
  // The server SNIFFS the file (filename + content) — JSON/NDJSON vs CSV vs log, then per-format
  // signatures — and dispatches to the matching importer (deterministic ones, or the AI CSV/log
  // path). Evidence-first: the raw file is persisted + audit-logged before analysis. The detected
  // `kind` is returned so a mis-route is visible. (The per-format routes below remain for
  // programmatic use.)
  app.post("/cases/:id/import", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed") {
      return res.status(423).json({ error: `Case "${caseId}" is closed — reopen it before importing evidence` });
    }
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "import.dat");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const kind = resolveImportKind(originalName, text);
    if (kind === "unknown") {
      return res.status(400).json({ error: "could not detect the file type — not recognized as any supported import (THOR / SIEM-EDR / Chainsaw-EVTX / Hayabusa / Velociraptor / Suricata-Zeek / KAPE / Cyber Triage / M365-Entra / AWS / GCP-Azure / Plaso / Sandbox / Volatility-Rekall memory / Email-eml-msg / auditd / journald / sysdig-Falco / CSV / log)" });
    }
    if ((kind === "csv" || kind === "log") && !hasAiProvider()) {
      return res.status(501).json({ error: "AI provider not configured for CSV/log analysis" });
    }

    // Cross-case signal: tell every dashboard an artifact import landed for THIS case, so one viewing
    // a different case warns "artifacts are arriving for another case" — parity with screenshots. The
    // extension's "Push to DFIR-Companion" hits this route, so this covers the extension-drift trap.
    options.onImport?.(caseId);

    // Optional minimum-severity floor (the old per-format "which minimum severity?" prompt,
    // restored for the single Import button). Gate-aware: imports that don't grade severity
    // (all-Info telemetry like KAPE/Plaso) are kept whole — see applySeverityFloor. A missing
    // / unrecognized value imports everything.
    const minSeverity = parseMinSeverity(req.body?.minSeverity);

    try {
      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: 0, bytes: Buffer.byteLength(text, "utf8"),
      });

      // CSV/log imports are themselves an LLM call (free-form data the model must interpret), so
      // they respect the per-case AI toggle exactly like screenshot analysis + synthesis: with AI
      // OFF, the evidence is saved (above) but NOT sent to the model. Deterministic imports have no
      // LLM call, so they proceed and populate the timeline + IOCs regardless (synthesis still waits
      // for AI — see resynthesizeInBackground). This keeps "AI off" meaning no LLM call / nothing
      // leaves for the model, and stops the dashboard from claiming the AI is analyzing while off.
      const aiDependent = kind === "csv" || kind === "log";
      if (aiDependent && !(await getControl(caseId)).enabled) {
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `AI is off — ${kind.toUpperCase()} saved as evidence but not analyzed (turn AI on, then re-import)` });
        return res.status(202).json({ accepted: true, kind, file: storedName, minSeverity, analyzed: false, reason: "ai-off" });
      }

      res.status(202).json({ accepted: true, kind, file: storedName, minSeverity });

      const pipeline = options.pipeline;
      const onProgress = (done: number, total: number): void => options.onAiStatus?.(caseId, {
        status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `${kind} import — ${done}/${total}`,
      });
      const base = { label: storedName, idPrefix: `${seq}`, importedAt, onProgress, minSeverity };
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing (${kind})${minSeverity ? ` — min severity ${minSeverity}` : ""}` });

      const run = (): Promise<unknown> => dispatchImport(kind, caseId, text, base);

      // Snapshot the FULL investigation state BEFORE the import so the .then() below can (a) diff what
      // this import added (the "last import" banner) and (b) push a pre-import undo checkpoint (#76 —
      // the whole state, so undo also takes back the findings/MITRE the post-import synthesis derives).
      let stateBefore: InvestigationState | null = null;
      if (options.stateStore) {
        try { stateBefore = await options.stateStore.load(caseId); } catch { /* keep null */ }
      }

      run()
        .then(async () => {
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
          // Record what this import added to the forensic timeline + IOCs, BEFORE resynthesis (which
          // preserves both). Best-effort: a meta failure must not break the import.
          if (options.stateStore && stateBefore) {
            try {
              const s = await options.stateStore.load(caseId);
              const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
              const iDiff = diffIocs(stateBefore.iocs, s.iocs);
              if (options.importMetaStore) {
                await options.importMetaStore.record(caseId, { kind, file: storedName, diff: tDiff, iocsDiff: iDiff });
                options.onImportMeta?.(caseId);
              }
              // #76: snapshot the pre-import state for undo — but only when the import actually changed
              // something (skip a no-op re-import so undo doesn't pile up dead levels).
              if (tDiff.added.length || tDiff.removed.length || iDiff.added.length || iDiff.removed.length) {
                await pushImportCheckpoint(caseId, stateBefore, `${kind} (${storedName})`);
              }
            } catch { /* non-fatal */ }
          }
          // Phase 2 (#35): auto-mark IOCs that match the global whitelist as legitimate BEFORE
          // re-synthesis, so known-good indicators drop out of the analysis. Best-effort.
          try {
            const wl = await applyWhitelistToCase(caseId);
            if (wl.added > 0) logLine(`[whitelist] ${caseId} auto-marked ${wl.added} imported IOC(s) legitimate`);
          } catch { /* non-fatal */ }
          // #63: auto-mark imported events/IOCs whose hash is in the global NSRL set (known-good
          // files) legitimate, also BEFORE re-synthesis, to reduce false positives. Best-effort.
          try {
            const ns = await applyNsrlToCase(caseId);
            if (ns.added > 0) logLine(`[nsrl] ${caseId} auto-marked ${ns.added} imported known-good item(s) legitimate`);
          } catch { /* non-fatal */ }
          // #97: decode obfuscated command lines (PowerShell -enc, base64) and extract hidden IOCs.
          try {
            const deob = await applyDeobfuscationToCase(caseId);
            if (deob.deobfuscated > 0) logLine(`[deobfuscate] ${caseId} decoded ${deob.deobfuscated} event(s), +${deob.newIocs} new IOC(s)`);
          } catch { /* non-fatal */ }
          resynthesizeInBackground(caseId);
        })
        .catch((err) => { recordImportFailure(caseId, kind, storedName, err); recordAiError(caseId, "import", err); options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }); });
      return;
    } catch (err) {
      recordImportFailure(caseId, kind, originalName, err);
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a CSV result export (e.g. a Velociraptor artifact) as evidence and analyze
  // it like captured screenshots: extract dated forensic events + IOCs into the
  // timeline, then synthesize findings/TTPs/attacker-path. Evidence-first: the raw
  // CSV is persisted + audit-logged BEFORE any analysis; analysis runs in background.
  app.post("/cases/:id/import-csv", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for CSV analysis" });
    const caseId = req.params.id;
    const csv = typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "import.csv");
    if (!csv.trim()) return res.status(400).json({ error: "csv is required" });

    try {
      const { rows } = parseCsv(csv);
      if (rows.length === 0) return res.status(400).json({ error: "CSV has no data rows" });

      // Evidence-first: persist the raw CSV + append the audit line before analysis.
      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, csv);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: rows.length, bytes: Buffer.byteLength(csv, "utf8"),
      });

      // Acknowledge immediately; the dashboard watches AI status + state over the WS.
      res.status(202).json({ accepted: true, file: storedName, rows: rows.length });

      // Background: extract events from the rows, then synthesize conclusions.
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${rows.length} CSV row(s)` });
      void options.pipeline.analyzeCsv(caseId, csv, {
        label: storedName,
        idPrefix: `m${seq}`,
        importedAt,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `CSV import — batch ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a generic log file (firewall, syslog, sshd, IIS/Apache/nginx access,
  // application logs — anything line-oriented, typically .log or .txt) as evidence.
  // Same evidence-first pattern as import-csv: persist + audit, then analyze in the
  // background (line-batched). The CSV path stays specialized for tabular exports.
  app.post("/cases/:id/import-log", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for log analysis" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "import.log");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    try {
      // Validate and split lines up-front so we can reject empty files with a 400
      // (mirrors the CSV "no rows" check) — and so we report line count back to the UI.
      const { lines } = parseLogLines(text);
      if (lines.length === 0) return res.status(400).json({ error: "log file has no non-empty lines" });

      const seq = await store.nextImportSeq(caseId);
      // Preserve the original extension (.log / .txt / etc.) so it round-trips through
      // the evidence endpoint with the right content-type.
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.log");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: lines.length, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, lines: lines.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${lines.length} log line(s)` });
      void options.pipeline.analyzeLog(caseId, text, {
        label: storedName,
        idPrefix: `l${seq}`,
        importedAt,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `log import — batch ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a THOR (Nextron) scanner report (JSON-Lines from `thor --jsonfile`).
  // Evidence-first like the CSV/log paths; mapping is DETERMINISTIC (no AI extraction),
  // dropping scan-lifecycle/info noise. Synthesis (findings/attacker path) runs after.
  app.post("/cases/:id/import-thor", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const json = typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "thor.json");
    if (!json.trim()) return res.status(400).json({ error: "json is required" });

    // Optional severity floor: keep only Alert / Alert+Warning / Alert+Warning+Notice.
    const rawLevel = String(req.body?.minLevel ?? "").trim().toLowerCase();
    const minLevel = rawLevel === "alert" ? "Alert" : rawLevel === "warning" ? "Warning" : rawLevel === "notice" ? "Notice" : undefined;
    const thorOpts = minLevel ? { minLevel } as const : undefined;

    try {
      // Parse up-front: reject a file with no real findings (only info/lifecycle rows),
      // and report kept/dropped counts back to the UI.
      const preview = parseThorReport(json, thorOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable THOR JSON lines" });
      if (preview.kept === 0) {
        return res.status(400).json({ error: `THOR report has no findings after dropping ${preview.dropped} info/lifecycle row(s)` });
      }

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "thor.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, json);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(json, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, findings: preview.kept, dropped: preview.dropped, total: preview.total });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} THOR finding(s)` });
      void options.pipeline.importThor(caseId, json, {
        label: storedName,
        idPrefix: `t${seq}`,
        importedAt,
        thor: thorOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `THOR import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a SIEM / EDR JSON export — the second JSON ingest path besides THOR, for
  // exports from Elastic/Kibana, Splunk, an EDR console, or a raw winlogbeat dump.
  // Evidence-first like the other imports; mapping is DETERMINISTIC (no AI extraction):
  // the container is unwrapped, Windows/Sysmon events get a per-EID mapping (others use
  // field auto-detection), and repetitive events aggregate. Synthesis runs after.
  app.post("/cases/:id/import-siem", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const json = typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "siem.json");
    if (!json.trim()) return res.status(400).json({ error: "json is required" });

    // Optional severity floor: keep only events at/above this level (e.g. "low" drops
    // Info noise like logoffs / process-terminated). Default = keep everything.
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const siemOpts: SiemImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      // Parse up-front: reject a file with no parseable records, and report counts to the UI.
      const preview = parseSiemExport(json, siemOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable SIEM/EDR records found (expected a JSON array, an Elastic/Kibana export, or NDJSON)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "siem.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, json);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(json, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} SIEM event(s)` });
      void options.pipeline.importSiem(caseId, json, {
        label: storedName,
        idPrefix: `s${seq}`,
        importedAt,
        siem: siemOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `SIEM import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Chainsaw (WithSecure) hunt output or a raw EVTX-as-JSON dump — the third JSON
  // ingest path, and the richest for Windows IR. Evidence-first like the other imports;
  // mapping is DETERMINISTIC (no AI extraction): embedded EVTX events get the per-EID
  // Windows mapping and, for Chainsaw, the matched Sigma rule's level/tags drive
  // severity/MITRE. Synthesis runs after.
  app.post("/cases/:id/import-chainsaw", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const json = typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "chainsaw.json");
    if (!json.trim()) return res.status(400).json({ error: "json is required" });

    // Optional severity floor (e.g. "medium" drops Low/Info detections and noise events).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const chainsawOpts: ChainsawImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      // Parse up-front: reject a file with no parseable records, and report counts to the UI.
      const preview = parseChainsawReport(json, chainsawOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Chainsaw/EVTX records found (expected Chainsaw hunt JSON, or evtx_dump JSON/NDJSON)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "chainsaw.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, json);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(json, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, detections: preview.detections, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      const kind = preview.detections > 0 ? "Chainsaw" : "EVTX";
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} ${kind} event(s)` });
      void options.pipeline.importChainsaw(caseId, json, {
        label: storedName,
        idPrefix: `c${seq}`,
        importedAt,
        chainsaw: chainsawOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `${kind} import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Hayabusa (Yamato Security) detection timeline — JSON/JSONL or CSV. Sister of
  // the Chainsaw path; evidence-first, mapping is DETERMINISTIC (no AI extraction): the
  // matched Sigma rule's level drives severity, its title/tactics/tags drive the
  // description + MITRE, and IOCs/asset/process-chain come from the rendered detail fields.
  app.post("/cases/:id/import-hayabusa", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "hayabusa.csv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    // Optional severity floor (e.g. "medium" drops Low/Info detections + noise).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const hayabusaOpts: HayabusaImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      // Parse up-front: reject a file with no parseable records, and report counts to the UI.
      const preview = parseHayabusaTimeline(text, hayabusaOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Hayabusa records found (expected a Hayabusa json-timeline or csv-timeline)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "hayabusa.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Hayabusa event(s)` });
      void options.pipeline.importHayabusa(caseId, text, {
        label: storedName,
        idPrefix: `h${seq}`,
        importedAt,
        hayabusa: hayabusaOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Hayabusa import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Velociraptor native JSON (collection results / hunt export). Evidence-first;
  // mapping is DETERMINISTIC (no AI extraction): rows are classified (Sigma/YARA/EventLog/
  // generic) and mapped — detection rows verdict-driven, the rest auto-detect time + IOCs.
  app.post("/cases/:id/import-velociraptor", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "velociraptor.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    // Optional severity floor (e.g. "low" drops the Info-level raw-collection rows).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const vrOpts: VelociraptorImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseVelociraptorJson(text, vrOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Velociraptor rows found (expected JSON array, JSONL collection results, or an artifact map)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "velociraptor.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, rows: preview.total, detections: preview.detections, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Velociraptor event(s)` });
      void options.pipeline.importVelociraptor(caseId, text, {
        label: storedName,
        idPrefix: `v${seq}`,
        importedAt,
        velociraptor: vrOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Velociraptor import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import network-monitor logs — Suricata eve.json + Zeek JSON (Security Onion's network
  // side). Evidence-first; mapping is DETERMINISTIC (no AI extraction): the timeline is built
  // from the detections (Suricata alerts + Zeek notices); telemetry contributes IOCs only.
  app.post("/cases/:id/import-network", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "eve.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    // Optional severity floor on the alert events (e.g. "medium" drops Suricata priority-3).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const netOpts: NetworkImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseNetworkLogs(text, netOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Suricata/Zeek records found (expected Suricata eve.json or Zeek JSON, as NDJSON or an array)" });
      if (preview.kept === 0 && preview.iocs.length === 0) return res.status(400).json({ error: `no detections or IOCs found (${preview.total} record(s) parsed${rawLevel ? `, after the '${rawLevel}' floor` : ""})` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "eve.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, alerts: preview.alerts, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} network detection(s)` });
      void options.pipeline.importNetwork(caseId, text, {
        label: storedName,
        idPrefix: `n${seq}`,
        importedAt,
        network: netOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Network import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a KAPE / Eric Zimmerman Tools CSV (Prefetch, Amcache, ShimCache, LNK, JumpLists,
  // UsnJrnl, MFT, SRUM, Recycle Bin, Shellbags). Evidence-first; the EZ tool is detected from
  // the CSV header and mapped DETERMINISTICALLY (no AI extraction), reading the artifact's own time.
  app.post("/cases/:id/import-kape", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "kape.csv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const kapeOpts: KapeImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseKapeCsv(text, kapeOpts);
      if (preview.artifact === "unknown") return res.status(400).json({ error: "unrecognized CSV — expected a KAPE / Eric Zimmerman Tools export (Prefetch, Amcache, ShimCache, LNK, JumpLists, UsnJrnl, MFT, SRUM, RecycleBin, Shellbags)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events from the ${preview.artifact} CSV (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "kape.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, artifact: preview.artifact, events: preview.kept, rows: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} ${preview.artifact} event(s)` });
      void options.pipeline.importKape(caseId, text, {
        label: storedName,
        idPrefix: `k${seq}`,
        importedAt,
        kape: kapeOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `${preview.artifact} import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Cyber Triage timeline export (JSONL / JSON array / CSV). Evidence-first; mapping is
  // DETERMINISTIC (no AI extraction): scored rows map verdict-first, unscored process/task rows
  // become Info evidence, the bulk File super-timeline is dropped unless `fileTelemetry` is set.
  app.post("/cases/:id/import-cybertriage", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "cybertriage.jsonl");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const fileTelemetry = req.body?.fileTelemetry === true || /^(1|true|yes)$/i.test(String(req.body?.fileTelemetry ?? ""));
    const ctOpts: CybertriageImportOptions | undefined =
      minSeverity || fileTelemetry ? { ...(minSeverity ? { minSeverity } : {}), ...(fileTelemetry ? { fileTelemetry } : {}) } : undefined;

    try {
      const preview = parseCybertriage(text, ctOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "unrecognized file — expected a Cyber Triage timeline export (JSONL / JSON array / CSV with event_timestamp,epoch_timestamp,timestamp_description columns)" });
      if (preview.kept === 0 && preview.iocs.length === 0) return res.status(400).json({ error: `no events or IOCs from the Cyber Triage export (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "cybertriage.jsonl");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, rows: preview.total, notable: preview.notable, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Cyber Triage event(s)` });
      void options.pipeline.importCybertriage(caseId, text, {
        label: storedName,
        idPrefix: `ct${seq}`,
        importedAt,
        cybertriage: ctOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Cyber Triage import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Microsoft 365 Unified Audit Log + Entra ID sign-in / directory audit data
  // (cloud/identity IR). Evidence-first; mapping is DETERMINISTIC (no AI extraction): each
  // record is classified and mapped, severity derived from the operation / Entra risk verdict.
  app.post("/cases/:id/import-m365", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "m365.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const m365Opts: M365ImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseM365Audit(text, m365Opts);
      if (preview.total === 0 || preview.format === "empty") return res.status(400).json({ error: "no parseable M365/Entra records found (expected a Unified Audit Log export — CSV or JSON — or Entra sign-in/audit JSON)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "m365.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} M365/Entra event(s)` });
      void options.pipeline.importM365(caseId, text, {
        label: storedName,
        idPrefix: `m${seq}`,
        importedAt,
        m365: m365Opts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `M365 import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import AWS CloudTrail logs (cloud IR). Evidence-first; mapping is DETERMINISTIC (no AI
  // extraction): each API-call record is mapped, severity derived from the action + denied/
  // root/console-failure bumps; the caller sourceIPAddress becomes an IOC.
  app.post("/cases/:id/import-aws", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "cloudtrail.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const awsOpts: AwsImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseCloudTrail(text, awsOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable CloudTrail records found (expected a { Records: [...] } envelope, NDJSON, or a JSON array of CloudTrail events)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "cloudtrail.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} CloudTrail event(s)` });
      void options.pipeline.importAws(caseId, text, {
        label: storedName,
        idPrefix: `a${seq}`,
        importedAt,
        aws: awsOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `CloudTrail import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import GCP Cloud Audit Logs + Azure Activity Log (cloud IR). Evidence-first; mapping is
  // DETERMINISTIC (no AI extraction): each record is routed (GCP/Azure) and mapped, severity
  // derived from the action + denied bump; the caller IP becomes an IOC.
  app.post("/cases/:id/import-cloud-activity", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "cloud-activity.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const cloudOpts: CloudActivityImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseCloudActivity(text, cloudOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable GCP/Azure records found (expected GCP Cloud Audit Logs or an Azure Activity Log export, as JSON array or NDJSON)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "cloud-activity.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} ${preview.format} event(s)` });
      void options.pipeline.importCloudActivity(caseId, text, {
        label: storedName,
        idPrefix: `g${seq}`,
        importedAt,
        cloud: cloudOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Cloud activity import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Plaso / log2timeline super-timeline (psort CSV — dynamic or l2tcsv). Evidence-first;
  // mapping is DETERMINISTIC (no AI extraction): each row is an Info evidence event read at its
  // own time, with IOCs scraped from the message + source file path.
  app.post("/cases/:id/import-plaso", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "plaso.csv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const plasoOpts: PlasoImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parsePlasoCsv(text, plasoOpts);
      if (preview.format === "unknown") return res.status(400).json({ error: "unrecognized CSV — expected a Plaso psort export (dynamic: datetime,message,… or l2tcsv: date,time,…,desc,…)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events from the Plaso ${preview.format} CSV (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "plaso.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, rows: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Plaso event(s)` });
      void options.pipeline.importPlaso(caseId, text, {
        label: storedName,
        idPrefix: `p${seq}`,
        importedAt,
        plaso: plasoOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Plaso import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a malware-sandbox detonation report (CAPEv2 or CrowdStrike Falcon Sandbox).
  // Evidence-first; mapping is DETERMINISTIC (no AI extraction): the verdict + each signature
  // map to events, and dropped/extracted hashes + network indicators are harvested as IOCs.
  app.post("/cases/:id/import-sandbox", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "sandbox.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const sandboxOpts: SandboxImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseSandboxReport(text, sandboxOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable sandbox report found (expected a CAPEv2 report.json or a CrowdStrike Falcon Sandbox summary JSON)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "sandbox.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, signatures: preview.signatures, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} sandbox event(s)` });
      void options.pipeline.importSandbox(caseId, text, {
        label: storedName,
        idPrefix: `sb${seq}`,
        importedAt,
        sandbox: sandboxOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Sandbox import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import memory-forensics tool output (Volatility 3 JSON renderer or Rekall JSON). Evidence-first;
  // mapping is DETERMINISTIC (no AI call): pslist/psscan/pstree → process-tree events, netscan →
  // connection events, malfind → injected-code (T1055), cmdline/svcscan/modules → evidence; the
  // foreign IPs / file paths / process names are harvested as IOCs.
  app.post("/cases/:id/import-memory", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "memory.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const dllTelemetry = req.body?.dllTelemetry === true || String(req.body?.dllTelemetry ?? "").toLowerCase() === "true";
    const memoryOpts: MemoryImportOptions = { filename: originalName, ...(minSeverity ? { minSeverity } : {}), ...(dllTelemetry ? { dllTelemetry } : {}) };

    try {
      const preview = parseMemory(text, memoryOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable memory output found (expected a Volatility 3 JSON-renderer array or a Rekall JSON statement list)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "memory.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, tool: preview.tool, events: preview.kept, injected: preview.injected, connections: preview.connections, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} memory event(s)` });
      void options.pipeline.importMemory(caseId, text, {
        label: storedName,
        idPrefix: `mem${seq}`,
        importedAt,
        memory: memoryOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Memory import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import an email artifact (.eml RFC 2822, or best-effort .msg). Evidence-first; mapped
  // DETERMINISTICALLY (no AI call): one event at the Date: header, severity from SPF/DKIM/DMARC +
  // sender heuristics, URLs/domains/IP/attachment-names as IOCs. Covers ATT&CK T1566 (Phishing).
  app.post("/cases/:id/import-email", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.eml === "string" ? req.body.eml : "";
    const originalName = String(req.body?.filename ?? "message.eml");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const emailOpts: EmailImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseEmail(text, emailOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable email found (expected an .eml RFC 2822 message, or an Outlook .msg export)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "message.eml");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, subject: preview.subject, sender: preview.sender, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing email "${preview.subject.slice(0, 60)}"` });
      void options.pipeline.importEmail(caseId, text, {
        label: storedName,
        idPrefix: `em${seq}`,
        importedAt,
        email: emailOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Email import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a TheHive 5 case, alert, or observable export. Evidence-first; mapped
  // DETERMINISTICALLY (no AI call): case/alert records → events, severity from TheHive's 1–4
  // scale, MITRE from ATT&CK-tagged tags, TLP/PAP prepended; observables → IOCs by dataType.
  app.post("/cases/:id/import-thehive", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "thehive-export.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    try {
      const preview = parseTheHive(text);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable TheHive records found (expected a case/alert JSON export or an observable list)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "thehive-export.json";
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, total: preview.total, observables: preview.observables, iocs: preview.iocCount });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing TheHive export (${preview.format})` });
      void options.pipeline.importTheHive(caseId, text, {
        label: storedName,
        idPrefix: `th${seq}`,
        importedAt,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `TheHive import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Linux auditd log (raw audit.log / `ausearch` record format, or an `aureport` table).
  // Evidence-first; mapped DETERMINISTICALLY (no AI call): records grouped by serial, per-type
  // severity/MITRE, read at the audit() epoch.
  app.post("/cases/:id/import-auditd", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.log === "string" ? req.body.log : "";
    const originalName = String(req.body?.filename ?? "audit.log");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const auditdOpts: AuditdImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseAuditdLog(text, auditdOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable auditd records found (expected raw audit.log / ausearch 'type=… msg=audit(…)' lines or an aureport table)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "audit.log");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, records: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} auditd event(s)` });
      void options.pipeline.importAuditd(caseId, text, {
        label: storedName,
        idPrefix: `ad${seq}`,
        importedAt,
        auditd: auditdOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `auditd import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a systemd-journald structured log (`journalctl -o json` / `-o json-pretty`). Evidence-first;
  // mapped DETERMINISTICALLY (no AI call): severity from PRIORITY + tradecraft bumps, read at the
  // entry's own µs-epoch time.
  app.post("/cases/:id/import-journald", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "journal.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const journaldOpts: JournaldImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseJournald(text, journaldOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable journald entries found (expected `journalctl -o json` / `-o json-pretty` output)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "journal.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, entries: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} journald event(s)` });
      void options.pipeline.importJournald(caseId, text, {
        label: storedName,
        idPrefix: `jd${seq}`,
        importedAt,
        journald: journaldOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `journald import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a sysdig / Falco export (Falco alert JSON and/or sysdig `-j` event JSON). Evidence-first;
  // mapped DETERMINISTICALLY (no AI call): Falco rule hits → detections (verdict-first), raw sysdig
  // syscall events → Info evidence, read at each event's own time.
  app.post("/cases/:id/import-sysdig", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "falco.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const sysdigOpts: SysdigImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseSysdig(text, sysdigOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable sysdig/Falco records found (expected Falco alert JSON or sysdig `-j` event JSON; a binary .scap must be exported to JSON first)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "falco.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, records: preview.total, alerts: preview.alerts, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} sysdig/Falco event(s)` });
      void options.pipeline.importSysdig(caseId, text, {
        label: storedName,
        idPrefix: `sd${seq}`,
        importedAt,
        sysdig: sysdigOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `sysdig import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Wazuh SIEM/EDR alert exports (alerts.json / NDJSON / API export envelope).
  // Evidence-first; mapped DETERMINISTICALLY (no AI call): rule.level drives severity,
  // rule.mitre.technique → MITRE, agent.name → asset, data fields → IOCs.
  app.post("/cases/:id/import-wazuh", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "wazuh-alerts.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const wazuhOpts: WazuhImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseWazuhAlerts(text, wazuhOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable Wazuh alerts found (expected an array or NDJSON of Wazuh alert objects with rule.level, rule.description, and agent fields, or a Wazuh API export { data: { affected_items: [...] } })" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "wazuh-alerts.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, records: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Wazuh alert(s)` });
      void options.pipeline.importWazuh(caseId, text, {
        label: storedName,
        idPrefix: `wz${seq}`,
        importedAt,
        wazuh: wazuhOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Wazuh import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Threat-intel enrichment toggle (per case, default OFF for OPSEC). GET reads the
  // current state. POST { enabled } turns it on/off; turning it ON enriches the current
  // IOCs immediately AND auto-enriches any IOCs added later (imports/synthesis).
  // ⚠ Enrichment sends indicators to third-party services (VirusTotal/MalwareBazaar/
  // AbuseIPDB) — that's why it is off until the analyst opts in.
  app.get("/cases/:id/enrich-control", async (req: Request, res: Response) => {
    try {
      const enabled = new Set(resolveEnabledProviders(await enrichControl.load(req.params.id), configuredNames, localNames));
      return res.status(200).json({
        anyConfigured: allProviders.length > 0,
        // Each CONFIGURED provider with its scope (local = OPSEC-safe) and whether it's on for this case.
        providers: allProviders.map((p) => ({ name: p.name, scope: p.scope, enabled: enabled.has(p.name) })),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Reachability of the configured providers (for the dashboard's ●up/down dots). Probes each
  // one (cached ~60s, so opening the modal repeatedly is cheap) and reports its last verdict.
  // Providers without a probe() (external SaaS) report ok:true (no health endpoint to test).
  app.get("/enrich-health", async (_req: Request, res: Response) => {
    try {
      const health = await Promise.all(allProviders.map(async (p) => {
        const h = p.probe ? await enrichHealth.check(p) : { ok: true, checkedAt: 0 };
        return { name: p.name, scope: p.scope, probed: Boolean(p.probe), ok: h.ok, detail: h.detail };
      }));
      return res.status(200).json({ providers: health });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Set which providers are enabled for this case. Accepts `{ providers: string[] }`
  // (preferred) or legacy `{ enabled: boolean }`. Saving re-runs enrichment; per-provider
  // caching means only the newly-enabled providers query the existing IOCs.
  app.post("/cases/:id/enrich-control", async (req: Request, res: Response) => {
    if (allProviders.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET / DFIR_MISP_* / DFIR_YETI_*)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    let providers: string[];
    if (Array.isArray(req.body?.providers)) providers = req.body.providers.map(String).filter((n: string) => configuredNames.includes(n));
    else if (typeof req.body?.enabled === "boolean") providers = req.body.enabled ? [...configuredNames] : [];
    else return res.status(400).json({ error: "providers (array of provider names) or enabled (boolean) is required" });
    try {
      await enrichControl.save(caseId, { providers });
      if (providers.length > 0) enrichInBackground(caseId);   // re-check; cache only queries newly-enabled / un-checked
      else enrichPending.delete(caseId);                      // disabled — stop the poller from waiting on a down provider for this case
      return res.status(200).json({ providers });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manual one-shot re-scan (e.g. force re-query). Honors the same providers; does NOT
  // change the toggle. `{ force: true }` re-queries already-enriched IOCs.
  app.post("/cases/:id/enrich", async (req: Request, res: Response) => {
    const providers = options.enrichmentProviders ?? [];
    if (providers.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const force = req.body?.force === true || req.query.force === "true";
    try {
      const state = await options.stateStore.load(caseId);
      enrichInBackground(caseId, force);
      return res.status(202).json({ accepted: true, iocs: state.iocs.length, providers: providers.map((p) => p.name) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // On-demand holistic synthesis: derive findings / MITRE / attacker path from the
  // forensic timeline. (Per-window capture builds the timeline; this writes the
  // conclusions.) Broadcasts the updated state to dashboard clients via onState.
  app.post("/cases/:id/synthesize", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for synthesis" });
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed") {
      return res.status(423).json({ error: `Case "${caseId}" is closed — reopen it before running synthesis` });
    }
    // Per-run Chain-of-Thought toggle (#121): "deepReasoning" enables extended thinking for THIS run
    // only (no .env edit + restart) — an optional thinkingTokens overrides the budget. Off otherwise.
    const deepReasoning = (req.body as { deepReasoning?: unknown })?.deepReasoning === true;
    const reqThinking = Number((req.body as { thinkingTokens?: unknown })?.thinkingTokens);
    const thinkingTokens = Number.isFinite(reqThinking) && reqThinking > 0 ? Math.floor(reqThinking) : undefined;
    options.onAiStatus?.(caseId, { status: "analyzing", at: new Date().toISOString(), detail: deepReasoning ? "synthesizing (deep reasoning)" : "synthesizing conclusions" });
    try {
      // Explicit user action → force, so it always runs even if inputs are unchanged.
      const state = await options.pipeline.synthesize(caseId, { force: true, deepReasoning, ...(thinkingTokens !== undefined ? { thinkingTokens } : {}) });
      // Keep the playbook checklist aligned with the fresh next steps/findings (idempotent —
      // preserves analyst status/edits). Best-effort: never fail synthesis on a playbook hiccup.
      if (options.playbookStore) {
        try {
          const { useTemplates } = await loadPlaybookControl(caseId);
          await options.playbookStore.sync(caseId, state, { useTemplates });
          options.onPlaybook?.(caseId);
        } catch { /* non-fatal */ }
      }
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      return res.status(200).json({
        findings: state.findings.length,
        mitreTechniques: state.mitreTechniques.length,
        forensicEvents: state.forensicTimeline.length,
        attackerPath: Boolean(state.attackerPath),
        narrativeTimeline: Boolean(state.narrativeTimeline),
      });
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Second LLM opinion (issue #116): run a DIFFERENT model over the same case (independent
  // re-synthesis + reconcile) and surface where it disagrees, for analyst QA. On-demand, two
  // text-only AI calls; NON-DESTRUCTIVE — the deltas are stored, not applied, until the analyst
  // accepts them per item. 501 when no second-opinion model is configured (DFIR_AI_SECOND_OPINION_MODEL).
  app.post("/cases/:id/second-opinion", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionEnabled) {
      return res.status(501).json({ error: "second-opinion model not configured — set DFIR_AI_SECOND_OPINION_MODEL" });
    }
    const caseId = req.params.id;
    // Same per-run deep-reasoning toggle (#121) as /synthesize — flows into both model A & B passes.
    const deepReasoning = (req.body as { deepReasoning?: unknown })?.deepReasoning === true;
    options.onAiStatus?.(caseId, { status: "analyzing", at: new Date().toISOString(), detail: deepReasoning ? "running second opinion (deep reasoning)" : "running second opinion" });
    try {
      const record = await options.pipeline.secondOpinion(caseId, { deepReasoning });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      options.onSecondOpinion?.(caseId);
      return res.status(200).json(record);
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Fetch the last second-opinion record for a case (or null). Read-only; no AI.
  app.get("/cases/:id/second-opinion", async (req: Request, res: Response) => {
    if (!options.secondOpinionStore) return res.status(200).json(null);
    try {
      return res.status(200).json(await options.secondOpinionStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Accept or reject ONE second-opinion delta. Accept (re-)applies all accepted deltas onto the
  // case (idempotent; durable across re-synthesis); reject only records the decision. The case
  // state is otherwise untouched. Body: { deltaId, accept }.
  app.post("/cases/:id/second-opinion/apply", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionStore) return res.status(501).json({ error: "second opinion not configured" });
    const deltaId = typeof req.body?.deltaId === "string" ? req.body.deltaId.trim() : "";
    const accept = req.body?.accept === true;
    if (!deltaId) return res.status(400).json({ error: "deltaId is required" });
    try {
      const { record } = await options.pipeline.applySecondOpinion(req.params.id, deltaId, accept);
      options.onSecondOpinion?.(req.params.id);
      return res.status(200).json(record);
    } catch (err) {
      const msg = (err as Error).message;
      const code = /unknown second-opinion delta/.test(msg) ? 404 : /no second opinion/.test(msg) ? 409 : 500;
      return res.status(code).json({ error: msg });
    }
  });

  // Bulk accept-all / reject-all over the still-pending second-opinion deltas, in one pass. Body:
  // { accept }. Accept (re-)applies all accepted deltas to the case; reject just records decisions.
  app.post("/cases/:id/second-opinion/apply-all", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.secondOpinionStore) return res.status(501).json({ error: "second opinion not configured" });
    const accept = req.body?.accept === true;
    try {
      const { record } = await options.pipeline.applyAllSecondOpinion(req.params.id, accept);
      options.onSecondOpinion?.(req.params.id);
      return res.status(200).json(record);
    } catch (err) {
      const msg = (err as Error).message;
      const code = /no second opinion/.test(msg) ? 409 : 500;
      return res.status(code).json({ error: msg });
    }
  });

  // Ask the LLM a free-form question about the case ("was data exfiltrated?"). Single-shot,
  // no state change — returns a grounded answer + status + collection guidance (`pointer`).
  app.post("/cases/:id/ask", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for case questions" });
    const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
    if (!question) return res.status(400).json({ error: "question is required" });
    try {
      const answer = await options.pipeline.ask(req.params.id, question);
      return res.status(200).json(answer);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Translate a plain-English hunting request into runnable queries per platform (issue #100).
  // EPHEMERAL (no state change) — the dashboard shows each query for review, copy, and (for the
  // Velociraptor query) one-click deploy via POST /velociraptor/hunt. Body: { request, platforms? }.
  // `platforms` is an optional analyst-chosen subset; both it and the result are bounded by the
  // server's DFIR_HUNT_PLATFORMS allowlist so a disabled platform is never generated.
  app.post("/cases/:id/translate-query", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for query translation" });
    const request = typeof req.body?.request === "string" ? req.body.request.trim() : "";
    if (!request) return res.status(400).json({ error: "request is required" });
    const enabled = options.huntPlatforms ?? [...HUNT_PLATFORMS];
    const bodyPlatforms = Array.isArray(req.body?.platforms)
      ? req.body.platforms
          .map((p: unknown) => normalizeHuntPlatform(typeof p === "string" ? p : ""))
          .filter((p: HuntPlatform | null): p is HuntPlatform => !!p)
      : [];
    const wanted = bodyPlatforms.length ? enabled.filter((p) => bodyPlatforms.includes(p)) : enabled;
    const platforms = wanted.length ? wanted : enabled;
    try {
      const result = await options.pipeline.translateQuery(req.params.id, request, platforms);
      logLine(`[translate-query] produced ${result.queries.length} query/ies for ${req.params.id}`);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Generate a management-facing executive summary over the synthesized case (one text-only AI
  // call). The dashboard shows it and can save it into report-meta.executiveSummary, which then
  // overrides the auto-derived summary in the generated report.
  app.post("/cases/:id/executive-summary", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for executive summary" });
    try {
      const result = await options.pipeline.executiveSummary(req.params.id);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Generate (or regenerate) a prose narrative timeline for the case (one text-only AI call).
  // Saves the result to state.narrativeTimeline so it persists and appears in the report/dashboard.
  app.post("/cases/:id/narrative", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for narrative generation" });
    try {
      const result = await options.pipeline.generateNarrative(req.params.id);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Save an analyst-edited narrative timeline. The analyst may edit the AI-generated narrative
  // before export; this persists the edit to state.narrativeTimeline until the next synthesis.
  app.put("/cases/:id/narrative", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const narrative = typeof req.body?.narrativeTimeline === "string" ? req.body.narrativeTimeline : "";
    try {
      const state = await options.stateStore.load(req.params.id);
      const updated = { ...state, narrativeTimeline: narrative };
      await options.stateStore.save(updated);
      return res.status(200).json({ narrativeTimeline: narrative });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Last-synthesis metadata: when synthesis last actually ran + what changed in the findings.
  // Backs the dashboard's "last synthesized N ago" indicator and the what-changed diff view.
  app.get("/cases/:id/synth-meta", async (req: Request, res: Response) => {
    if (!options.synthMetaStore) return res.status(501).json({ error: "synth metadata not configured" });
    try {
      return res.status(200).json(await options.synthMetaStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Last-import metadata: when the last import ran + what it added to the forensic timeline.
  // Backs the dashboard's "last import N ago - +N new events" banner and per-row "new" highlight.
  app.get("/cases/:id/import-meta", async (req: Request, res: Response) => {
    if (!options.importMetaStore) return res.status(501).json({ error: "import metadata not configured" });
    try {
      return res.status(200).json(await options.importMetaStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // #76 Import undo/redo. Imports can flood the dashboard; these let the analyst roll the forensic
  // timeline + IOCs back to the pre-import snapshot (and redo). The synthesis-derived conclusions are
  // re-derived from the restored timeline by resynthesizeInBackground, exactly as on import.

  // Current undo/redo state (button enable + labels). Lightweight summary, not the raw snapshots.
  app.get("/cases/:id/import/undo-stack", async (req: Request, res: Response) => {
    if (!options.importUndoStore) return res.status(501).json({ error: "import undo not configured" });
    try {
      const stack = await options.importUndoStore.load(req.params.id);
      return res.status(200).json(summarizeUndoStack(stack, options.importUndoStore.depth()));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Undo the latest import: restore the full pre-import state (findings/IOCs/timeline/MITRE/attacker
  // path), push the current state to redo. No AI re-synthesis — the snapshot is the exact prior state.
  app.post("/cases/:id/import/undo", async (req: Request, res: Response) => {
    if (!options.importUndoStore || !options.stateStore) return res.status(501).json({ error: "import undo not configured" });
    const caseId = req.params.id;
    try {
      const stack = await options.importUndoStore.load(caseId);
      const state = await options.stateStore.load(caseId);
      const result = applyUndo(stack, state);
      if (!result) return res.status(400).json({ error: "nothing to undo" });
      const next = await restoreImportState(caseId, result.restore);
      await options.importUndoStore.save(caseId, result.stack);
      // The "last import" banner / NEW row highlights describe a change that has now been rolled back.
      if (options.importMetaStore) { try { await options.importMetaStore.clear(caseId); options.onImportMeta?.(caseId); } catch { /* non-fatal */ } }
      options.onImportUndo?.(caseId);
      if (next) options.onState?.(next);
      return res.status(200).json(summarizeUndoStack(result.stack, options.importUndoStore.depth()));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Redo the most-recently-undone import: re-apply its full state.
  app.post("/cases/:id/import/redo", async (req: Request, res: Response) => {
    if (!options.importUndoStore || !options.stateStore) return res.status(501).json({ error: "import undo not configured" });
    const caseId = req.params.id;
    try {
      const stack = await options.importUndoStore.load(caseId);
      const state = await options.stateStore.load(caseId);
      const result = applyRedo(stack, state);
      if (!result) return res.status(400).json({ error: "nothing to redo" });
      const next = await restoreImportState(caseId, result.restore);
      await options.importUndoStore.save(caseId, result.stack);
      if (options.importMetaStore) { try { await options.importMetaStore.clear(caseId); options.onImportMeta?.(caseId); } catch { /* non-fatal */ } }
      options.onImportUndo?.(caseId);
      if (next) options.onState?.(next);
      return res.status(200).json(summarizeUndoStack(result.stack, options.importUndoStore.depth()));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add an analyst question to the case's open key questions (e.g. from Ask, when unknown).
  // It's pinned, so synthesis preserves it and answers it once the evidence supports it.
  app.post("/cases/:id/questions", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
    if (!question) return res.status(400).json({ error: "question is required" });
    const statusIn = String(req.body?.status ?? "unknown");
    const status: QuestionStatus = statusIn === "answered" || statusIn === "partial" ? statusIn : "unknown";
    try {
      const state = await options.stateStore.load(req.params.id);
      const nums = state.keyQuestions.map((q) => Number(/^aq(\d+)$/.exec(q.id)?.[1])).filter((n) => !Number.isNaN(n));
      const newQuestion: InvestigationQuestion = {
        id: `aq${(nums.length ? Math.max(...nums) : 0) + 1}`,
        question,
        status,
        answer: typeof req.body?.answer === "string" ? req.body.answer : "",
        pointer: typeof req.body?.pointer === "string" ? req.body.pointer : "",
        pinned: true,
      };
      const next = { ...state, keyQuestions: [...state.keyQuestions, newQuestion] };
      await options.stateStore.save(next);
      options.onState?.(next);
      return res.status(201).json(newQuestion);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Investigator comments on case entities (collaboration). GET lists them; POST adds one
  // to a `(targetType, targetId)` entity; DELETE removes by id. Add/remove ping live clients.
  app.get("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      return res.status(200).json(await options.commentsStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    const targetType = typeof req.body?.targetType === "string" ? req.body.targetType.trim() : "";
    const targetId = typeof req.body?.targetId === "string" ? req.body.targetId.trim() : "";
    const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
    if (!targetType || !targetId || !text) return res.status(400).json({ error: "targetType, targetId and text are required" });
    try {
      const comment = await options.commentsStore.add(req.params.id, {
        targetType, targetId, text,
        author: typeof req.body?.author === "string" ? req.body.author : "",
      });
      options.onComments?.(req.params.id);
      return res.status(201).json(comment);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/comments/:commentId", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      const removed = await options.commentsStore.remove(req.params.id, req.params.commentId);
      if (!removed) return res.status(404).json({ error: "comment not found" });
      options.onComments?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Analyst triage tags on case entities (hand labels). GET lists them; POST attaches one to a
  // `(targetType, targetId)` entity (label normalized + deduped server-side); DELETE removes by
  // id. Add/remove ping live clients. Survives synthesis (side file, not InvestigationState).
  app.get("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    try {
      return res.status(200).json(await options.tagsStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const targetType = typeof req.body?.targetType === "string" ? req.body.targetType.trim() : "";
    const targetId = typeof req.body?.targetId === "string" ? req.body.targetId.trim() : "";
    const label = typeof req.body?.label === "string" ? req.body.label.trim() : "";
    if (!targetType || !targetId || !label) return res.status(400).json({ error: "targetType, targetId and label are required" });
    try {
      const tag = await options.tagsStore.add(req.params.id, {
        targetType, targetId, label,
        author: typeof req.body?.author === "string" ? req.body.author : "",
      });
      options.onTags?.(req.params.id);
      return res.status(201).json(tag);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/tags/:tagId", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    try {
      const removed = await options.tagsStore.remove(req.params.id, req.params.tagId);
      if (!removed) return res.status(404).json({ error: "tag not found" });
      options.onTags?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-case playbook (issue #36): a trackable checklist auto-derived from the case's next
  // steps + Critical/High findings, plus analyst-added custom tasks. The list is re-derived
  // idempotently on every GET (write-if-changed) so it tracks the latest synthesis without
  // ever clobbering analyst status/edits. POST adds a custom task; POST /sync forces a
  // re-derive; PATCH /order reorders; PATCH /:taskId edits; DELETE /:taskId removes.
  // GET/PUT …/control toggles severity-based IR templates (Phase 2). The response carries
  // computed completion stats for the dashboard badge.
  const loadPlaybookControl = async (caseId: string): Promise<PlaybookControl> =>
    options.playbookControlStore ? options.playbookControlStore.load(caseId) : { ...DEFAULT_PLAYBOOK_CONTROL };

  // Re-derive against current state honoring the case's template setting (no-op-safe write).
  const syncPlaybook = async (caseId: string): Promise<PlaybookTask[]> => {
    if (!options.playbookStore || !options.stateStore) return options.playbookStore ? options.playbookStore.load(caseId) : [];
    const state = await options.stateStore.load(caseId);
    const { useTemplates } = await loadPlaybookControl(caseId);
    return options.playbookStore.sync(caseId, state, { useTemplates });
  };

  // Load the persisted hunt suggestions (#70), dropping any whose task was reworded/deleted since
  // generation, and write the pruned set back so stale ones don't keep returning. Best-effort — a
  // store hiccup never breaks the playbook read (returns []).
  const loadFreshHunts = async (caseId: string, tasks: readonly PlaybookTask[]) => {
    if (!options.playbookHuntStore) return [];
    try {
      const persisted = await options.playbookHuntStore.load(caseId);
      const fresh = selectFreshHunts(persisted, tasks);
      if (fresh.changed) await options.playbookHuntStore.save(caseId, { generatedAt: persisted.generatedAt, suggestions: fresh.suggestions, taskHashes: fresh.taskHashes });
      return fresh.suggestions;
    } catch {
      return [];
    }
  };

  app.get("/cases/:id/playbook/control", async (req: Request, res: Response) => {
    if (!options.playbookControlStore) return res.status(200).json({ ...DEFAULT_PLAYBOOK_CONTROL });
    try {
      return res.status(200).json(await options.playbookControlStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/playbook/control", async (req: Request, res: Response) => {
    if (!options.playbookControlStore) return res.status(501).json({ error: "playbook control not configured" });
    if (typeof req.body?.useTemplates !== "boolean") return res.status(400).json({ error: "useTemplates (boolean) is required" });
    try {
      const control = await options.playbookControlStore.set(req.params.id, { useTemplates: req.body.useTemplates });
      const tasks = await syncPlaybook(req.params.id);   // re-derive immediately under the new mode
      options.onPlaybook?.(req.params.id);
      return res.status(200).json({ control, tasks, stats: playbookStats(tasks) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/playbook", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    try {
      // Auto-sync against current state so the panel reflects the latest next steps/findings.
      const tasks = options.stateStore ? await syncPlaybook(req.params.id) : await options.playbookStore.load(req.params.id);
      // Persisted AI hunt suggestions, filtered to tasks that are UNCHANGED since generation (#70) —
      // so they survive a page refresh but a reworded/deleted task drops its stale hunt.
      const huntSuggestions = await loadFreshHunts(req.params.id, tasks);
      return res.status(200).json({ tasks, stats: playbookStats(tasks), control: await loadPlaybookControl(req.params.id), huntSuggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Force a re-derive from the current case state (the "Sync from analysis" button).
  app.post("/cases/:id/playbook/sync", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const tasks = await syncPlaybook(req.params.id);
      options.onPlaybook?.(req.params.id);
      return res.status(200).json({ tasks, stats: playbookStats(tasks), control: await loadPlaybookControl(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // AI-suggest a Velociraptor hunt for each ENDPOINT-related playbook task (issue #70). Single
  // text-only AI call, EPHEMERAL (no state change) — the dashboard shows each task's VQL + rationale
  // for review, then deploys it as a fleet HUNT (POST /velociraptor/hunt) or, for a task tied to one
  // endpoint, a single-client COLLECTION (POST /velociraptor/collect-host). Needs an AI provider +
  // the playbook store; does NOT need the Velociraptor API (the VQL is useful to copy even when off).
  // Registered BEFORE /:taskId so "suggest-hunts" is not captured as a task id.
  app.post("/cases/:id/playbook/suggest-hunts", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for hunt suggestions" });
    if (!options.playbookStore || !options.stateStore) return res.status(501).json({ error: "playbook not configured" });
    try {
      const tasks = await syncPlaybook(req.params.id);

      // SINGLE-TASK REGEN: body carries `{ taskId, excludeVql }` — force-regenerate just that one
      // task, passing the existing VQL so the model produces something different.
      const regenTaskId = typeof req.body?.taskId === "string" ? req.body.taskId.trim() : null;
      if (regenTaskId) {
        const task = tasks.find((t) => t.id === regenTaskId);
        if (!task) return res.status(404).json({ error: "task not found" });
        const excludeVql = typeof req.body?.excludeVql === "string" ? req.body.excludeVql.trim() : undefined;
        const [, artifactNames] = await Promise.all([
          refreshVeloClients().catch((e) => { logLine(`[velociraptor] inventory refresh before regen failed: ${(e as Error).message}`); return 0; }),
          options.velociraptorClient
            ? options.velociraptorClient.listClientArtifacts().then((a) => a.map((x) => x.name)).catch(() => [] as string[])
            : Promise.resolve([] as string[]),
        ]);
        const newSuggestions = await options.pipeline.suggestPlaybookHunts(req.params.id, [task], artifactNames, { excludeVql });
        const persisted = options.playbookHuntStore ? await options.playbookHuntStore.load(req.params.id) : { ...EMPTY_PERSISTED_HUNTS };
        // Replace the old suggestion for this task (if any) and keep everything else.
        const kept = (persisted.suggestions ?? []).filter((s) => s.taskId !== regenTaskId);
        const merged: typeof persisted = {
          generatedAt: new Date().toISOString(),
          suggestions: [...kept, ...newSuggestions.filter((s) => s.taskId === regenTaskId)],
          taskHashes: { ...persisted.taskHashes },
        };
        logLine(`[velociraptor] playbook hunt regen for task ${regenTaskId} in ${req.params.id}: ${newSuggestions.length} suggestion(s)`);
        if (options.playbookHuntStore) {
          try { await options.playbookHuntStore.save(req.params.id, merged); }
          catch (e) { logLine(`[velociraptor] could not persist playbook hunts: ${(e as Error).message}`); }
        }
        return res.status(200).json({ suggestions: merged.suggestions, generated: newSuggestions.length, more: false });
      }

      // INCREMENTAL (#70): keep the suggestions whose task is unchanged and only generate for NEW or
      // CHANGED tasks — so adding one task and pressing Generate sends just that task to the model and
      // never re-does the hunts that already exist. `force:true` regenerates everything from scratch.
      const force = req.body?.force === true;
      const persisted = options.playbookHuntStore ? await options.playbookHuntStore.load(req.params.id) : { ...EMPTY_PERSISTED_HUNTS };
      const fresh = force ? { suggestions: [], taskHashes: {} } : selectFreshHunts(persisted, tasks);
      const pending = pendingHuntTasks(tasks, fresh.taskHashes);
      // Concurrently (best-effort, no-op when the API is off): refresh the client inventory so a host
      // enrolled MID-INVESTIGATION is resolvable at deploy time, AND fetch the server's REAL CLIENT
      // artifact names so the model only references artifacts that EXIST. Skip the artifact fetch when
      // nothing is pending (no AI call needed). Both finish before the AI call → no added latency.
      const [, artifactNames] = await Promise.all([
        refreshVeloClients().catch((e) => { logLine(`[velociraptor] inventory refresh before suggestions failed: ${(e as Error).message}`); return 0; }),
        pending.length && options.velociraptorClient
          ? options.velociraptorClient.listClientArtifacts().then((a) => a.map((x) => x.name)).catch(() => [] as string[])
          : Promise.resolve([] as string[]),
      ]);
      // Keep only suggestions FOR the pending tasks — so a model that echoes a wrong taskId can't
      // duplicate or clobber a kept (covered) suggestion. fresh + new then have disjoint task ids.
      const pendingIds = new Set(pending.map((t) => t.id));
      const newSuggestions = (pending.length ? await options.pipeline.suggestPlaybookHunts(req.params.id, pending, artifactNames) : [])
        .filter((s) => pendingIds.has(s.taskId));
      // Which pending tasks to mark "evaluated" (won't be re-sent): if the model hit the per-generation
      // cap there may be MORE pending tasks it never got to — stamp only the ones it actually hunted, so
      // the rest are retried on the next press. Otherwise it saw every pending task → stamp them all
      // (a non-endpoint task it deliberately skipped won't be re-evaluated).
      const cap = Number(process.env.DFIR_PBHUNT_SUGGEST_MAX) || PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT;
      const truncated = newSuggestions.length >= cap;
      const suggestedIds = new Set(newSuggestions.map((s) => s.taskId));
      const evaluatedTasks = truncated ? pending.filter((t) => suggestedIds.has(t.id)) : pending;
      const merged = mergePersistedHunts(fresh, newSuggestions, evaluatedTasks, new Date().toISOString());
      logLine(`[velociraptor] playbook hunts for ${req.params.id}: ${newSuggestions.length} new (of ${pending.length} pending task(s))${truncated ? " [cap hit — press again for more]" : ""}, ${merged.suggestions.length} total`);
      // Persist so the set survives a refresh + future incremental generates. Best-effort.
      if (options.playbookHuntStore) {
        try { await options.playbookHuntStore.save(req.params.id, merged); }
        catch (e) { logLine(`[velociraptor] could not persist playbook hunts: ${(e as Error).message}`); }
      }
      return res.status(200).json({ suggestions: merged.suggestions, generated: newSuggestions.length, more: truncated });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Reorder tasks by a supplied id sequence. Registered BEFORE /:taskId so "order" is not
  // captured as a task id.
  app.patch("/cases/:id/playbook/order", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String) : null;
    if (!ids) return res.status(400).json({ error: "ids array is required" });
    try {
      const tasks = await options.playbookStore.reorder(req.params.id, ids);
      options.onPlaybook?.(req.params.id);
      return res.status(200).json({ tasks, stats: playbookStats(tasks) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/playbook", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    const title = typeof req.body?.title === "string" ? req.body.title.trim() : "";
    if (!title) return res.status(400).json({ error: "title is required" });
    const input: NewPlaybookTask = {
      title,
      description: typeof req.body?.description === "string" ? req.body.description : undefined,
      status: PLAYBOOK_STATUSES.includes(req.body?.status as PlaybookStatus) ? (req.body.status as PlaybookStatus) : undefined,
      priority: typeof req.body?.priority === "string" ? req.body.priority : undefined,
      assignee: typeof req.body?.assignee === "string" ? req.body.assignee : undefined,
      dueDate: typeof req.body?.dueDate === "string" ? req.body.dueDate : undefined,
      notes: typeof req.body?.notes === "string" ? req.body.notes : undefined,
      relatedFindingId: typeof req.body?.relatedFindingId === "string" ? req.body.relatedFindingId : undefined,
    };
    try {
      const task = await options.playbookStore.add(req.params.id, input);
      options.onPlaybook?.(req.params.id);
      dispatchNotify(playbookTaskEvent(req.params.id, task, "added", new Date().toISOString()));
      return res.status(201).json(task);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/playbook/:taskId", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    const patch: PlaybookTaskPatch = {};
    if (typeof req.body?.title === "string") patch.title = req.body.title;
    if (typeof req.body?.description === "string") patch.description = req.body.description;
    if (typeof req.body?.status === "string") patch.status = req.body.status as PlaybookStatus;
    if (typeof req.body?.priority === "string") patch.priority = req.body.priority;
    if (typeof req.body?.assignee === "string") patch.assignee = req.body.assignee;
    if (typeof req.body?.dueDate === "string") patch.dueDate = req.body.dueDate;
    if (typeof req.body?.notes === "string") patch.notes = req.body.notes;
    try {
      const updated = await options.playbookStore.update(req.params.id, req.params.taskId, patch);
      if (!updated) return res.status(404).json({ error: "playbook task not found" });
      options.onPlaybook?.(req.params.id);
      // Notify only on a STATUS change (the meaningful playbook signal) — "completed" when it lands
      // on done, "updated" otherwise. Pure metadata edits (notes/assignee) stay quiet to avoid noise.
      if (patch.status) {
        dispatchNotify(playbookTaskEvent(req.params.id, updated, updated.status === "done" ? "completed" : "updated", new Date().toISOString()));
      }
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/playbook/:taskId", async (req: Request, res: Response) => {
    if (!options.playbookStore) return res.status(501).json({ error: "playbook not configured" });
    try {
      const removed = await options.playbookStore.remove(req.params.id, req.params.taskId);
      if (!removed) return res.status(404).json({ error: "playbook task not found" });
      options.onPlaybook?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-case analyst notebook (hypotheses, notes, open questions). GET lists all entries;
  // POST adds one; PATCH updates text/type/linkedEntityIds; DELETE removes by id.
  // Entries survive synthesis (side file, not InvestigationState). The AI synthesis pass
  // reads notebook entries when ai-control.includeNotebook is true (opt-in).
  app.get("/cases/:id/notebook", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    try {
      return res.status(200).json(await options.notebookStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manual asset-graph edits (renames, additions, suppressions, link overrides). Each write
  // pings live dashboard clients so the graph refreshes without a page reload.
  app.get("/cases/:id/asset-overrides", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    try {
      return res.status(200).json(await options.assetOverridesStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/notebook", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
    if (!text) return res.status(400).json({ error: "text is required" });
    const typeIn = String(req.body?.type ?? "note");
    const type: NotebookEntryType = NOTEBOOK_ENTRY_TYPES.includes(typeIn as NotebookEntryType)
      ? (typeIn as NotebookEntryType)
      : "note";
    try {
      const entry = await options.notebookStore.add(req.params.id, {
        text,
        type,
        author: typeof req.body?.author === "string" ? req.body.author : undefined,
        linkedEntityIds: Array.isArray(req.body?.linkedEntityIds) ? req.body.linkedEntityIds.map(String) : undefined,
      });
      options.onNotebook?.(req.params.id);
      return res.status(201).json(entry);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Settings: read/write the .env file so the dashboard can configure the companion.
  app.get("/settings/env", async (_req: Request, res: Response) => {
    try {
      const env = await getEnvForSettings();
      return res.json({ env });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/notebook/:entryId", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    const patch: { text?: string; type?: NotebookEntryType; linkedEntityIds?: string[] } = {};
    if (typeof req.body?.text === "string") patch.text = req.body.text;
    if (typeof req.body?.type === "string" && NOTEBOOK_ENTRY_TYPES.includes(req.body.type as NotebookEntryType)) {
      patch.type = req.body.type as NotebookEntryType;
    }
    if (Array.isArray(req.body?.linkedEntityIds)) patch.linkedEntityIds = req.body.linkedEntityIds.map(String);
    try {
      const updated = await options.notebookStore.update(req.params.id, req.params.entryId, patch);
      if (!updated) return res.status(404).json({ error: "notebook entry not found" });
      options.onNotebook?.(req.params.id);
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Rename (or un-rename) an asset by its graph id. Pass an empty name to clear the rename.
  app.put("/cases/:id/asset-overrides/assets/:assetId", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const name = typeof req.body?.name === "string" ? req.body.name : "";
    try {
      const ov = await options.assetOverridesStore.rename(req.params.id, req.params.assetId, name);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/notebook/:entryId", async (req: Request, res: Response) => {
    if (!options.notebookStore) return res.status(501).json({ error: "notebook not configured" });
    try {
      const removed = await options.notebookStore.remove(req.params.id, req.params.entryId);
      if (!removed) return res.status(404).json({ error: "notebook entry not found" });
      options.onNotebook?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Create a manual asset (one not auto-derived from the forensic timeline).
  app.post("/cases/:id/asset-overrides/assets", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const type = typeof req.body?.type === "string" ? req.body.type.trim() : "host";
    if (!name) return res.status(400).json({ error: "name is required" });
    try {
      const result = await options.assetOverridesStore.addAsset(req.params.id, { name, type: type as AssetType });
      options.onAssetOverrides?.(req.params.id);
      return res.status(201).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Suppress an auto-derived asset or delete a manual one.
  app.delete("/cases/:id/asset-overrides/assets/:assetId", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    try {
      const ov = await options.assetOverridesStore.removeAsset(req.params.id, req.params.assetId);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Restore a suppressed auto-derived asset (remove it from the removed list).
  app.post("/cases/:id/asset-overrides/assets/:assetId/restore", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    try {
      const ov = await options.assetOverridesStore.restoreAsset(req.params.id, req.params.assetId);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add a manual link between an asset and an IoC. Body: { asset, ioc }.
  app.post("/cases/:id/asset-overrides/links", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const asset = typeof req.body?.asset === "string" ? req.body.asset.trim() : "";
    const ioc = typeof req.body?.ioc === "string" ? req.body.ioc.trim() : "";
    if (!asset || !ioc) return res.status(400).json({ error: "asset and ioc are required" });
    try {
      const ov = await options.assetOverridesStore.addLink(req.params.id, asset, ioc);
      options.onAssetOverrides?.(req.params.id);
      return res.status(201).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Suppress (or delete) a link. Query params: ?asset=...&ioc=...
  app.delete("/cases/:id/asset-overrides/links", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const asset = typeof req.query?.asset === "string" ? req.query.asset : "";
    const ioc = typeof req.query?.ioc === "string" ? req.query.ioc : "";
    if (!asset || !ioc) return res.status(400).json({ error: "asset and ioc query params are required" });
    try {
      const ov = await options.assetOverridesStore.removeLink(req.params.id, asset, ioc);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/settings/env", async (req: Request, res: Response) => {
    try {
      const updates = req.body?.updates;
      if (!updates || typeof updates !== "object" || Array.isArray(updates)) {
        return res.status(400).json({ error: "updates must be an object" });
      }
      await updateEnvFile(updates as Record<string, string>);
      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Re-arm any persisted live Velociraptor monitors so streaming survives a restart (#84). Fire-and-
  // forget + self-gating (no store/client or no persisted monitors → no-op), so it's a safe no-op for
  // tests and embeddings that don't use monitoring.
  void resumeVeloMonitors();

  return app;
}

import { StateStore as StateStoreImpl } from "./analysis/stateStore.js";
import { AnalysisPipeline as AnalysisPipelineImpl } from "./analysis/pipeline.js";
import { makeImageLoader } from "./analysis/imageLoader.js";
import { ProviderRegistry, ProviderError } from "./providers/provider.js";
import type { AIProvider as AnalyzeProvider } from "./providers/provider.js";
import { OpenAIProvider } from "./providers/openai.js";
import { OpenRouterProvider } from "./providers/openrouter.js";
import { OllamaCloudProvider } from "./providers/ollama.js";
import { LiteLlmProvider } from "./providers/litellm.js";
import { GeminiProvider } from "./providers/gemini.js";
import { AnthropicProvider } from "./providers/anthropic.js";
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
  return registry.get(name);
}

export function buildProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_PROVIDER,
    model: process.env.DFIR_AI_MODEL,
    apiKey: process.env.DFIR_AI_KEY,
    baseUrl: process.env.DFIR_AI_BASE_URL,
    imageDetail: process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined,
  });
}

// Synthesis model: dedicated DFIR_AI_SYNTH_* vars, falling back to the main model.
export function buildSynthesisProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_SYNTH_PROVIDER ?? process.env.DFIR_AI_PROVIDER,
    model: process.env.DFIR_AI_SYNTH_MODEL ?? process.env.DFIR_AI_MODEL,
    apiKey: process.env.DFIR_AI_SYNTH_KEY ?? process.env.DFIR_AI_KEY,
    baseUrl: process.env.DFIR_AI_SYNTH_BASE_URL ?? process.env.DFIR_AI_BASE_URL,
    imageDetail: process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined,
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
    provider: process.env.DFIR_AI_SECOND_OPINION_PROVIDER ?? process.env.DFIR_AI_PROVIDER,
    model,
    apiKey: process.env.DFIR_AI_SECOND_OPINION_KEY ?? process.env.DFIR_AI_KEY,
    baseUrl: process.env.DFIR_AI_SECOND_OPINION_BASE_URL ?? process.env.DFIR_AI_BASE_URL,
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
    apiKey: process.env.DFIR_AI_VELO_KEY ?? process.env.DFIR_AI_KEY,
    baseUrl: process.env.DFIR_AI_VELO_BASE_URL ?? process.env.DFIR_AI_BASE_URL,
  });
}

// Build the threat-intel enrichment providers from env. Each is added only when its key
// is present (MalwareBazaar needs DFIR_MB_KEY for its API). Empty array → enrichment off.
// Optional per-provider TLS trust for a self-hosted intel host with an internal-CA or
// self-signed cert. Returns undefined (→ default, fully-verified global fetch) unless a
// DFIR_<NAME>_CA bundle or DFIR_<NAME>_INSECURE flag is set. Scoped to that provider only.
function tlsFetchFor(name: "MISP" | "YETI" | "IRIS" | "TIMESKETCH" | "NOTION" | "CLICKUP" | "NOTIFY") {
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
    parentPageId: process.env.DFIR_NOTION_PARENT_PAGE_ID || undefined,
    databaseId: process.env.DFIR_NOTION_DATABASE_ID || undefined,
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
    stateStore: params.stateStore,
    legitimateStore: new LegitimateStore(params.store),
    scopeStore: new ScopeStore(params.store),
    imageLoader: params.imageLoader ?? makeImageLoader(params.store),
    onState: params.onState,
    onSynth: params.onSynth,
    anonStore: new AnonControlStore(params.store),
    customEntitiesStore: new CustomEntitiesStore(params.store),
    discoveredStore: new DiscoveredEntitiesStore(params.store),
    synthMetaStore: new SynthMetaStore(params.store),
    notebookStore: new NotebookStore(params.store),
    aiControlStore: new AiControlStore(params.store),
    ocrRunner: params.ocrRunner,
    logger: params.logger,
    kevStore: params.kevStore,
  });
}

export function startServer(casesRoot: string, port = 4773, host = "127.0.0.1", logDir?: string): void {
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
  const stateStore = new StateStoreImpl(store);
  const templateStore = new TemplateStore(join(dirname(casesRoot), "templates"));
  const artifactBundleStore = new ArtifactBundleStore(join(dirname(casesRoot), "bundles"));
  // Report templates are GLOBAL like case templates/bundles — a dedicated subdir beside cases/.
  const reportTemplateStore = new ReportTemplateStore(join(dirname(casesRoot), "report-templates"));
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
  const reportMetaStore = new ReportMetaStore(store);
  const reportTemplateControlStore = new ReportTemplateControlStore(store);
  const commentsStore = new CommentsStore(store);
  const tagsStore = new TagsStore(store);
  const notebookStore = new NotebookStore(store);
  const playbookStore = new PlaybookStore(store);
  const playbookHuntStore = new PlaybookHuntStore(store);
  const playbookControlStore = new PlaybookControlStore(store);
  const assetOverridesStore = new AssetOverridesStore(store);
  const synthMetaStore = new SynthMetaStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const importMetaStore = new ImportMetaStore(store);
  // #76: import undo/redo. Depth is the number of import levels kept (each = a full timeline+IOC copy).
  const importUndoStore = new ImportUndoStore(store, Number(process.env.DFIR_IMPORT_UNDO_DEPTH) || undefined);
  const notionExportStore = new NotionExportStore(store);
  const clickupExportStore = new ClickUpExportStore(store);
  const reportWriter = new ReportWriterImpl(store, stateStore, new ScopeStore(store), new LegitimateStore(store), reportMetaStore, new CustomerExposureStore(store), notebookStore, assetOverridesStore, playbookStore, reportTemplateStore, reportTemplateControlStore, kevStore);

  const provider = buildProvider();
  const synthesisProvider = buildSynthesisProvider();
  const velociraptorProvider = buildVelociraptorProvider();   // dedicated VQL-hunt model (#70)
  const secondOpinionProvider = buildSecondOpinionProvider(); // dedicated second-opinion model (#116)
  // Model labels for the second-opinion comparison header (fall back to provider name in the pipeline).
  const synthesisModelLabel = process.env.DFIR_AI_SYNTH_MODEL ?? process.env.DFIR_AI_MODEL ?? undefined;
  const secondOpinionModelLabel = process.env.DFIR_AI_SECOND_OPINION_MODEL?.trim() || undefined;
  if (secondOpinionProvider) logLine(`[second-opinion] enabled — model "${secondOpinionModelLabel}" (${secondOpinionProvider.name})`);
  // Provide the Tesseract OCR runner only when the vision model is on an external (cloud)
  // provider — if the model is local, screenshots never leave the machine so redaction is
  // optional. Evidence-first: the runner only redacts the in-memory copy sent to the model.
  const visionIsLocalForPipeline = isLocalAiProvider(process.env.DFIR_AI_PROVIDER, process.env.DFIR_AI_BASE_URL);
  const ocrRunner = !visionIsLocalForPipeline ? new TesseractOcrRunner() : undefined;
  const wiredPipeline = buildRuntimePipeline({
    provider, synthesisProvider, velociraptorProvider, stateStore, store, onState: (s) => hub.broadcast(s), ocrRunner, logger, kevStore,
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
    reportWriter,
    // The redacted-export route needs OCR even when the vision model is local (the pipeline's
    // ocrRunner is undefined in that case), so give createApp its own always-available runner.
    ocrRunner: ocrRunner ?? new TesseractOcrRunner(),
    reportMetaStore,
    reportTemplateStore,
    reportTemplateControlStore,
    onReportTemplate: (caseId) => hub.broadcastTo(caseId, { type: "report_template_changed" }),
    commentsStore,
    onComments: (caseId) => hub.broadcastTo(caseId, { type: "comments_changed" }),
    tagsStore,
    onTags: (caseId) => hub.broadcastTo(caseId, { type: "tags_changed" }),
    notebookStore,
    onNotebook: (caseId) => hub.broadcastTo(caseId, { type: "notebook_changed" }),
    playbookStore,
    playbookHuntStore,
    playbookControlStore,
    onPlaybook: (caseId) => hub.broadcastTo(caseId, { type: "playbook_changed" }),
    assetOverridesStore,
    onAssetOverrides: (caseId) => hub.broadcastTo(caseId, { type: "asset_overrides_changed" }),
    onLegitimate: (caseId) => hub.broadcastTo(caseId, { type: "legitimate_changed" }),
    onScope: (caseId, scope) => hub.broadcastTo(caseId, { type: "scope_changed", ...scope }),
    synthMetaStore,
    secondOpinionStore,
    secondOpinionEnabled: Boolean(secondOpinionProvider),
    onSecondOpinion: (caseId) => hub.broadcastTo(caseId, { type: "second_opinion_changed" }),
    importMetaStore,
    onImportMeta: (caseId) => hub.broadcastTo(caseId, { type: "import_meta_changed" }),
    importUndoStore,
    onImportUndo: (caseId) => hub.broadcastTo(caseId, { type: "import_undo_changed" }),
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
    timesketchClient: buildTimesketchClient(),
    timesketchOptions: timesketchPushOptions(),
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

  // Redirect root to the dashboard.
  app.get("/", (_req, res) => {
    res.redirect("/dashboard");
  });

  // Serve the dashboard.
  app.get("/dashboard", async (_req, res) => {
    const html = await readPublicAsset("dashboard.html", "utf8");
    res.type("html").send(html);
  });

  // Mobile companion (#59): a read-only, phone-optimized view (timeline / findings / IOCs / status)
  // for quick glances during IR away from the workstation. It's a PWA — installable via the
  // web manifest + a minimal service worker (offline app-shell). All three are static files in
  // public/; the SW is served at root so its default control scope covers /mobile.
  app.get("/mobile", async (_req, res) => {
    const html = await readPublicAsset("mobile.html", "utf8");
    res.type("html").send(html);
  });

  app.get("/manifest.webmanifest", async (_req, res) => {
    try {
      const json = await readPublicAsset("manifest.webmanifest", "utf8");
      res.type("application/manifest+json").set("Cache-Control", "no-cache").send(json);
    } catch {
      res.status(404).end();
    }
  });

  app.get("/sw.js", async (_req, res) => {
    try {
      const js = await readPublicAsset("sw.js", "utf8");
      // no-cache + a same-origin allowed scope so the SW can control /mobile even if it's
      // ever moved into a subdirectory; browsers re-check sw.js on every navigation anyway.
      res.type("application/javascript").set("Cache-Control", "no-cache").set("Service-Worker-Allowed", "/").send(js);
    } catch {
      res.status(404).end();
    }
  });

  // Bind host. Defaults to 127.0.0.1 (localhost-only — the OPSEC invariant for native runs).
  // Inside a container set DFIR_HOST=0.0.0.0 so the published port is reachable; the compose
  // file maps it to 127.0.0.1 on the HOST, so the localhost-only posture is preserved end-to-end.
  const server = app.listen(port, host, () => {
    const shownHost = host === "0.0.0.0" ? "127.0.0.1" : host;
    logLine(`DFIR companion on http://${shownHost}:${port} (dashboard at /dashboard)`);
  });

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
  loadDotenv({ path: seaRuntime ? join(companionDir, ".env") : undefined });
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
