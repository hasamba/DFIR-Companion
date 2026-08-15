/**
 * `AppOptions` — the injection bag `createApp` takes, and the AI-status event shape that travels
 * with it.
 *
 * Moved out of server.ts by #416. It is a pure type surface: ~90 optional members, every one a
 * store, client, or callback the host wires and a test may omit. Nothing here executes, so the move
 * cannot change behaviour — but it took 417 lines and roughly half of server.ts's import block with
 * it, which is the point. The definitions moved; the public surface did not (server.ts re-exports
 * all four names), so routes/context.ts, the presidio routes and the tests keep importing them from
 * `src/server.js` exactly as before — the same treatment #384 gave the integration factories.
 *
 * EVERY import here is `import type`. This file is imported by server.ts at type level only, and a
 * value import would put ~70 modules back on server.ts's runtime graph for no reason.
 */
import type { AnalysisPipeline } from "../analysis/pipeline.js";
import type { TeamAuth } from "../auth/teamAuth.js";
import type { StateLock } from "../analysis/stateLock.js";
import type { OperationalMetricsStore } from "../analysis/operationalMetrics.js";
import type { StateStore } from "../analysis/stateStore.js";
import type { ReportWriter } from "../reports/reportWriter.js";
import type { OcrRunner } from "../analysis/ocrRedact.js";
import type { ReportMetaStore } from "../reports/reportMeta.js";
import type { ReportVersionStore } from "../reports/reportVersionStore.js";
import type { ReportTemplateStore } from "../reports/reportTemplateStore.js";
import type { ReportTemplateControlStore } from "../reports/reportTemplateControl.js";
import type { DashboardViewStore } from "../analysis/dashboardViewStore.js";
import type { ActivityLogStore } from "../analysis/activityLog.js";
import type { CommentsStore } from "../analysis/comments.js";
import type { TagsStore } from "../analysis/tags.js";
import type { PinnedFindingsStore } from "../analysis/pinnedFindings.js";
import type { FindingWorkflowStore } from "../analysis/findingWorkflow.js";
import type { NotebookStore } from "../analysis/notebookStore.js";
import type { HypothesisStore } from "../analysis/hypothesisStore.js";
import type { LearnedPatternStore } from "../analysis/learnedPatternStore.js";
import type { SourceTrustStore } from "../analysis/sourceTrustStore.js";
import type { ClockSkewStore } from "../analysis/clockSkewStore.js";
import type { DwellWindowStore } from "../analysis/dwellWindowStore.js";
import type { SuperTimelineStore } from "../analysis/superTimelineStore.js";
import type { StarredReportStore } from "../analysis/starredReportStore.js";
import type { TaggerStore } from "../analysis/taggerStore.js";
import type { ForensicGateControlStore } from "../analysis/forensicGateControl.js";
import type { CustodyStore } from "../analysis/custody.js";
import type { EvidenceIntegrityMonitor } from "../analysis/custodyIntegrity.js";
import type { ConfidenceControlStore } from "../analysis/confidenceControl.js";
import type { ComplianceControlStore } from "../analysis/complianceControl.js";
import type { PlaybookStore } from "../analysis/playbookStore.js";
import type { PlaybookHuntStore } from "../analysis/playbookHuntStore.js";
import type { PlaybookControlStore } from "../analysis/playbookControl.js";
import type { AssetOverridesStore } from "../analysis/assetOverrides.js";
import type { HostDuplicateDismissalStore } from "../analysis/hostDuplicateDismissals.js";
import type { LateralPathDismissStore } from "../analysis/lateralPathDismiss.js";
import type { IocAliasStore } from "../analysis/iocAlias.js";
import type { SynthMetaStore } from "../analysis/synthMeta.js";
import type { AnalysisRunStore } from "../analysis/analysisRunStore.js";
import type { AiCostStore } from "../analysis/aiCost.js";
import type { CorrelationProfileStore } from "../analysis/correlationProfile.js";
import type { SecondOpinionStore } from "../analysis/secondOpinionStore.js";
import type { ImportMetaStore } from "../analysis/importMeta.js";
import type { DropStatusStore } from "../analysis/dropStatus.js";
import type { ImportUndoStore } from "../analysis/importUndo.js";
import type { ScopeWindow } from "../analysis/scope.js";
import type { EnrichmentProvider } from "../enrichment/provider.js";
import type { CustomerExposureProvider } from "../analysis/customerExposure.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { IrisClient } from "../integrations/iris/irisClient.js";
import type { IrisPushOptions } from "../integrations/iris/irisPush.js";
import type { IrisExportStore } from "../integrations/iris/irisExportStore.js";
import type { VelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";
import type { ToolRunner } from "../integrations/tools/toolRunner.js";
import type { ToolId, ToolConfig } from "../integrations/tools/toolConfig.js";
import type { CustomToolStore } from "../integrations/tools/customToolStore.js";
import type { McpServerStore } from "../integrations/mcp/mcpServerStore.js";
import type { ClaudeRunner } from "../providers/claudeRunner.js";
import type { TransferRunner } from "../integrations/mcp/mcpDelivery.js";
import type { VelociraptorClientStore } from "../analysis/velociraptorClientStore.js";
import type { ArtifactBundleStore } from "../analysis/artifactBundleStore.js";
import type { VeloHuntStore } from "../analysis/veloHuntStore.js";
import type { JobManager } from "../analysis/jobManager.js";
import type { HuntOutcomeStore } from "../analysis/huntOutcomeStore.js";
import type { HuntRunSnapshotStore } from "../analysis/huntRunSnapshotStore.js";
import type { VeloMonitorStore } from "../analysis/veloMonitorStore.js";
import type { PushTokenStore } from "../analysis/pushTokenStore.js";
import type { IocWhitelistStore } from "../analysis/iocWhitelistStore.js";
import type { ImporterStore } from "../analysis/importerStore.js";
import type { NsrlStore } from "../analysis/nsrlStore.js";
import type { NsrlDb } from "../analysis/nsrlDb.js";
import type { KevStore } from "../analysis/kevStore.js";
import type { HuntPlatform } from "../analysis/huntPlatforms.js";
import type { TimesketchClient } from "../integrations/timesketch/timesketchClient.js";
import type { TimesketchPushOptions } from "../integrations/timesketch/timesketchPush.js";
import type { TemplateStore } from "../analysis/templateStore.js";
import type { IncidentTypeStore } from "../analysis/incidentTypeStore.js";
import type { CollectionPlanStore } from "../analysis/collectionPlanStore.js";
import type { HostScopeStore } from "../analysis/hostScopeStore.js";
import type { MispPushClient } from "../integrations/misp/mispPushClient.js";
import type { MispPushOptions } from "../integrations/misp/mispPush.js";
import type { NotionClient } from "../integrations/notion/notionClient.js";
import type { NotionPushOptions } from "../integrations/notion/notionPush.js";
import type { NotionExportStore } from "../integrations/notion/notionExportStore.js";
import type { ClickUpClient } from "../integrations/clickup/clickupClient.js";
import type { ClickUpExportStore } from "../integrations/clickup/clickupExportStore.js";
import type { JiraClientLike } from "../integrations/jira/jiraClient.js";
import type { JiraExportStore } from "../integrations/jira/jiraExportStore.js";
import type { ServiceNowClientLike } from "../integrations/servicenow/servicenowClient.js";
import type { ServiceNowExportStore } from "../integrations/servicenow/servicenowExportStore.js";
import type { NotificationConfigStore } from "../analysis/notificationStore.js";
import type { SlashCommandChannelStore } from "../analysis/slashCommandStore.js";
import type { Notifier } from "../integrations/notify/notifyDispatch.js";
import type { AIProvider as AnalyzeProvider } from "../providers/provider.js";
import type { UpdateCheckStore } from "../analysis/updateCheckStore.js";
import type { BackupManager } from "../storage/backupManager.js";
import type { PreflightReport } from "../analysis/preflight.js";

export type AiStatus = "analyzing" | "idle" | "error";
// What the AI is actually doing, so the dashboard can say "processing screenshots"
// vs "synthesizing" vs idle rather than a generic "analyzing".
// "deep-pass" is its own phase rather than another "synthesizing": its detail already reads as a
// whole sentence ("deep pass (Medium+) — reading batch 2 of 5"), and the client must be able to tell
// the two apart to render it without the "synthesizing findings…" prefix.
export type AiPhase = "extracting" | "synthesizing" | "deep-pass";

export interface AiStatusEvent {
  status: AiStatus;
  at: string; // ISO timestamp
  phase?: AiPhase; // present when status === "analyzing"
  detail?: string; // e.g. window size, or error message
}

export interface AppOptions {
  pipeline?: AnalysisPipeline;
  teamAuth?: TeamAuth;
  // Per-case mutex serializing load->save critical sections so concurrent state writes
  // (manual adds vs background enrichment/synthesis) cannot clobber each other.
  stateLock?: StateLock;
  aiConfigured?: boolean;
  operationalMetrics?: OperationalMetricsStore;
  liveConnectionCount?: () => number;
  windowSize?: number;
  // Safety-net interval that drains capture buffers even when a window never fills.
  // Default 5 min; set 0 to disable.
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
  // Report versioning (#77): one snapshot per report regeneration (markdown + meta + content hash +
  // the diff-relevant slice of state), powering a version list, a diff view, and rollback of the
  // editable report-meta.
  reportVersionStore?: ReportVersionStore;
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
  // Per-host clock offsets, the analyst's manual overrides and the alignment toggle (#228), in
  // state/clock-skew.json. onClockSkew pings dashboard clients to re-fetch — alignment changes every
  // timestamp on screen, so the timeline must be reloaded with it.
  clockSkewStore?: ClockSkewStore;
  onClockSkew?: (caseId: string) => void;
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
  custodyStore?: CustodyStore;
  integrityMonitor?: EvidenceIntegrityMonitor;
  // Per-case minimum-confidence display preference (#226) — a machine/analyst preference, not
  // investigation data, mirroring forensicGateControlStore's shape. Purely a display filter: nothing
  // is removed from state, only the dashboard's findings list defaults to this floor.
  confidenceControlStore?: ConfidenceControlStore;
  onConfidenceControl?: (caseId: string) => void;
  // Per-case compliance-view settings (#336): the analyst-set incident-discovery date the
  // notification clocks run from, and which frameworks to show. Both are inputs the ATT&CK ->
  // obligation mapping cannot derive on its own — see analysis/complianceControl.ts.
  complianceControlStore?: ComplianceControlStore;
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
  // Pairs the analyst has judged to be different machines, persisted per case in
  // state/host-duplicate-dismissals.json. Presence of this store is what ENABLES the pre-synthesis
  // near-duplicate merge gate — see analysis/hostDuplicateGate.ts.
  hostDuplicateDismissalStore?: HostDuplicateDismissalStore;
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
  // Append-only operation manifests (#377), including replay ancestry and integrity hashes.
  analysisRunStore?: AnalysisRunStore;
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
  enrichProviderDelayMs?: Record<string, number>; // per-provider throttle overrides (keyed by provider.name)
  enrichJitterMs?: number; // ± random jitter added to the inter-call wait (#78)
  enrichRetries?: number; // retry attempts for a provider call that hits a 429 (#78)
  enrichRetryBackoffMs?: number; // base backoff before the first 429 retry, doubles each attempt (#78)
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
  // Policy for the MCP servers CLAUDE CODE is configured with (#296) — which of them case evidence
  // may be pointed at, what they may run, how it gets there. No URLs and no tokens: the analyst
  // configures servers in Claude Code, and the companion asks Claude Code to call them.
  // Absent → the /mcp routes answer 501.
  mcpServerStore?: McpServerStore;
  // Drives the `claude` CLI for MCP discovery and single tool calls. Tests inject; absent = a real
  // spawn. The Companion speaks no MCP itself, so this is the only route to a server.
  mcpClaudeRunner?: ClaudeRunner;
  // How evidence is pushed to an analysis host (scp). Defaults to a real spawn; tests inject.
  mcpTransferRunner?: TransferRunner;
  // Drives agentic MCP mode (spawns the claude CLI). Tests inject; absent = the real spawn.
  mcpAgentRunner?: ClaudeRunner;
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
  // Durable background-job ledger (#225, #380): tracks heavy async operations across restarts.
  // Jobs appear in the dashboard Jobs panel + /api/jobs. Constructed in startServer (its
  // onJob hook WS-broadcasts job_changed); absent in createApp-only unit tests + scripts/* pipelines.
  jobManager?: JobManager;
  // Hunting feedback loop (#157): per-case ledger of deployed hunts + their outcomes (hit/miss +
  // counts). Recorded on deploy (bundle + suggested fleet/playbook/technique hunts), filled on collect,
  // read by the suggestion routes (exclude + "PRIOR HUNTS" context) and the dashboard hunting profile.
  huntOutcomeStore?: HuntOutcomeStore;
  // Run-to-run hunt diffing (#80): the latest result-row snapshot per VQL fingerprint, so re-deploying
  // a recurring/scheduled hunt can show what's new/gone vs its PREVIOUS run (not just vs the whole
  // case). Sibling to huntOutcomeStore — see huntRunSnapshotStore.ts.
  huntRunSnapshotStore?: HuntRunSnapshotStore;
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
  // Incident-type auto-playbooks (#236): the built-in + custom incident-type library plus the
  // per-case chosen-type record. Applies a type's auto-configuration (key questions, next steps,
  // expected-finding seeds) at case creation or on demand, and feeds the synthesis hint.
  incidentTypeStore?: IncidentTypeStore;
  // Collection plan (#347): per-case analyst overrides for the incident type's evidence checklist.
  // The plan itself is derived on read from the timeline — only the overrides are stored.
  collectionPlanStore?: CollectionPlanStore;
  // Host scope ledger: analyst decisions only (clearances, out-of-scope). The ledger itself is
  // derived on read from the super-timeline, findings and the fleet snapshot.
  hostScopeStore?: HostScopeStore;
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
  // Jira export (issue #272): push individual findings as Jira issues. Configured via
  // DFIR_JIRA_URL, DFIR_JIRA_USER, DFIR_JIRA_TOKEN, and DFIR_JIRA_PROJECT_KEY.
  // Typed as the INTERFACE, not the concrete client: everything downstream
  // (pushFindingToJira / pushFindingsToJira / the `configured` flag) needs only me() +
  // createIssue() + updateIssue(), and naming the class here forced the route tests to
  // launder their stub through an `as unknown as` cast, which is what kept them out of the
  // typecheck (#385). Production still passes a real JiraClient.
  jiraClient?: JiraClientLike;
  jiraExportStore?: JiraExportStore;
  jiraOptions?: { projectKey?: string; issueType?: string };
  // ServiceNow export (issue #272): push individual findings as ServiceNow incidents. Configured via
  // DFIR_SERVICENOW_URL, DFIR_SERVICENOW_USER, and DFIR_SERVICENOW_PASSWORD.
  // Interface rather than the concrete client, for the same reason as jiraClient above.
  servicenowClient?: ServiceNowClientLike;
  servicenowExportStore?: ServiceNowExportStore;
  servicenowOptions?: { caller?: string; category?: string; subcategory?: string };
  // Notifications (issue #58): a GLOBAL channel store (Slack/Teams webhooks + SMTP email) + a
  // notifier that dispatches NotificationEvents to the channels that want them. Opt-in — the store
  // starts empty. `notifier` is the dispatcher (loads channels, formats, sends, best-effort);
  // `notifyEmailEnabled` tells the dashboard whether an SMTP transport is wired (so it can hint).
  // `dashboardBaseUrl` deep-links notifications back to the case.
  notificationStore?: NotificationConfigStore;
  // Per-channel case-binding store for the war-room slash-command bot (#235), in a global JSON
  // file beside the notification config. Absent → the bot's routes are not registered at all.
  slashCommandChannelStore?: SlashCommandChannelStore;
  // Poll Telegram for commands instead of receiving them on a webhook, so no inbound URL is needed
  // (#235). Gated on this flag rather than read straight from env, so createApp-only unit tests
  // never start a network loop — same reasoning as the drop-folder watcher below.
  telegramPolling?: boolean;
  // Receive Slack commands over an outbound WebSocket instead of a Request URL (#235). Same
  // reasoning as telegramPolling above: gated on the flag so tests never open a socket.
  slackSocketMode?: boolean;
  notifier?: Notifier;
  notifyEmailEnabled?: boolean;
  dashboardBaseUrl?: string;
  // Diagnostics live probe; tests can inject a no-network provider.
  aiTestProvider?: () => AnalyzeProvider | undefined;
  // Opt-in "newer release available" notice (issue #127). All optional → a bare createApp (tests)
  // gets the feature OFF and never touches the network or a timer.
  updateCheckStore?: UpdateCheckStore;
  appVersion?: string; // resolved once in startServer via getAppVersion()
  updateRepo?: string; // default DEFAULT_UPDATE_REPO; override for forks
  updateCheckEnv?: string; // raw DFIR_UPDATE_CHECK (passed, not read globally, for testability)
  updateFetch?: typeof fetch; // injectable so tests never hit the network
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
  // Additional browser origins beyond the always-trusted extension and loopback origins.
  allowedOrigins?: string[];
  // Named hosts/suffixes explicitly trusted by the DNS-rebinding guard.
  allowedHosts?: string[];
  allowedHostSuffixes?: string[];
}
