// The tier-3 feature manifest, shared by every suite that asks something per feature.
//
// Extracted from dashboardFeatureModules.test.ts when that file passed the repo's 800-line limit
// (#415). The limit does not reach tests — check:size walks src/ and public/ only — so nothing
// would have failed; growing the one file until nobody reads the bottom of it is the actual cost.

import { readFile } from "node:fs/promises";
import type { DashboardScript } from "../helpers/dashboardAst.js";
import {
  dashboardScripts,
  functionBindingsOf,
  scriptFromSource,
  topLevelBindings,
} from "../helpers/dashboardAst.js";
import { globalNamesOf } from "../helpers/dashboardModule.js";

// TIER 3 (#415): whole features moved out of the inline script, each owning its own state.
//
// One suite for eight modules rather than eight suites, because the assertions are identical in
// shape and the differences that matter are data — which names each publishes, which state each
// keeps private. A per-module file would be eight copies of the same five checks.
//
// WHY THESE EIGHT, AND WHY AN IIFE. The measurement for this tier found nine features with ZERO
// escaping reads: every mutable binding they touch is read by nothing else, so the binding travels
// with the feature. That is the ADR's own plan for tier 3 — "they move into their feature's module
// as `let` at module scope and never become anyone's API" — with one correction. In a CLASSIC
// script a top-level `let` joins the shared global lexical environment, so it would still be
// reachable by name from every other script; js/dashboard-tagger.js and js/dashboard-kev.js got
// away with top-level declarations only because they hold no state. These do, so they are wrapped,
// and only the names the page actually calls are published.

export const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

export interface Feature {
  file: string;
  /** Names the inline script calls by bare name, so the module must put them on `window`. */
  publish: string[];
  /** State that must NOT be reachable from outside the closure. */
  private: string[];
  /** A published entry point that does the feature's load-time work, if it has one. */
  initializer?: string;
  /** Names that only exist AFTER the initializer has run. */
  postInitPublish?: string[];
}

export const FEATURES: Feature[] = [
  {
    file: "dashboard-anomalies.js",
    publish: ["loadAnomalies", "scheduleAnomaliesReload", "markAnomalySpikeFalsePositive"],
    private: ["anomaliesData", "anomaliesTimer"],
  },
  {
    file: "dashboard-sessions.js",
    // sessionsCollapsed came home: its only reader is this feature's own collapse-all control.
    publish: ["loadSessions", "scheduleSessionsReload", "summarizeSession", "toggleSessionsCollapse"],
    private: ["sessionsData", "sessionsTimer", "sessionSummaries", "sessionsCollapsed"],
  },
  {
    file: "dashboard-compliance.js",
    publish: [
      "loadCompliance",
      "scheduleComplianceReload",
      "setComplianceDiscovered",
      "clearComplianceDiscovered",
      "toggleComplianceFramework",
    ],
    private: ["complianceData", "complianceTimer"],
  },
  {
    file: "dashboard-d3fend.js",
    publish: ["loadD3fend", "scheduleD3fendReload"],
    private: ["d3fendData", "d3fendTimer"],
  },
  {
    file: "dashboard-geo.js",
    publish: [
      "loadGeoMap",
      "scheduleGeoMapReload",
      "renderGeoView",
      "ensureGeoMap",
      "renderGeoMarkers",
      "geoFocusIp",
      "geoDownloadCsv",
    ],
    private: [
      "geoMapData",
      "geoMap",
      "geoLayer",
      "geoFlowLayer",
      "geoMapTimer",
      "geoMapInitializing",
      // Missing from the first inventory, which is its own argument for asserting the EXACT global
      // set rather than listing names by hand and hoping the list is complete.
      "geoTileUrl",
    ],
  },
  {
    file: "dashboard-custody.js",
    publish: ["initCustodyButtons", "loadCustody", "verifyCustodyOnOpen"],
    private: ["custodyRecords", "custodyFailedPaths", "custodyVerifiedAt"],
    // Declared late. The page guards and calls initCustodyButtons() exactly as it does the other
    // two initializers, but this entry omitted the field, so every check keyed on
    // `f.initializer` skipped it — and the only thing standing behind it was
    // `expect(html).toContain("initCustodyButtons();")`, a check on prose. The manifest
    // completeness test below now derives the expected set from the page instead of trusting
    // this list, so a fourth initializer cannot be added without an entry either.
    initializer: "initCustodyButtons",
  },
  { file: "dashboard-backup.js", publish: ["loadCaseBackups", "restoreCaseBackup"], private: [] },
  {
    // The load-time-heavy one: everything it does on load is wrapped in initTicketIntegrations(),
    // which the page calls where the block used to sit. openIrisImportModal is published from
    // INSIDE that function, so it is not on this list — the exact-globals check below would
    // otherwise fail, which is the honest signal that it appears later rather than at load.
    file: "dashboard-tickets.js",
    publish: ["pushFindingToTicket", "bulkPushFindingsToTicket", "initTicketIntegrations"],
    private: [
      // The re-entry latch this PR added. It was missing from the first version of this list, and
      // moving it out to shared global scope passed every test in the file — the same lesson the
      // geoTileUrl note above records, one tier later.
      "initialised",
      "pushSelect",
      "notionHasDefault",
      "clickupDefaultList",
      "notionOverlay",
      "irisImportOverlay",
      "irisReconnectBtn",
      "clickupOverlay",
      "irisPushOverlay",
    ],
    // Everything this module does happens when the page calls initTicketIntegrations(), so the
    // checks that matter have to RUN it — see the block at the bottom of this file.
    initializer: "initTicketIntegrations",
    postInitPublish: ["openIrisImportModal"],
  },
  {
    // MCP Analysis (#296) — the agent-driven tool runner. The cleanest tier-3 candidate left when
    // this was measured: 29 top-level declarations in the block and exactly ONE name crossing the
    // boundary (loadMcpRun, called by the lazy-section table). Its three outward calls — esc,
    // fileToBase64, mcpJobDuration — all resolve to tier-1 helper modules tagged before it.
    file: "dashboard-mcp.js",
    publish: ["loadMcpRun", "initMcp"],
    private: [
      "_mcpRunServers",
      "_mcpWatchToken",
      "_mcpActiveJobId",
      "_mcpRetry",
      "_mcpPreviewJob",
      "MCP_BROWSER_FILE_MAX_MB",
    ],
    initializer: "initMcp",
  },
  {
    // Hunting Profile (#157). The only candidate on the board with ZERO escaping bindings: its one
    // module-scope value is a frozen label/colour lookup, and its second function is internal.
    // No initializer — it has no load-time DOM work to defer, so there is nothing for the page to
    // call at load and nothing that could wire against markup that does not exist yet.
    file: "dashboard-hunt-profile.js",
    publish: ["loadHuntProfile"],
    // renderHuntProfile is private too, but deliberately not listed: this check exists to catch a
    // binding assigned without being declared, and a function declaration cannot become an implicit
    // global. The exact-globals check above already proves it stays off window.
    private: ["HP_STATUS"],
  },
  {
    // Four server-derived panels in one file — see the module header for why they are not four
    // files. The manifest treats it as one module because that is what it is; the publish list is
    // the union of the four load/schedule pairs the page calls.
    file: "dashboard-derived-panels.js",
    publish: [
      "loadBeacons",
      "scheduleBeaconsReload",
      "loadEvidenceGaps",
      "scheduleEvidenceGapsReload",
      "loadPlaybookMatch",
      "schedulePlaybookMatchReload",
      "loadAttackMitigations",
      "scheduleAttackMitigationsReload",
      "generateRemediation",
    ],
    private: [
      "beaconsData",
      "beaconsTimer",
      "evidenceGapsData",
      "evidenceGapsTimer",
      "playbookMatchData",
      "playbookMatchTimer",
      "mitigationsData",
      "mitigationsTimer",
    ],
  },
  {
    // Deep pass (#282). Two of its four bindings used to escape and both were closed rather than
    // published — see the module header. It calls back into the page's job registry, which is the
    // established shape (js/dashboard-swimlane.js does it seven times), not a new dependency.
    // Its five controls came home in #415: they had been left under the "Background jobs" banner.
    file: "dashboard-deep-pass.js",
    initializer: "initDeepPass",
    publish: [
      "initDeepPass",
      "runDeepPass",
      "cancelDeepPass",
      "resetDeepPass",
      "applyDeepPassGate",
      "loadDeepPassPreview",
      "deepPassGuidance",
      "deepPassBusy",
      "deepPassJob",
      "setDeepPassSynthesisEnabled",
    ],
    private: ["deepPassSynthesisEnabled", "deepPassPreviewLoaded", "deepPassPreviewSeq", "deepPassPosting"],
  },
  {
    // Super timeline (#188). The largest tier-3 move: 591 lines, 16 mutable bindings, and the two
    // that used to be written from outside became setters rather than staying public.
    file: "dashboard-super-timeline.js",
    initializer: "initSuperTimeline",
    publish: [
      "applyTimeframe",
      "clearSuperTime",
      "initSuperTimeline",
      "closeSuperCtxMenu",
      "genStarredReport",
      "genViewSummary",
      "loadSavedStarredReport",
      "loadSavedTimeframes",
      "loadSuperTimeline",
      "openSuperCtxMenu",
      "promoteSuperSelected",
      "refreshSuperRows",
      "renderSuperTimeline",
      "resetSuperPagination",
      "saveTimeframe",
      "setSuperLabelFilter",
      "superBulkStar",
      "superBulkTag",
      "superCaseId",
      "superPage",
      "superScopeToWindow",
      "toggleSuperPromote",
      "toggleSuperSelectAll",
      "toggleSuperStarredOnly",
      "toggleSuperTaggedOnly",
    ],
    private: [
      "superOffset",
      "superTotal",
      "superOrigins",
      "superSelectedOrigins",
      "superKnownOrigins",
      "superHosts",
      "superSelectedHosts",
      "superKnownHosts",
      "superLabelsAvail",
      "superSelectedLabels",
      "superPromote",
      "superTaggedOnly",
      "superStarredOnly",
      "superSavedTimeframes",
    ],
  },
  {
    // Playbook (#230). Zero state escapes — the two that looked like escapes were a mention in a
    // comment and an HTML id attribute, which is why the block check reads code and not text.
    file: "dashboard-playbook.js",
    initializer: "initPlaybook",
    publish: [
      "loadPlaybook",
      "pbPatch",
      "pbDelete",
      "pbMove",
      "pbToggleDep",
      "pbToggleDeps",
      "pbJumpFinding",
      "doSuggestPlaybookHunts",
      "resetPlaybookHuntSuggest",
      "initPlaybook",
    ],
    private: ["playbookTasks", "pbOpenOnly", "pbDepsOpen", "pbHuntFlat", "pbHuntCollapsed"],
  },
  {
    // Health / Diagnostics (#118). Its five controls were wired from the page's Settings block,
    // which meant five bare references to this file evaluated at load; initDiagnostics() owns that
    // binding now so the page guards one name instead of five.
    file: "dashboard-diagnostics.js",
    initializer: "initDiagnostics",
    publish: [
      "initDiagnostics",
      "loadDiagnostics",
      "renderPreflightStatus",
      "loadPreflightStatus",
      "loadCaseStats",
      "loadClockSkew",
      "clockSkewMutate",
      "diagAiTest",
      "diagComputeSizes",
      "diagCopy",
      "diagDownloadSupport",
      "diagPreviewSupport",
    ],
    private: ["diagCopyText", "diagSupportText", "diagSupportFilename"],
  },
  {
    // Report versions (#77). Its three controls were bound in the page's shared modal-wiring block,
    // not in its own — the block wires nothing, which is not the same as nothing wiring the block.
    file: "dashboard-report-versions.js",
    initializer: "initReportVersions",
    publish: ["initReportVersions", "openReportVersions", "closeReportVersions", "doReportVersionsDiff"],
    private: ["rvReviewMode", "rvReviewers", "rvReleased"],
  },
  {
    // Settings → Tools, MCP servers and the update check (#127). Three panels under one banner that
    // named only the last of them; they are one Settings screen and share nothing with the rest.
    file: "dashboard-settings-tools.js",
    initializer: "initSettingsTools",
    publish: ["initSettingsTools", "loadTools", "loadUpdateCheck"],
    private: ["_mcpDiscovered"],
  },
  {
    // Sigma draft (#89) + the hunt modal. showToast sits under the same banner and did NOT move: it
    // is a page-wide helper and js/dashboard-tickets.js calls it, so moving it would have made an
    // unrelated module depend on this feature for a toast.
    file: "dashboard-sigma-hunt.js",
    initializer: "initHuntModal",
    publish: [
      "initHuntModal",
      "exportFindingSigma",
      "sigmaExportChip",
      "openHuntModal",
      "closeHuntModal",
      "launchHuntInto",
    ],
    // The Sigma/hunt helpers: YAML quoting and value-list building, and the per-format escapers.
    // No mutable state — toastTimer was the only `let` under this banner and it stayed with
    // showToast.
    private: ["yqNorm", "yq", "sigmaVals", "yaraHashFn", "suriContent", "suriMsg"],
  },
  {
    // Push ingest token (#84). The banner it sat under also covers eleven velo* functions that
    // belong to the Velociraptor bundle builder above it — only these five moved.
    file: "dashboard-push-token.js",
    initializer: "initPushToken",
    publish: ["initPushToken", "loadPushToken"],
    // Only the binding. renderPushToken/pushTokenGenerate/pushTokenClear are function
    // declarations, which cannot become implicit globals, and this list is checked against
    // let/const/var.
    private: ["_pushTokenInfo"],
  },
  {
    // Reproducible analysis runs (#377). No state of its own — the modal reads what it needs on
    // open — so there is no `private` list to declare.
    file: "dashboard-analysis-runs.js",
    initializer: "initAnalysisRuns",
    publish: ["initAnalysisRuns", "openAnalysisRuns", "closeAnalysisRuns", "compareAnalysisRuns"],
    private: [],
  },
  {
    // Report Templates (#60). Two of its four controls were bound by passing the function as a
    // value, so the page could not simply keep calling them by name once they moved.
    file: "dashboard-report-templates.js",
    initializer: "initReportTemplates",
    publish: ["initReportTemplates", "loadReportTemplates", "rtFillEditor", "rtSave", "rtDelete"],
    private: ["rtTemplates", "rtCurrentId", "rtEditSections", "rtRequiredSections"],
  },
  {
    // Adversary Hints (#46). No initializer: measured, not assumed — nothing in the block runs at
    // load and nothing outside binds its functions while the page parses.
    file: "dashboard-adversary-hints.js",
    publish: ["loadAdversaryHints", "scheduleAdversaryHintsReload", "huntForTechnique"],
    private: ["adversaryHintsData", "adversaryHintsTimer"],
  },
  {
    // Gap Hypotheses (#96). Same shape, and GH_SEV_COLOR is why the IIFE matters: unwrapped it
    // would be a page-wide global named after one panel.
    file: "dashboard-gap-hypotheses.js",
    publish: ["doHypothesizeGaps", "resetGapHypotheses"],
    private: ["GH_SEV_COLOR", "ghArtMeta"],
  },
  {
    // Narrative Timeline. Two of the six module-scope bindings under its banner stayed in the page:
    // they wire the import undo/redo buttons to a function six hundred lines away.
    file: "dashboard-narrative.js",
    initializer: "initNarrativeTimeline",
    publish: ["initNarrativeTimeline", "genNarrative", "loadSynthMeta"],
    private: [],
  },
  {
    // Host & Account Ranking (#202). One delegated listener rather than per-row handlers, because
    // the rows are re-rendered on every refresh.
    file: "dashboard-host-ranking.js",
    initializer: "initHostRanking",
    publish: ["initHostRanking", "loadHostRanking", "scheduleHostRankingReload", "applyHostRankingScope"],
    private: ["hostRankingData", "hostRankingTimer", "hostRankingExpanded"],
  },
  {
    // NSRL known-good hashes (#63). Six of its nine bindings pass the function as a value, so the
    // page could not have kept calling them by name once they moved.
    file: "dashboard-nsrl.js",
    initializer: "initNsrl",
    publish: [
      "initNsrl",
      "loadNsrl",
      "nsrlImport",
      "nsrlImportFile",
      "nsrlClear",
      "nsrlApplyToCase",
      "nsrlDbConnect",
      "nsrlDbDisconnect",
    ],
    private: [],
  },
  {
    // Dashboard Views EDITOR (#142) — not "Dashboard view presets (#142)", a separate and larger
    // block that applies a view to the page. They share an issue number, not a boundary.
    file: "dashboard-views-editor.js",
    initializer: "initDashboardViewsEditor",
    publish: ["initDashboardViewsEditor", "loadDashboardViewsEditor", "dvFillEditor", "dvSave", "dvDelete"],
    private: ["dvViews", "dvCurrentId", "dvEditSections"],
  },
  {
    // Import undo / redo (#76). Its two toolbar buttons were bound beside the Narrative Timeline's
    // controls purely by proximity; that extraction left them behind and this one collects them.
    // doAsk sits under the same banner and is the AI Ask box — it stayed.
    file: "dashboard-import-undo.js",
    initializer: "initImportUndoRedo",
    publish: ["initImportUndoRedo", "loadUndoStack", "doImportUndoRedo"],
    private: [],
  },
  {
    // Case lifecycle (#119). Its wiring was already a self-calling wireLifecycleButtons() — the
    // same load-time trap in a shape that looks deliberate — and is 113 of the block's 149 lines.
    file: "dashboard-case-lifecycle.js",
    initializer: "initCaseLifecycle",
    publish: ["initCaseLifecycle", "loadCaseLifecycle"],
    private: [],
  },
  {
    // Threat-intel enrichment. `enrichProviders` is also an element id in the markup, which is why
    // a global named after a panel is a bad idea and the IIFE is not ceremony.
    file: "dashboard-enrichment.js",
    initializer: "initEnrichment",
    publish: ["initEnrichment", "loadEnrichToggle", "openEnrichModal", "saveEnrich"],
    private: ["enrichProviders", "enrichAvailable", "enrichOnCount"],
  },
  {
    // Unified import. No declarations and no state — the block was two statements of listener
    // wiring, so the module publishes only its initializer.
    file: "dashboard-unified-import.js",
    initializer: "initUnifiedImport",
    publish: ["initUnifiedImport"],
    private: [],
  },
  {
    // Asset overrides. Same shape: six statements of wiring, nothing else, nothing published but
    // the initializer.
    file: "dashboard-asset-overrides.js",
    initializer: "initAssetOverrides",
    publish: ["initAssetOverrides"],
    private: [],
  },
  {
    // Encrypted case archive export. Two of its three bindings pass a function as a value.
    file: "dashboard-encrypted-export.js",
    initializer: "initEncryptedExport",
    publish: ["initEncryptedExport", "openEncryptedExport", "closeEncryptedExport", "doEncryptedExport"],
    private: [],
  },
  {
    // Redacted case export (#54). Same shape as the encrypted archive beside it.
    file: "dashboard-redacted-export.js",
    initializer: "initRedactedExport",
    publish: ["initRedactedExport", "openRedactedExport", "closeRedactedExport", "doRedactedExport"],
    private: [],
  },
  {
    // Explain Event (#141). Its only caller is the timeline's delegated click handler, which calls
    // it from inside a listener rather than binding it — nothing evaluated at load, nothing to defer.
    file: "dashboard-explain-event.js",
    publish: ["openExplainPanel"],
    private: [],
  },
  {
    // Timeline Gaps (#83). Refreshed from the reload chain and the WebSocket handler, both calls
    // rather than bindings, so no initializer.
    file: "dashboard-timeline-gaps.js",
    publish: ["loadTimelineGaps", "scheduleTimelineGapsReload"],
    private: ["timelineGapsData", "timelineGapsTimer"],
  },
  {
    // Unified export menu. Wiring only — one statement seventy-four lines long.
    file: "dashboard-unified-export.js",
    initializer: "initUnifiedExport",
    publish: ["initUnifiedExport"],
    private: [],
  },
  {
    // Manual add. One shared POST helper in the body, eight statements of form wiring in the
    // initializer.
    file: "dashboard-manual-add.js",
    initializer: "initManualAdd",
    publish: ["initManualAdd"],
    private: [],
  },
  {
    // Correlation profile. CORR_PROFILE_WINDOWS is the reason for the IIFE — a per-profile time
    // window table has no business being a page-wide global.
    file: "dashboard-correlation-profile.js",
    initializer: "initCorrelationProfile",
    publish: ["initCorrelationProfile", "loadCorrProfile", "applyCorrProfile"],
    private: ["CORR_PROFILE_WINDOWS"],
  },
  {
    // Settings modal. openSettingsTab is called from three places across the page, so it publishes.
    file: "dashboard-settings-modal.js",
    initializer: "initSettingsModal",
    publish: ["initSettingsModal", "openSettingsTab", "closeSettingsModal", "openSettingsModal"],
    private: ["SETTINGS_MODE_KEY"],
  },
  {
    // Responsive toolbar. Wiring only — one statement forty lines long.
    file: "dashboard-toolbar-responsive.js",
    initializer: "initResponsiveToolbar",
    publish: ["initResponsiveToolbar"],
    private: [],
  },
  {
    // Save as Template. Both controls were bound by assigning the function as a value.
    file: "dashboard-save-template.js",
    initializer: "initSaveTemplate",
    publish: ["initSaveTemplate", "openSaveTemplate", "closeSaveTemplate", "saveAsTemplate"],
    private: [],
  },
  {
    // ZIP case archive — the unencrypted sibling of dashboard-encrypted-export.js.
    file: "dashboard-zip-archive.js",
    initializer: "initZipArchive",
    publish: ["initZipArchive", "openZipArchive", "closeZipArchive", "doZipArchive"],
    private: [],
  },
  {
    // Timeline row display toggles.
    file: "dashboard-timeline-display.js",
    initializer: "initTimelineDisplay",
    publish: ["initTimelineDisplay", "loadTlDisplay", "renderTlChecks", "applyTlDisplayFromChecks", "tlShow"],
    private: [],
  },
  {
    // Setup wizard AI step (#181). Its wiring was a self-calling IIFE — the fourth in this PR.
    // WIZ_MODEL_HINTS and LOCAL_PROVIDERS came home in #415, in a second pass — they interleaved
    // with the setup-wizard bindings and could not move in the same splice.
    file: "dashboard-wizard-ai-step.js",
    initializer: "initWizardAiStep",
    publish: ["initWizardAiStep", "wizResetAiStep"],
    private: [],
  },
  {
    // Disk-space warning (#1). Its initializer takes a declaration with it: the dismiss button was
    // captured by `const … = document.getElementById(…)` at module scope, which is null in a <head>
    // script, so the lookup and its wiring had to move together.
    file: "dashboard-disk-warning.js",
    initializer: "initDiskWarning",
    publish: ["initDiskWarning", "loadDiskStats"],
    private: ["diskWarnDismissed"],
  },
  {
    file: "dashboard-ioc-blocklist.js",
    initializer: "initIocBlocklist",
    publish: ["initIocBlocklist", "openIocBlocklist", "closeIocBlocklist", "downloadIocBlocklist"],
    private: [],
  },
  {
    // Its one control passes saveCaseTemplate as a value.
    file: "dashboard-case-template-picker.js",
    initializer: "initCaseTemplatePicker",
    publish: [
      "initCaseTemplatePicker",
      "loadCaseTemplatePicker",
      "refreshCaseTemplatePicker",
      "saveCaseTemplate",
    ],
    private: [],
  },
  {
    // Five of six bindings moved: wlApplyBtn calls wlApplyToCase, declared below the block.
    file: "dashboard-ioc-whitelist.js",
    initializer: "initWhitelist",
    publish: ["initWhitelist", "loadWhitelist", "wlAddRule", "wlImport", "wlExport", "wlApplyToCase"],
    private: [],
  },
  {
    // Search bar, time range and scope. 220 lines, nineteen statements, no declarations and nothing
    // published but the initializer — three of the nineteen were self-calling IIFEs.
    file: "dashboard-search-scope.js",
    initializer: "initSearchAndScope",
    publish: ["initSearchAndScope"],
    private: [],
  },
  {
    // Import case. The whole block is the initializer: two module-scope `const`s read the DOM, so
    // nothing here can safely sit in the module body.
    file: "dashboard-import-case.js",
    initializer: "initImportCase",
    publish: ["initImportCase"],
    private: [],
  },
  {
    // Executive summary. No initializer — the three load-time statements in its banner range were
    // all guard stanzas belonging to other features.
    file: "dashboard-exec-summary.js",
    publish: ["genExecSummary"],
    private: [],
  },
  {
    // Import minimum-severity preference. Same: both load-time statements in range were stanzas.
    file: "dashboard-import-severity.js",
    publish: ["askMinSeverity", "setImportSevPref", "syncImportSevDefaultSelect"],
    private: [],
  },
  {
    file: "dashboard-merge-picker.js",
    initializer: "initMergePicker",
    publish: ["openMergeModal", "initMergePicker"],
    private: [],
  },
  {
    file: "dashboard-preflight-banner.js",
    initializer: "initPreflightBanner",
    publish: ["initPreflightBanner"],
    private: [],
  },
  {
    // data-act dispatch. ACTIONS stays a fixed literal — it is deliberately not a window[name]
    // lookup, because the name comes from a DOM attribute.
    file: "dashboard-data-act.js",
    initializer: "initDataAct",
    publish: ["initDataAct"],
    private: [],
  },
  {
    file: "dashboard-tooltip.js",
    initializer: "initTooltip",
    publish: ["initTooltip"],
    private: [],
  },
  {
    file: "dashboard-presentation-mode.js",
    initializer: "initPresentationMode",
    publish: ["initPresentationMode"],
    private: [],
  },
  {
    // Finding assignment + workflow status (#87). Split out of a banner that also covered Pinned
    // findings; the cohesion check reported clusters of 7 and 10 and was right.
    file: "dashboard-finding-workflow.js",
    publish: ["loadFindingWorkflow", "findingWorkflowControls", "setFindingWorkflowStatus", "assignFinding"],
    private: ["workflowByFinding", "FINDING_WF_STATUS_LABELS"],
  },
  {
    // Pinned findings (#220) — the other half of that banner. Nothing here references the feature
    // above it and nothing there references this.
    // The three bindings and loadPins() came home in #415: the feature had moved out but its state
    // and writer stayed in the page, so the module was reading globals it did not own.
    file: "dashboard-pinned-findings.js",
    publish: ["renderPinned", "togglePin", "loadPins", "pinBtn"],
    private: ["pinDragActive", "_pinnedSig", "pinMsgTimer", "pinnedList", "pinnedSet", "pinLimit"],
  },
  {
    // Command palette registry (#238). Split from the section-order code sharing its banner.
    // DfirPaletteConfig is published from an initializer so the assignment happens in order.
    file: "dashboard-palette-registry.js",
    initializer: "initPaletteConfig",
    publish: ["revealSection", "buildPaletteActions", "initPaletteConfig"],
    private: ["PALETTE_BUTTONS"],
  },
  {
    // Section order and visibility (#238) — the other half of that banner.
    file: "dashboard-section-order.js",
    publish: [
      "saveSectionsOrder",
      "getEffectiveOrder",
      "applySecOrder",
      "applySectionsVis",
      "renderSecChecks",
    ],
    private: [],
  },
  {
    // Query Translator — one of THREE features that shared a banner (clusters 5, 4 and 1).
    file: "dashboard-query-translator.js",
    initializer: "initQueryTranslator",
    publish: ["initQueryTranslator", "renderNlqPlatforms", "doTranslateQuery"],
    private: ["NLQ_PLATFORM_LABELS", "NLQ_PLATFORM_ORDER"],
  },
  {
    // applyScope — the singleton cluster. Called from js/dashboard-search-scope.js, so it is its
    // own module rather than a passenger in whichever neighbour was extracted first.
    file: "dashboard-scope-apply.js",
    publish: ["applyScope"],
    private: [],
  },
  {
    // The per-case AI on/off toggle — the third feature under that banner.
    file: "dashboard-ai-toggle.js",
    publish: ["loadAiToggle", "toggleAi"],
    private: [],
  },
  {
    // Live CLIENT_EVENT monitoring (#84) — one of two features under its banner. No initializer:
    // the per-row buttons are wired by renderVeloMonitors() as the rows are built.
    // Its four static controls were bound by the bundle builder's wireVeloTriage(); they drive
    // THIS feature and moved here, which is why it has an initializer at all.
    file: "dashboard-velo-monitors.js",
    initializer: "initVeloMonitors",
    publish: [
      "initVeloMonitors",
      "loadVeloMonitors",
      "veloMonBrowse",
      "veloMonSyncAllClients",
      "veloMonStart",
      "veloMonAuto",
    ],
    private: [],
  },
  {
    // Velociraptor triage bundles — the other half. Its wiring was a self-calling IIFE.
    // veloArtifactCache, veloEditingId and veloSelected moved here from the inline block. The
    // first two were declared there and used only here; veloSelected had thirteen uses here and
    // two assignments, against one reset in the page — ownership follows use.
    file: "dashboard-velo-bundles.js",
    initializer: "initVeloBundles",
    publish: [
      "initVeloBundles",
      "resetVeloSelected",
      "renderVeloSelected",
      "veloClearBuilder",
      "veloEdit",
      "veloDuplicate",
      "veloDeleteBundle",
      "veloResetBuiltin",
    ],
    private: [],
  },
  {
    // Import progress bar helpers. Split from the AI status banner that shared its heading.
    file: "dashboard-import-progress.js",
    publish: [
      "showImportProgress",
      "showImportProgressIndeterminate",
      "hideImportProgress",
      "cancelImportProgress",
      "importPermissionMessage",
      "readFileTextWithProgress",
    ],
    private: ["_ipb"],
  },
  {
    // The AI status banner — the singleton cluster under that heading.
    file: "dashboard-ai-status.js",
    publish: ["applyAiStatus", "clearTransientStatus"],
    private: [],
  },
  {
    // Custom importers. wlApplyToCase sat here by position and went home to the whitelist module.
    file: "dashboard-custom-importers.js",
    initializer: "initCustomImporters",
    publish: [
      "initCustomImporters",
      "loadImporters",
      "impAdd",
      "impReload",
      "impSetPrecedence",
      "impCopyPrompt",
    ],
    private: [],
  },
  {
    // Dashboard view PRESETS (#142) — applying a saved layout. Not the views EDITOR of the same
    // issue number, which is a separate module.
    file: "dashboard-view-presets.js",
    initializer: "initViewPresets",
    publish: [
      "initViewPresets",
      "viewFilters",
      "viewMeetsMinSev",
      "viewTopN",
      "applyDashboardView",
      "applySavedViewForCase",
      "loadDashboardViews",
    ],
    private: ["RT_FRIENDLY"],
  },
  {
    // The .env settings form. loadedEnvValues is why the IIFE matters: it is the snapshot that
    // decides which integration groups get rebuilt on save (#178).
    file: "dashboard-env-settings.js",
    initializer: "initEnvSettings",
    publish: ["initEnvSettings", "fetchEnvSettings", "saveSettings"],
    private: ["loadedEnvValues", "RELOADABLE_ENV_PREFIXES"],
  },
  {
    // Memory Next Steps (#101). No initializer — the only load-time statement in its range was a
    // guard stanza an earlier extraction left there.
    file: "dashboard-memory-next-steps.js",
    publish: ["toggleMemNextSteps", "resetMemNextSteps", "doMemNextSteps"],
    private: ["MNS_SEV_COLOR", "MNS_SEV_RANK"],
  },
  {
    // Delete case. Its archive-choice radios AND its three modal controls move — the latter were
    // in the page's shared modal-wiring block, which every other modal extraction has also taken
    // its own lines out of.
    file: "dashboard-delete-case.js",
    initializer: "initDeleteCase",
    publish: ["initDeleteCase", "openDeleteCase", "closeDeleteCase", "doDeleteCase"],
    private: [],
  },
  {
    // Case password protection. Nothing outside calls in, so it publishes only its initializer.
    file: "dashboard-case-password.js",
    initializer: "initCasePassword",
    publish: ["initCasePassword"],
    private: [],
  },
  {
    // Comprehensive setup wizard (#181). Everything load-time is in the initializer, including two
    // `const`s that read the DOM and would be null in a <head> script.
    // Its state came home in #415: the module existed but WIZ_DISMISS_KEY, F, WIZARD_STEPS,
    // WIZ_ORDER, WIZARD_BY_ID, wizCurrent and wizStatus had stayed in the page.
    file: "dashboard-setup-wizard.js",
    initializer: "initSetupWizard",
    publish: ["initSetupWizard", "openSetupWizard", "closeSetupWizard", "wizRefreshStatus", "fetchLogLevel"],
    private: [],
  },
  {
    // Multi-select and its bulk actions. The selection itself lives in DfirSelection (tier 2); this
    // is the UI over it. No initializer: the bars re-render on every selection change.
    file: "dashboard-bulk-select.js",
    publish: [
      "updateBulkBar",
      "clearSelection",
      "updateIocBulkBar",
      "clearIocSelection",
      "bulkStarIds",
      "bulkToggleStar",
      "openBulkTagModal",
      "bulkMarkFalsePositive",
    ],
    private: [],
  },
  {
    // Bulk IOC operations — the sibling of the module above. They share DfirSelection, nothing else.
    file: "dashboard-bulk-ioc.js",
    publish: ["bulkEnrichIocs", "bulkTagIocs", "bulkMarkIocsFalsePositive"],
    private: [],
  },
  {
    // Case unlock prompt. What followed its controls in the inline block is the page's own startup
    // sequence — loadCaseList(), restore() and two guard stanzas — and none of it came along.
    file: "dashboard-case-unlock.js",
    initializer: "initCaseUnlock",
    publish: ["initCaseUnlock", "promptCaseUnlock"],
    private: [],
  },
  {
    // New case creation. Its banner is 692 lines and 595 of them are the page's shared wiring run
    // with nineteen guard stanzas threaded through it — only this feature's own eight lines moved.
    file: "dashboard-new-case.js",
    initializer: "initNewCase",
    publish: ["initNewCase", "openNewCase", "closeNewCase", "createNewCase", "loadDemoCase"],
    private: [],
  },
  {
    // Case templates and incident types. Its `_cachedTemplates` was written from
    // js/dashboard-save-template.js across the shared global lexical environment; the escape is
    // CLOSED by publishing invalidateTemplateCache() rather than the binding.
    file: "dashboard-case-templates.js",
    publish: [
      "loadTemplates",
      "loadIncidentTypes",
      "populateTemplateSelect",
      "selectedNewCasePlaybook",
      "onTemplateSelectChange",
      "invalidateTemplateCache",
    ],
    // CP_LABELS moved here from the inline block: declared under a keyboard-navigation banner
    // it had nothing to do with, and read only here.
    private: ["_cachedTemplates", "_cachedIncidentTypes", "CP_LABELS"],
  },
  {
    // Velociraptor triage. Seven bindings crossed the boundary: three were simply declared in the
    // wrong file and moved to the module that used them, four are genuinely shared and are handed
    // out through accessors while the writes stay here.
    file: "dashboard-velo-triage.js",
    publish: [
      "loadVeloTriage",
      "loadVeloBundles",
      "loadVeloClients",
      "loadVeloHuntJobs",
      "veloCaseId",
      "applyVeloEnabled",
      "doRefreshVeloClients",
      "doVeloReconnect",
      "veloImportExternal",
      "veloBundlesList",
      "veloClientsList",
      "veloMonAutoBrowsed",
      "setVeloMonAutoBrowsed",
    ],
    private: ["_veloBundles", "_veloClients", "_veloMonAutoBrowsed"],
  },
  {
    // Background jobs (#225) — the last banner holding feature code. Its one escape, _jobsCache, is
    // read by dashboard-deep-pass.js, which asks runningJob(kind) rather than taking the array:
    // nothing outside should be able to mutate the cache the badge renders from.
    file: "dashboard-jobs.js",
    initializer: "initJobs",
    publish: [
      "initJobs",
      "runningJob",
      "applyHeavyAiJobLock",
      "cancelJob",
      "loadJobs",
      "pollCount",
      "scheduleJobUiRefresh",
    ],
    // countTimer is NOT here: it lives in the page's state block with the other shared bindings.
    private: ["_jobsCache", "_jobsMenuShape"],
  },
  {
    // Analyst triage tags. Two escapes crossing in opposite directions: bulk-select WROTE tagTarget
    // (so it gets an operation), and two modules READ tagsByTarget in two different ways (so they
    // get the two questions they ask, not the Map).
    file: "dashboard-tags.js",
    initializer: "initTagModal",
    publish: [
      "initTagModal",
      "addTag",
      "closeTagModal",
      "loadTags",
      "openTagModal",
      "renderTagModal",
      "tagAddBtn",
      "tagChip",
      "tagPills",
      "setBulkTagTarget",
      "eachTagList",
      "tagsForTarget",
    ],
    private: ["tagTarget", "tagsByTarget"],
  },
  {
    // Theme (#53). Its three escapes were read by renderThemeMenu and the menu handlers, which sat
    // on the wrong side of the "Theme picker" banner — that banner is the page's state hub, not a
    // theme feature. Moving the boundary past the menu left this with no escapes.
    file: "dashboard-theme.js",
    initializer: "initTheme",
    publish: ["initTheme", "applyTheme", "storedTheme", "systemTheme", "themeColor"],
    private: ["DFIR_THEMES", "THEME_GROUP_LABELS", "THEME_GROUP_ORDER"],
  },
  {
    // Setup-wizard step definitions — pure data, split out when moving the wizard's state home put
    // dashboard-setup-wizard.js over the 800-line budget. Accessors, because published names must
    // be callable.
    file: "dashboard-wizard-steps.js",
    publish: ["wizardOrder", "wizardStepById"],
    private: ["WIZARD_STEPS", "WIZ_ORDER", "WIZARD_BY_ID", "F"],
  },
  {
    // Asset↔IoC graph, split out of the Login Graph banner. Its expand handler came along; the
    // .asset-type-toggle handlers beside it did not — those mutate the Compromised-assets
    // section's state and only call in here afterwards.
    file: "dashboard-asset-graph.js",
    initializer: "initAssetGraph",
    publish: ["initAssetGraph", "assetEnsureGV", "renderAssetGraph", "renderAssetList"],
    private: ["assetGV", "ASSET_STYLE"],
  },
  {
    // Login Graph. The banner it shared with the asset↔IoC graph was split first — that graph's
    // helpers are used by the "Compromised assets" section next door. lgEl is published for the
    // same reason: a shared DOM helper, not state.
    file: "dashboard-login-graph.js",
    initializer: "initLoginGraph",
    publish: ["initLoginGraph", "loadLoginGraph", "scheduleLoginGraphReload", "renderLoginGraph", "lgEl"],
    private: ["lgData", "lgTimer", "lgGV", "LG_STYLE"],
  },
  {
    // Notifications (#58). No initializer. Zero state escapes — it sat off the queue only because
    // the queue was filtered on sharedMachinery, which is an argument about what to publish rather
    // than a blocker. loadCaseList, the one entry, is page machinery below this block and stays.
    file: "dashboard-notifications.js",
    initializer: "initNotifications",
    publish: [
      "initNotifications",
      "loadNotifications",
      "ntfAddChannel",
      "ntfTest",
      "ntfToggle",
      "ntfTypeChanged",
    ],
    private: ["ntfChannels", "NTF_TYPE_LABEL", "NTF_WEBHOOK_PLACEHOLDER"],
  },
  {
    // Starred events. No initializer. Reported five escapes until the IOC view state that shared
    // its banner — and belongs to renderIocs, not to starring — moved out to the page's shared state.
    file: "dashboard-starred.js",
    publish: ["deriveStarred", "isSystemPathIoc", "migrateLocalStars", "toggleStar"],
    private: ["starredKey", "SYSTEM_PATH_RE"],
  },
  {
    // Event-density heatmap. No initializer. Reported 470 lines and zero escapes until the banner
    // it shared with renderTimelineEvents was split — a spine reports no escapes because it
    // declares everything it touches, which is the opposite of what the number usually means.
    file: "dashboard-heatmap.js",
    publish: ["renderTimelineHeatmap", "zoomToTimeWindow"],
    private: ["HM_SEV_ORDER", "HM_MAX_BUCKETS"],
  },
  {
    // Mark-false-positive modal. Two ranges: the feature, and the six controls of its own that sat
    // 3,300 lines away in the page's wiring block, which is where its one escape was read.
    file: "dashboard-false-positive.js",
    initializer: "initFalsePositiveModal",
    publish: [
      "initFalsePositiveModal",
      "openFalsePositiveModal",
      "closeFalsePositiveModal",
      "renderFpCandidates",
    ],
    private: ["fpTarget"],
  },
  {
    // Bulk finding operations + hunt-query builders. No initializer: nothing here runs at load.
    // Reported eight escapes for most of #415 and had none — five were const arrow helpers the
    // inventory miscounted, three belonged to other owners.
    file: "dashboard-bulk-findings.js",
    publish: [
      "baseName",
      "bulkCopyIocs",
      "bulkExcludeIocs",
      "bulkMarkFindingsFalsePositive",
      "bulkTagFindings",
      "cleanWinPath",
      "clearFindingSelection",
      "explainChip",
      "hasAny",
      "hq",
      "huntChip",
      "huntContextFor",
      "huntKql",
      "huntSigma",
      "huntSpl",
      "huntVql",
      "huntVqlNotebook",
      "pushUniq",
      "showToast",
      "updateFindingBulkBar",
    ],
    private: [],
  },
  {
    // Analyst notebook. Its one escape was a cross-module read from dashboard-hypotheses.js, which
    // reached into notebookEntries to build the notebook→hypothesis bridge from the far side.
    file: "dashboard-notebook.js",
    initializer: "initNotebook",
    publish: ["initNotebook", "loadNotebook", "loadNbAiToggle", "nbDelete", "nbStartEdit", "notebookEntry"],
    private: ["notebookEntries"],
  },
  {
    // Collapsible + reorderable sections. Reported blocked on a `sections` escape for most of #415
    // and never was: it is a const-declared arrow function, and the inventory keyed on the keyword.
    file: "dashboard-collapsible.js",
    initializer: "initCollapsible",
    publish: ["initCollapsible", "setupCollapsible", "setupReorder"],
    private: ["COLLAPSE_KEY"],
  },
  {
    // IOC provenance, corroboration and risk. No initializer: its controls stayed where they are
    // (the page's delegated click block, and the risk <select> in dashboard-search-scope.js) and
    // hand their values over — the plumbing is theirs, the state is this feature's.
    file: "dashboard-ioc-provenance.js",
    initializer: "initIocProvenance",
    publish: [
      "initIocProvenance",
      "iocCorroborationCount",
      "applyIocProvenanceFilters",
      "iocProvenanceFiltersActive",
      "iocChainFor",
      "setIocProvenanceFilter",
      "setRiskIocsFilter",
      "riskIocsFilterValue",
      "loadIocSources",
      "scheduleIocSourcesReload",
      "loadIocProvenance",
      "scheduleIocProvenanceReload",
      "loadIocProvenanceChains",
      "scheduleIocProvenanceChainReload",
      "loadIocRisk",
      "scheduleIocRiskReload",
      "iocProvenanceOf",
      "iocProvenanceBadge",
      "iocRiskRankOf",
      "iocRiskBadge",
      "iocCorroBadge",
      "iocChainChip",
      "openIocChainPanel",
      "findingEvidenceDetails",
      "citeEvents",
    ],
    private: [
      "iocSourcesById",
      "iocProvenanceFilter",
      "riskIocsFilter",
      "iocProvenanceChains",
      "iocProvenance",
      "iocRisk",
    ],
  },
  {
    // Attack Phases. Reunited with its own renderPhases first — 230 lines of IOC provenance code
    // shared its banner and had split the feature in two. That split banner took the block from
    // five state escapes to one, and the one crosses as hasPhases().
    file: "dashboard-attack-phases.js",
    initializer: "initAttackPhases",
    publish: ["initAttackPhases", "loadPhases", "schedulePhasesReload", "renderPhases", "hasPhases"],
    private: ["phasesData", "phOpen", "phasesTimer"],
  },
  {
    // Second LLM opinion (#116). Two sources: the section, and the button + panel handler that
    // dashboard-search-scope.js had been carrying since an earlier extraction swept them in. The
    // capability flags cross as a setter (the /health poller writes them) and a predicate.
    file: "dashboard-second-opinion.js",
    initializer: "initSecondOpinion",
    publish: [
      "initSecondOpinion",
      "setSecondOpinionCapabilities",
      "isFpAiConfigured",
      "loadSecondOpinion",
      "renderSecondOpinion",
      "runSecondOpinion",
      "applySecondOpinionDelta",
      "applyAllSecondOpinion",
    ],
    private: [
      "soCollapsed",
      "SO_COLLAPSE_KEY",
      "lastSecondOpinionRec",
      "secondOpinionEnabled",
      "fpAiConfigured",
    ],
  },
  {
    // Screenshot OCR full-text search. All-initializer: it was a self-calling IIFE, so it only ever
    // ran at load. Publishes nothing else — nothing outside it calls in.
    file: "dashboard-ocr-search.js",
    initializer: "initOcrSearch",
    publish: ["initOcrSearch"],
    private: [],
  },
  {
    // Evidence Chain graph. Two ranges: the feature, and the six load-time statements that were its
    // own controls sitting 4,000 lines away in the page's wiring block. The boundary is exact — the
    // next statement belongs to report metadata.
    file: "dashboard-evidence-graph.js",
    initializer: "initEvidenceGraph",
    publish: ["initEvidenceGraph", "loadEvidenceGraph", "scheduleEvidenceGraphReload", "hasEvidenceGraph"],
    private: [
      "evGraphData",
      "evTypesEnabled",
      "evMinSev",
      "evColorMode",
      "evGV",
      "evPathsData",
      "evPathsShowDismissed",
    ],
  },
  {
    // Last-import change tracking. All three escapes were READS from the page's two renderers, so
    // what crosses the boundary is a question — isNewEvent / isNewIoc — not the key sets. No
    // initializer: nothing here runs at load, and loadImportMeta() is already in the refresh fan-out.
    file: "dashboard-import-changes.js",
    publish: [
      "loadImportMeta",
      "loadDropStatus",
      "fetchRawToolExts",
      "askRunToolsOnImport",
      "propagateFalsePositive",
      "paintIocImportMeta",
      "doAsk",
      "isNewEvent",
      "isNewIoc",
    ],
    private: ["newEventKeys", "newIocKeys", "evKey", "evNorm"],
  },
  {
    // Presidio approval panel. Its escape was written from three places outside the section, each
    // open-coding the same assign-then-render pair. setPresidioPending() is that pair, owned here,
    // so a caller can no longer update the findings and forget the badge.
    // The anonymization block's six bindings and four loaders came home in #415: they were read
    // only here while the page held the declarations.
    file: "dashboard-presidio.js",
    initializer: "initPresidio",
    publish: [
      "initPresidio",
      "loadPresidioPending",
      "renderPresidioPending",
      "setPresidioPending",
      "addCustomEntity",
      "openAnonModal",
      "saveAnon",
      "setAi",
      "loadAnonEntities",
      "loadAnonToggle",
      "renderAnonToggle",
      "renderAutoEntities",
    ],
    private: [
      "presidioPending",
      "ANON_CATEGORIES",
      "ANON_ENTITY_CATEGORIES",
      "anonAuto",
      "anonControl",
      "anonCustom",
      "anonSuppressed",
    ],
  },
  {
    // Hypotheses (#140). Its one escape was a WRITE from dashboard-data-act.js, which assigned
    // pendingHuntHypothesis = null directly. The owner exports clearPendingHuntHypothesis() and the
    // caller asks for it, so the binding can stay private here.
    file: "dashboard-hypotheses.js",
    initializer: "initHypotheses",
    publish: [
      "initHypotheses",
      "loadHypotheses",
      "hypPatch",
      "linkNextHuntToHypothesis",
      "consumePendingHuntHypothesis",
      "clearPendingHuntHypothesis",
      "hypDelete",
      "hypApplyReview",
      "promoteToHypothesis",
    ],
    private: ["pendingHuntHypothesis"],
  },
  {
    // Inline IOC quick-actions. The audit mark is published, not private: it is the protocol between
    // this module (which writes it at the head of every audit comment) and render() in the page
    // (which reads it to pull those comments into the Investigation Log). It is published as an
    // accessor because the published surface is callables — and because a reader that must survive
    // this module being absent can then guard on `typeof`.
    file: "dashboard-ioc-quick-actions.js",
    initializer: "initIocQuickActions",
    publish: ["initIocQuickActions", "qaAudit", "qaLinkify", "qaResolveIocId", "qaAuditMark"],
    private: ["qaCur", "qaTrayEl", "qaCaseId", "QA_MATCHERS", "QA_FILE_EXT", "QA_AUDIT_MARK"],
  },
  {
    // Vim-style keyboard navigation. Four of the fifteen load-time statements under its banner were
    // its own — including #miValue's Escape handler, which reads as part of the manual-IOC form
    // until you notice it clears the one-shot recording whether the keyboard opened that form.
    file: "dashboard-keyboard-nav.js",
    initializer: "initKeyboardNav",
    publish: ["initKeyboardNav", "kbdShortcutsEnabled", "setKbdShortcutsEnabled", "kbdOpenHelp"],
    private: ["KBD_SHORTCUTS_KEY", "focusedEventId", "_kbdIocFormAutoOpened"],
  },
  {
    // CP_MARK moved here from the inline block: declared under a keyboard-navigation banner and
    // read only here.
    file: "dashboard-collection-plan.js",
    publish: ["fetchCollectionResults", "renderCollectionPlan"],
    private: ["CP_MARK"],
  },
  {
    // The canvas chart. Like dashboard-tickets.js, all of its load-time work is DOM wiring —
    // eleven listeners on the canvas and toolbar plus a ResizeObserver — so it is wrapped in
    // initSwimlane() and the page calls it where the old IIFE sat. Unlike tickets the initializer
    // publishes nothing, so there is no postInitPublish list: all six names appear at load.
    //
    // swLocateInTable is NOT here on purpose. Its name says swimlane, its body scrolls a row in
    // #forensicTimeline, and both callers are inside jumpToEvent, which stayed in the page.
    file: "dashboard-swimlane.js",
    publish: [
      "loadSwimlane",
      "scheduleSwimlaneReload",
      "swRenderCanvas",
      "swSelToolbar",
      "swReflectSelection",
      "initSwimlane",
    ],
    private: [
      "SW_LANE_H",
      "SW_AXIS_H",
      "SW_DOT_R",
      "SW_SEV_TOKEN",
      "SW_LABEL_TOKEN",
      "SW_AXIS_LABEL",
      "swLanes",
      "swDataMinMs",
      "swDataMaxMs",
      "swViewStartMs",
      "swViewEndMs",
      "swDrag",
      "swDragMoved",
      "swDragStartX",
      "swDragViewStart",
      "swHoverEvId",
      "swSelEvId",
      "swTimer",
      "swRubber",
      "swTimeBrush",
    ],
    // The thirteen private FUNCTIONS (swFitView, swUpdateSubtitle, swZoomRatio, swTsToX, swXToTs,
    // swRenderLabels, swHitTest, swShowDetail, swUpdateZoomLabel, swSelectionChanged,
    // swFinishRubber, swScopeToView, swExportPng) are deliberately not on that list: it exists to
    // catch a binding that is assigned but never declared, and a function declaration cannot
    // become an implicit global. That they stay off `window` is already asserted by the
    // exact-globals check.
    initializer: "initSwimlane",
  },
];

/**
 * The names a loaded module put on the global object, ignoring the sandbox's own furniture.
 *
 * The vm context is seeded with `window`/`globalThis`, the host globals the loader borrows live
 * (Date, btoa, atob, console — see dashboardModule.ts) and whatever `extraGlobals` the caller
 * supplied. None of those are the module's doing.
 */
const SANDBOX_FURNITURE = new Set(["window", "globalThis", "Date", "btoa", "atob", "console"]);
const globalsOf = (api: Record<string, unknown>, seeded: string[] = []): string[] =>
  globalNamesOf(api).filter((k) => !SANDBOX_FURNITURE.has(k) && !seeded.includes(k));

export { SANDBOX_FURNITURE, globalsOf };

export const read = (f: string) => readFile(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
export const scripts = dashboardScripts();

/**
 * THE CENSUS SEAM: names the module binds that the inline script binds too.
 *
 * A named function rather than two lines inlined into the assertion, because the two lines are the
 * thing that has now been wrong twice and neither wrongness was reachable from a test. Its own
 * contract lives in the `describe` at the bottom of this file — synthetic module and inline sources
 * carrying the exact mutations that got through, so the seam is exercised and not just its helper.
 */
/**
 * Names a module declares that are ALSO still declared at the top level of the inline script.
 *
 * The question is "did the feature move as a unit, or is a copy of one of its declarations still
 * sitting in the page" — and the page's answer is only meaningful at its TOP level. That is what a
 * later script can see, what can shadow or be shadowed, and what "left behind" can mean.
 *
 * IT USED TO COMPARE BOTH SIDES AT ANY DEPTH, and that produced three false positives in one
 * session, each costing a rename that the code did not want: `tick` → `mcpTick`, `wire` →
 * `wireToolRules`, `poll` → `pollHuntResults`. The fourth would have been renaming `const v = (elId,
 * val) => …`, a two-character local, because three unrelated functions elsewhere in the page happen
 * to name a local `v` too. A nested local in the page is invisible to the module and cannot be a
 * leftover of anything; flagging it taught the reader to rename around the gate rather than to look.
 *
 * The module side stays at any depth on purpose: the module is the thing under test, and a
 * declaration anywhere in it that matches a page global is worth knowing about.
 */
const duplicateBindings = (
  moduleName: string,
  moduleSrc: string,
  inlineScripts: DashboardScript[],
): string[] => {
  const declared = functionBindingsOf(scriptFromSource(moduleName, moduleSrc)).map((b) => b.name);
  return inlineScripts.flatMap((s) => {
    const pageTopLevel = new Set(topLevelBindings(s).map((b) => b.name));
    return functionBindingsOf(s)
      .filter((b) => declared.includes(b.name) && pageTopLevel.has(b.name))
      .map((b) => `${s.name}:${b.line} ${b.name}`);
  });
};

export { duplicateBindings };

/**
 * The dashboard-*.js modules the page loads that are NOT tier-3 features.
 *
 * Exists so that "every module the page loads is classified" can be a real check. FEATURES alone
 * cannot be the source of truth for what shipped: review deleted a row, added a genuine defect to
 * that module, and the suite went green — the feature was simply not examined by anything. Listing
 * the non-features explicitly means a new dashboard-*.js tag fails until someone decides which it
 * is, rather than being skipped in silence.
 *
 * Nine pure helpers (#415 tier 1), four state owners (tier 2), the tagger and KEV panels — which
 * are tier 3 but hold no state, so they have no private-binding contract to assert — and the no-op
 * facade, which is tier 1 infrastructure.
 */
export const NON_FEATURES = new Set([
  "dashboard-state.js",
  "dashboard-escape.js",
  "dashboard-time.js",
  "dashboard-text.js",
  "dashboard-glyphs.js",
  "dashboard-filters.js",
  "dashboard-ioc.js",
  "dashboard-values.js",
  "dashboard-fragments.js",
  "dashboard-scope.js",
  "dashboard-selection.js",
  "dashboard-facets.js",
  "dashboard-timeline-view.js",
  "dashboard-tagger.js",
  "dashboard-kev.js",
  "dashboard-facade.js",
]);
