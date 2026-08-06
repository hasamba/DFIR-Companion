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
    publish: ["loadSessions", "scheduleSessionsReload", "summarizeSession"],
    private: ["sessionsData", "sessionsTimer", "sessionSummaries"],
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
    file: "dashboard-deep-pass.js",
    publish: [
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
    file: "dashboard-collection-plan.js",
    publish: ["fetchCollectionResults", "renderCollectionPlan"],
    private: [],
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
