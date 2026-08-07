// A feature module that never loaded becomes a NO-OP, not a ReferenceError (#415 tier 3).
//
// WHAT THIS IS FOR. Every tier-3 feature ships as its own /js/ file and publishes its names by
// assignment (see js/dashboard-swimlane.js). dashboard.html calls a lot of those names BARE, and
// the dangerous ones sit in the middle of a single load-time statement:
//
//   scheduleAnomaliesReload(); scheduleSessionsReload(); … scheduleSwimlaneReload(); scheduleIocSourcesReload(); …
//
// on case restore and again in the WebSocket "state" handler. One 404 turned the first of those
// into a ReferenceError that took every LATER refresh in the same statement with it — the IOC
// panels, the super-timeline, the lot — while the server had already accepted the change. The page
// then reported a failure that had not happened and skipped work that had.
//
// Guarding nineteen call sites would work and would rot: the twentieth gets added without one. A
// stub is declared once, covers every present and future call site, and cannot be forgotten.
//
// WHY THIS FILE LOADS LAST. It can only tell a missing module from a present one after the feature
// scripts have run, so its tag sits below theirs in the head and above the inline script. If THIS
// file 404s the page is in the same shape it was before the stubs existed; it is a tier-1 helper
// like js/dashboard-state.js, not a feature, and the page does not pretend to survive without those.
//
// WHAT IS DELIBERATELY NOT HERE. No INITIALIZER name — not initSwimlane, initTicketIntegrations,
// initCustodyButtons, verifyCustodyOnOpen, renderCollectionPlan, loadCaseBackups, or the three kev*
// entry points. Those are the sentinels the guards in dashboard.html test to decide whether to put
// a chip on screen, and stubbing one would make its feature look present and silence the warning
// that says it is gone. A stub here must only ever replace work, never evidence.
//
// Nor DfirTimelineView: that is a tier-2 owner whose absence stops the page on purpose, because a
// dashboard whose timeline, IOCs and findings are all empty is indistinguishable from a case with
// no evidence in it.
(function () {
  // Every name below is one dashboard.html calls bare on a path that runs at LOAD, harvested with
  // the call-graph reachability the feature-module suite asserts against — not by hand.
  var STUBBED = [
    "fetchCollectionResults",
    "loadAnomalies",
    "loadCompliance",
    "loadCustody",
    "loadD3fend",
    "loadGeoMap",
    "loadSessions",
    "toggleSessionsCollapse",
    "loadSwimlane",
    "renderGeoMarkers",
    "renderGeoView",
    "scheduleAnomaliesReload",
    "scheduleComplianceReload",
    "scheduleD3fendReload",
    "scheduleGeoMapReload",
    "scheduleSessionsReload",
    "scheduleSwimlaneReload",
    "swReflectSelection",
    "swRenderCanvas",
    "swSelToolbar",
    // #415 tier 3, added with their modules. Every extraction has to land here too: these names are
    // called bare from the load-time refresh chains, and the gate in dashboardFeatureLifecycle.test.ts
    // ("every module name the page calls bare is stubbed or guarded") is what makes that not a thing
    // you have to remember.
    "loadBeacons",
    "scheduleBeaconsReload",
    "loadEvidenceGaps",
    "scheduleEvidenceGapsReload",
    "loadPlaybookMatch",
    "schedulePlaybookMatchReload",
    "loadAttackMitigations",
    "scheduleAttackMitigationsReload",
    "generateRemediation",
    "loadHuntProfile",
    "loadMcpRun",
    "resetDeepPass",
    "applyDeepPassGate",
    "loadDeepPassPreview",
    "deepPassGuidance",
    "deepPassBusy",
    "deepPassJob",
    "setDeepPassSynthesisEnabled",
    "loadSuperTimeline",
    "loadSavedTimeframes",
    "loadSavedStarredReport",
    "resetSuperPagination",
    "setSuperLabelFilter",
    "refreshSuperRows",
    "renderSuperTimeline",
    "superPage",
    // Playbook (#230). `initPlaybook` is deliberately absent: it is the module's own sentinel, and a
    // stub for it would swallow the "Playbook unavailable" chip the page shows when the file is gone.
    "loadPlaybook",
    "pbPatch",
    "pbDelete",
    "pbMove",
    "pbToggleDep",
    "pbToggleDeps",
    "pbJumpFinding",
    "doSuggestPlaybookHunts",
    "resetPlaybookHuntSuggest",
    // Health / Diagnostics (#118). `initDiagnostics` is absent on purpose — it is this module's
    // sentinel, and stubbing it would swallow the "Health / Diagnostics" chip. The rest are work
    // functions the Settings tab-switch calls.
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
    // Report versions (#77). `initReportVersions` is absent on purpose — the sentinel again.
    "openReportVersions",
    "closeReportVersions",
    "doReportVersionsDiff",
    // Settings → Tools + update check (#127). `initSettingsTools` is the sentinel, so not here.
    "loadTools",
    "loadUpdateCheck",
    // Sigma draft + hunt modal (#89). `initHuntModal` is the sentinel, so not here.
    "exportFindingSigma",
    "sigmaExportChip",
    "openHuntModal",
    "closeHuntModal",
    "launchHuntInto",
    // Push ingest token (#84). `initPushToken` is the sentinel, so not here.
    "loadPushToken",
    // Reproducible analysis runs (#377). `initAnalysisRuns` is the sentinel, so not here.
    "openAnalysisRuns",
    "closeAnalysisRuns",
    "compareAnalysisRuns",
    // Report Templates (#60). `initReportTemplates` is the sentinel, so not here.
    "loadReportTemplates",
    "rtFillEditor",
    "rtSave",
    "rtDelete",
    // Adversary Hints (#46) and Gap Hypotheses (#96). Neither has an initializer, so every name
    // they publish is a work function and belongs here — the facade's `filled` list is the only
    // way either can report that its file is missing.
    "loadAdversaryHints",
    "scheduleAdversaryHintsReload",
    "huntForTechnique",
    "doHypothesizeGaps",
    "resetGapHypotheses",
    // Narrative Timeline. `initNarrativeTimeline` is the sentinel, so not here.
    "genNarrative",
    "loadSynthMeta",
    // Host & Account Ranking (#202). `initHostRanking` is the sentinel, so not here.
    "loadHostRanking",
    "scheduleHostRankingReload",
    "applyHostRankingScope",
    // NSRL (#63) and the Dashboard Views editor (#142). Their initializers are the sentinels.
    "loadNsrl",
    "nsrlImport",
    "nsrlImportFile",
    "nsrlClear",
    "nsrlApplyToCase",
    "nsrlDbConnect",
    "nsrlDbDisconnect",
    "loadDashboardViewsEditor",
    "dvFillEditor",
    "dvSave",
    "dvDelete",
    // Import undo / redo (#76). `initImportUndoRedo` is the sentinel, so not here.
    "loadUndoStack",
    "doImportUndoRedo",
    // Case lifecycle (#119). `initCaseLifecycle` is the sentinel, so not here.
    "loadCaseLifecycle",
    // Threat-intel enrichment. `initEnrichment` is the sentinel, so not here.
    "loadEnrichToggle",
    "openEnrichModal",
    "saveEnrich",
    // The two case-export modals. Their initializers are the sentinels, so not here.
    "openEncryptedExport",
    "closeEncryptedExport",
    "doEncryptedExport",
    "openRedactedExport",
    "closeRedactedExport",
    "doRedactedExport",
    // Explain Event (#141) and Timeline Gaps (#83). Neither has an initializer, so every name they
    // publish is a work function and the facade's `filled` list is their only way to report.
    "openExplainPanel",
    "loadTimelineGaps",
    "scheduleTimelineGapsReload",
    // Correlation profile and the settings modal. Their initializers are the sentinels, so not here.
    "loadCorrProfile",
    "applyCorrProfile",
    "openSettingsTab",
    "closeSettingsModal",
    "openSettingsModal",
    // Save as Template, the ZIP archive and the timeline row toggles. Initializers are sentinels.
    "openSaveTemplate",
    "closeSaveTemplate",
    "saveAsTemplate",
    "openZipArchive",
    "closeZipArchive",
    "doZipArchive",
    "loadTlDisplay",
    "renderTlChecks",
    "applyTlDisplayFromChecks",
    "tlShow",
    // The wizard AI step and the disk-space warning. Their initializers are the sentinels.
    "wizResetAiStep",
    "loadDiskStats",
    // The block-list export, the template picker and the whitelist. Initializers are sentinels.
    "openIocBlocklist",
    "closeIocBlocklist",
    "downloadIocBlocklist",
    "loadCaseTemplatePicker",
    "refreshCaseTemplatePicker",
    "saveCaseTemplate",
    "loadWhitelist",
    "wlAddRule",
    "wlImport",
    "wlExport",
    // The executive summary, the import severity floor and the merge picker. The last two features
    // here have no initializer at all, so every name they publish is a work function.
    "genExecSummary",
    "askMinSeverity",
    "setImportSevPref",
    "syncImportSevDefaultSelect",
    "openMergeModal",
    // Finding workflow and pinned findings — neither has an initializer, so every published name
    // is a work function and the facade's `filled` list is how each reports a missing file.
    "loadFindingWorkflow",
    "findingWorkflowControls",
    "setFindingWorkflowStatus",
    "assignFinding",
    "renderPinned",
    "togglePin",
    // The palette registry and the section order/visibility code. initPaletteConfig is a sentinel.
    "revealSection",
    "buildPaletteActions",
    "saveSectionsOrder",
    "getEffectiveOrder",
    "applySecOrder",
    "applySectionsVis",
    "renderSecChecks",
    // The query translator, the scope-apply function and the AI toggle. None has an initializer.
    "renderNlqPlatforms",
    "doTranslateQuery",
    "applyScope",
    "loadAiToggle",
    "toggleAi",
    // The CLIENT_EVENT monitors and the triage-bundle builder. initVeloBundles is a sentinel.
    "loadVeloMonitors",
    "veloMonBrowse",
    "veloMonSyncAllClients",
    "veloMonStart",
    "veloMonAuto",
    "renderVeloSelected",
    "veloClearBuilder",
    "veloEdit",
    "veloDuplicate",
    "veloDeleteBundle",
    "veloResetBuiltin",
    "resetVeloSelected",
    // Import progress, the AI status banner and the custom importers. None has an initializer.
    "showImportProgress",
    "showImportProgressIndeterminate",
    "hideImportProgress",
    "cancelImportProgress",
    "importPermissionMessage",
    "readFileTextWithProgress",
    "applyAiStatus",
    "clearTransientStatus",
    "loadImporters",
    "impAdd",
    "impReload",
    "impSetPrecedence",
    "impCopyPrompt",
    "wlApplyToCase",
    // View presets and the .env settings form. Their initializers are the sentinels.
    "viewFilters",
    "viewMeetsMinSev",
    "viewTopN",
    "applyDashboardView",
    "applySavedViewForCase",
    "loadDashboardViews",
    "fetchEnvSettings",
    "saveSettings",
    // Memory Next Steps and the delete-case modal. initDeleteCase/initCasePassword are sentinels.
    "toggleMemNextSteps",
    "resetMemNextSteps",
    "doMemNextSteps",
    "openDeleteCase",
    "closeDeleteCase",
    "doDeleteCase",
    // The setup wizard. `initSetupWizard` is the sentinel, so not here.
    "openSetupWizard",
    "closeSetupWizard",
    "wizRefreshStatus",
    "fetchLogLevel",
    // Multi-select, the bulk IOC actions and the unlock prompt. initCaseUnlock is a sentinel.
    "updateBulkBar",
    "clearSelection",
    "updateIocBulkBar",
    "clearIocSelection",
    "bulkStarIds",
    "bulkToggleStar",
    "openBulkTagModal",
    "bulkMarkFalsePositive",
    "bulkEnrichIocs",
    "bulkTagIocs",
    "bulkMarkIocsFalsePositive",
    "promptCaseUnlock",
    // New case creation. `initNewCase` is the sentinel, so not here.
    "openNewCase",
    "closeNewCase",
    "createNewCase",
    "loadDemoCase",
    // Case templates. invalidateTemplateCache is included deliberately: js/dashboard-save-template.js
    // calls it after a save, and a missing templates module must not turn a successful save into a
    // ReferenceError.
    "loadTemplates",
    "loadIncidentTypes",
    "populateTemplateSelect",
    "selectedNewCasePlaybook",
    "onTemplateSelectChange",
    "invalidateTemplateCache",
    // Velociraptor triage. The accessors are stubbed too: two other modules call them, and a
    // missing triage module must not turn their renders into ReferenceErrors.
    // Bulk finding operations. All work functions; there is no sentinel because the block has no
    // initializer. showToast is stubbed with the rest — a missing toast is a missing decoration.
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
    // Analyst notebook. `initNotebook` is the sentinel. notebookEntry stubs to undefined, which
    // promoteToHypothesis already treats as "no such entry" and bails on.
    "loadNotebook",
    "loadNbAiToggle",
    "nbDelete",
    "nbStartEdit",
    "notebookEntry",
    // Collapsible sections. `initCollapsible` is the sentinel.
    "setupCollapsible",
    "setupReorder",
    // IOC provenance / corroboration / risk. NOTE the inverted direction: these are filters, so a
    // falsy stub means NO filtering and the analyst sees more rows, not fewer. iocCorroborationCount
    // is the exception that matters — the page defaults it to 2, never 0, because `0 >= 2` is false
    // and would filter out every IOC on the page.
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
    // Attack Phases. `initAttackPhases` is the sentinel. hasPhases stubs falsy so the refresh
    // fan-out skips the panel instead of throwing.
    "loadPhases",
    "schedulePhasesReload",
    "renderPhases",
    "hasPhases",
    // Second LLM opinion. `initSecondOpinion` is the sentinel. The two capability answers are
    // stubbed on purpose: falsy hides an AI button, which beats leaving a dead one on screen.
    "setSecondOpinionCapabilities",
    "isFpAiConfigured",
    "loadSecondOpinion",
    "renderSecondOpinion",
    "runSecondOpinion",
    "applySecondOpinionDelta",
    "applyAllSecondOpinion",
    // Evidence Chain graph. `initEvidenceGraph` is the sentinel. hasEvidenceGraph is stubbed so the
    // refresh fan-out reads "no graph loaded" and skips it, rather than throwing mid-fan-out.
    "loadEvidenceGraph",
    "scheduleEvidenceGraphReload",
    "hasEvidenceGraph",
    // Last-import change tracking. isNewEvent / isNewIoc are stubbed deliberately: falsy means the
    // NEW badge does not appear, which drops a decoration rather than an event.
    "loadImportMeta",
    "loadDropStatus",
    "fetchRawToolExts",
    "askRunToolsOnImport",
    "propagateFalsePositive",
    "paintIocImportMeta",
    "doAsk",
    "isNewEvent",
    "isNewIoc",
    // Presidio approval panel. `initPresidio` is the sentinel.
    "loadPresidioPending",
    "renderPresidioPending",
    "setPresidioPending",
    "addCustomEntity",
    "openAnonModal",
    "saveAnon",
    "setAi",
    // Hypotheses. `initHypotheses` is the sentinel. consumePendingHuntHypothesis is stubbed
    // because dashboard-sigma-hunt.js calls it on every launch: undefined just means "no hypothesis
    // to attach", which is the right answer when the module is gone.
    "loadHypotheses",
    "hypPatch",
    "linkNextHuntToHypothesis",
    "consumePendingHuntHypothesis",
    "clearPendingHuntHypothesis",
    "hypDelete",
    "hypApplyReview",
    "promoteToHypothesis",
    // Inline IOC quick-actions. `initIocQuickActions` is the sentinel, and QA_AUDIT_MARK is
    // deliberately absent: it is evidence vocabulary, and a stubbed function in its place would make
    // render()'s indexOf test never match, silently emptying the Investigation Log.
    "qaAudit",
    "qaLinkify",
    "qaResolveIocId",
    // Keyboard navigation. `initKeyboardNav` is the sentinel, so not here.
    "kbdShortcutsEnabled",
    "setKbdShortcutsEnabled",
    "kbdOpenHelp",
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
  ];
  // Not `window[n] = window[n] || noop`: a name that exists but is not callable is a different bug,
  // and quietly replacing it would hide that one too.
  // FILLED is the interesting half: which names were actually absent, i.e. which modules did not
  // load. A stub keeps the page alive but is silent by construction — a no-op panel looks exactly
  // like a panel with nothing to show — so a feature with no initializer of its own has no way to
  // say it is gone. Recording what we filled in gives it one. See the two checks in
  // dashboard.html that read this.
  var filled = [];
  for (var i = 0; i < STUBBED.length; i++) {
    var name = STUBBED[i];
    if (typeof window[name] !== "function") {
      window[name] = function () {};
      filled.push(name);
    }
  }
  window.DfirFacade = { stubbed: STUBBED, filled: filled };
})();
