// The case-load path — connect(), proceedConnect(), the loading overlay and the cross-case
// capture warning — extracted from dashboard.html (issue #415, tier 3).
//
// Second non-feature extraction, same contract as js/dashboard-render.js: connect and
// proceedConnect are NOT stubbed by the facade. A stubbed connect() means clicking Connect
// does nothing at all, with no error and no explanation — the analyst concludes the case is
// broken. The facade reports both missing at load instead, on the same banner as render.
//
// The active-case identity (activeCaseId, activeUnlockedCaseId, activeUnlockRemembered) did
// NOT come along: eight extracted modules read those by bare name, so they stay page
// vocabulary beside SEV. This module writes them through the same global lexical environment
// every other module already shares.
(function () {
  "use strict";

  // The capture extension POSTs to /captures with ITS configured case; the server broadcasts a
  // `capture_ingest` to every dashboard. If captures are arriving for a case we're not viewing,
  // the analyst's extension and dashboard have drifted apart — warn (it's an easy trap).
  let foreignCaptureCase = null; // the other case captures are arriving for
  let foreignCaptureTimer = null; // auto-clears the banner if foreign captures stop
  let mismatchDismissed = ""; // a foreign case the user dismissed — stay quiet until it changes
  function showCaseMismatch(otherCase, myCase, what) {
    if (!otherCase || otherCase === myCase || otherCase === mismatchDismissed)
      return;
    foreignCaptureCase = otherCase;
    document.getElementById("caseMismatchText").innerHTML =
      `⚠ ${esc(what || "Evidence")} are arriving for case <strong>${esc(otherCase)}</strong>, but you're viewing <strong>${esc(myCase)}</strong> — your capture extension is pointed at a different case.`;
    document.getElementById("caseMismatchSwitch").textContent =
      `Switch to ${otherCase}`;
    document.getElementById("caseMismatchBanner").hidden = false;
    if (foreignCaptureTimer) clearTimeout(foreignCaptureTimer);
    foreignCaptureTimer = setTimeout(hideCaseMismatch, 120000); // stale after 2 min of quiet
  }
  function hideCaseMismatch() {
    foreignCaptureCase = null;
    if (foreignCaptureTimer) {
      clearTimeout(foreignCaptureTimer);
      foreignCaptureTimer = null;
    }
    document.getElementById("caseMismatchBanner").hidden = true;
  }

  // Tracks the currently-connected password-protected case's unlock, so a NOT-"remembered"
  // unlock can be explicitly forgotten (POST /cases/:id/lock) the moment we leave it. A
  // session cookie otherwise survives switching cases within the same tab — only an actual
  // browser close clears it — which is stricter persistence than "don't remember" should
  // give: without this, unchecking "remember" would only matter across browser restarts,
  // not across simply switching to another case and back.
  function forgetActiveCaseIfNotRemembered() {
    if (activeUnlockedCaseId && !activeUnlockRemembered) {
      fetch(`/cases/${activeUnlockedCaseId}/lock`, { method: "POST" }).catch(
        () => {},
      );
    }
    activeUnlockedCaseId = null;
    activeUnlockRemembered = true;
  }
  // Covers refresh / navigating away entirely / closing the tab — sendBeacon is the
  // standard way to reliably fire a small POST during page teardown (a plain fetch can be
  // cancelled mid-flight once the page starts unloading).

  // The in-flight case-load "generation" (#174): each proceedConnect() gets its own AbortController
  // covering the two loads the overlay blocks on (state + lifecycle), and activeCaseId names whose
  // case is currently authoritative — used by render()'s stale-response guard above.
  let connectAbortController = null;
  // Same idea for the panel strip: only the newest generation's loaders may paint it.
  let _panelLoadGen = 0;
  // How many of the ~60 secondary panel loaders may be in flight at once. FOUR OF THE BROWSER'S
  // SIX HTTP/1.1 CONNECTIONS, deliberately leaving two free. The fan-out is not the analyst's only
  // claim on the pool: while it runs they may pick another case (a lock-status probe) or press
  // "+ New case" (a /cases fetch to suggest the next incident id). Unbounded, those sat behind up
  // to 86 queued requests — ~8 seconds on an 82 MB case, on routes the server answered in 2ms.
  const PANEL_LOAD_CONCURRENCY = 4;

  function connect() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    if (activeUnlockedCaseId && activeUnlockedCaseId !== caseId)
      forgetActiveCaseIfNotRemembered();
    fetch(`/cases/${caseId}/lock-status`)
      .then((r) =>
        r.ok
          ? r.json()
          : { hasPassword: false, unlocked: true, remembered: false },
      )
      .then((status) => {
        if (status.hasPassword && !status.unlocked) {
          promptCaseUnlock(caseId);
        } else {
          activeUnlockedCaseId = caseId;
          activeUnlockRemembered = !status.hasPassword || status.remembered;
          proceedConnect(caseId);
        }
      })
      .catch(() => proceedConnect(caseId)); // offline / older server — fall back to the old behavior
  }

  // Case loading overlay: blocks the screen from the moment a case is selected until
  // the timeline (state fetch) and the lifecycle status icon have both loaded — the two things
  // an analyst visually checks to know "is this case fully up yet?". The ~40 other secondary
  // panels (geo map, host ranking, playbook, ...) keep loading in the background afterward, same
  // as before this change — only these two block the overlay.
  let _caseLoadingTimeoutId = null;
  // The staged progress tracker for the CURRENT load generation, and the module that owns the
  // arithmetic. The module is an ES module, so it executes after this classic inline script —
  // every call site therefore reads it lazily and no-ops if it is absent. By the time a stage is
  // reported the load has already been through a network round-trip, so in practice it is there;
  // if it somehow is not, the case still loads exactly as it did before, just without a bar.
  let caseLoadState = null;
  const clpApi = () => window.DfirCaseLoadProgress || null;
  function clpPaint() {
    const api = clpApi();
    if (api && caseLoadState) api.paintOverlay(caseLoadState);
  }
  // Advance the bar AND re-arm the stall failsafe. Visible movement is the evidence that nothing
  // is stuck, which is exactly what the old fixed 15s timer had no way of knowing.
  function clpStage(stageId) {
    const api = clpApi();
    if (api && caseLoadState) {
      api.advanceStage(caseLoadState, stageId);
      clpPaint();
    }
    armCaseLoadingStall();
  }
  function clpEvents(n) {
    const api = clpApi();
    if (api && caseLoadState) api.setEventCount(caseLoadState, n);
  }
  // Let the browser paint before a main-thread-blocking phase (JSON.parse, render). Without this
  // the label for that phase is queued behind the work it describes and never appears until after
  // it finishes — the bar would freeze on the PREVIOUS stage and read as hung.
  function clpAfterPaint() {
    const api = clpApi();
    return api ? api.afterPaint() : Promise.resolve();
  }
  // Failsafe: never block the screen forever if a load hangs. Re-armed on every stage transition
  // (see clpStage), so it now fires on evidence of a STALL rather than on a fixed deadline — a
  // large case moving steadily through five stages is no longer told it is stuck.
  function armCaseLoadingStall() {
    const overlay = document.getElementById("caseLoadingOverlay");
    if (!overlay || overlay.style.display === "none") return;
    clearTimeout(_caseLoadingTimeoutId);
    _caseLoadingTimeoutId = setTimeout(() => {
      const textEl = document.getElementById("caseLoadingText");
      // Name the stage that stalled — "which part is stuck" is the first thing an analyst needs,
      // and the old message withheld it.
      const api = clpApi();
      const stuck =
        api && caseLoadState
          ? api.progressOf(caseLoadState).label.replace(/…$/, "")
          : "Still loading";
      if (textEl) textEl.textContent = `${stuck} — click to dismiss`;
      overlay.style.cursor = "pointer";
      overlay.onclick = dismissCaseLoading;
    }, 15000);
  }
  function showCaseLoadingOverlay() {
    const overlay = document.getElementById("caseLoadingOverlay");
    if (!overlay) return;
    const api = clpApi();
    caseLoadState = api ? api.createLoadState() : null;
    const textEl = document.getElementById("caseLoadingText");
    if (textEl) textEl.textContent = "Loading case…";
    overlay.onclick = null;
    overlay.style.cursor = "";
    overlay.style.display = "flex";
    clpPaint();
    armCaseLoadingStall();
  }
  function hideCaseLoadingOverlay() {
    const overlay = document.getElementById("caseLoadingOverlay");
    if (!overlay) return;
    overlay.style.display = "none";
    overlay.onclick = null;
    overlay.style.cursor = "";
    clearTimeout(_caseLoadingTimeoutId);
  }
  // The stalled-overlay click handler (#174): actually abandons the in-flight
  // state/lifecycle load instead of merely hiding the overlay, so those requests stop being able to
  // block or clobber a case the analyst connects to next. Selecting a new case has the same effect
  // (proceedConnect aborts the previous generation itself) — this covers giving up without picking
  // a replacement case yet.
  function dismissCaseLoading() {
    if (connectAbortController) connectAbortController.abort();
    // Retire the generation as well as aborting it. The abort stops the requests; this stops the
    // panel strip from going on reporting progress for a load the analyst has walked away from —
    // the tally would otherwise keep painting as the abandoned fetches reject one by one.
    _panelLoadGen++;
    const api = clpApi();
    if (api) api.hidePanelStrip();
    // THE ABORT CONTROLLER ONLY COVERS FETCHES. proceedConnect also opens a WebSocket and starts a
    // 5-second capture-count poll, and neither is a fetch, so both survived cancellation: the
    // socket went on delivering `state` pushes — which render() accepted, because activeCaseId
    // still named the cancelled case — plus the ~25 other message types that each re-fetch a
    // panel. The result was a dashboard that kept redrawing and re-loading a case the analyst had
    // just walked out of, at a URL that named no case at all.
    //
    // Order matters: drop activeCaseId LAST. render()'s stale guard compares against it, so
    // clearing it before the socket is closed would open a window where a push in flight is
    // measured against nothing.
    if (ws) {
      // Detach BEFORE closing. close() fires onclose asynchronously, and this socket's onclose
      // writes "disconnected" into the same status line the cancel message below claims — so
      // leaving it attached lets the teardown overwrite the explanation a beat later. Nulling
      // onmessage with it also closes the gap between close() and the socket actually closing,
      // during which a frame already in flight can still be delivered.
      try {
        ws.onclose = null;
        ws.onmessage = null;
        ws.onopen = null;
        ws.close();
      } catch {}
      ws = null;
    }
    if (typeof retireCount === "function") retireCount();
    activeCaseId = null;
    hideCaseLoadingOverlay();
    // Take the case back out of the URL. proceedConnect put it there the moment the load STARTED,
    // so without this the address bar goes on naming a case that is not loaded — and refreshing
    // (or sharing the link) would drop the analyst straight back into the load they just walked
    // out of, since ?caseId= is exactly the signal restoreCaseFromUrl acts on. The hash is kept:
    // it carries a deep link to an event, which cancelling a load does not invalidate.
    history.replaceState(null, "", location.pathname + location.hash);
    // Say what happened. A dashboard that simply stops filling in, with a case id still in the
    // picker, is indistinguishable from one that finished — and the analyst needs to know this
    // case is only partly loaded before they read anything off it. The picker keeps the id, so
    // retrying is one click.
    const statusEl = document.getElementById("status");
    if (statusEl) statusEl.textContent = "case load cancelled — pick a case to load";
  }

  function proceedConnect(caseId) {
    // Abandon the previous case's in-flight state/lifecycle load (#174): aborts its fetches (frees
    // the browser's connection slots and lets the server bail out early if it hasn't started the
    // heavy work yet) and makes render()'s stale-response guard reject anything it still returns.
    if (connectAbortController) connectAbortController.abort();
    connectAbortController = new AbortController();
    const loadSignal = connectAbortController.signal;
    activeCaseId = caseId;
    showCaseLoadingOverlay();
    hideCaseMismatch();
    mismatchDismissed = ""; // fresh start for the newly-connected case
    if (ws) {
      try {
        ws.close();
      } catch {}
      ws = null;
    }
    // Remember the case so a page refresh reconnects automatically.
    localStorage.setItem("dfir.caseId", caseId);
    history.replaceState(
      null,
      "",
      "?caseId=" + encodeURIComponent(caseId) + location.hash,
    ); // keep #event=... (deep link) intact
    // Staged case load (progress bar). Every clpStage() call below marks a milestone that has
    // ACTUALLY happened, which is the whole basis for the overlay's bar claiming a position.
    // The two phases that block the main thread — JSON.parse and render() — are each preceded by
    // a forced paint, so their labels appear BEFORE the thread locks up rather than after it
    // frees again. Reading the body by hand instead of r.json() is what makes the download the
    // one phase with a true percentage behind it (Content-Length).
    const stateLoadPromise = (async () => {
      try {
        const res = await fetch(`/cases/${caseId}/state`, {
          signal: loadSignal,
        });
        clpStage("query"); // headers are in — the server has finished querying
        const api = clpApi();
        const body = api
          ? await api.readBodyWithProgress(caseLoadState, res, clpPaint)
          : await res.text();
        clpStage("download");
        await clpAfterPaint();
        const state = JSON.parse(body);
        clpEvents(
          typeof state.forensicTimelineTotal === "number"
            ? state.forensicTimelineTotal
            : (state.forensicTimeline || []).length,
        );
        clpStage("parse");
        await clpAfterPaint();
        typeof render === "function" && render(state);
        jumpToEventFromHash();
        clpStage("render");
      } catch {
        // Aborted (#174), offline, or a non-JSON error body. Same outcome as the .catch(() => {})
        // this replaced: the overlay hides via allSettled below and the dashboard stays as-is.
      }
    })();
    if (typeof verifyCustodyOnOpen === "function") verifyCustodyOnOpen(caseId); // never block a case connect
    applySavedViewForCase(); // restore this case's dashboard-view preset (#142)
    DfirStarred.replace([]);
    starredTagIds = new Map(); // reset synchronously; loadTags re-derives for the new case
    DfirSelection.events.clear();
    DfirSelection.iocs.clear();
    DfirSelection.findings.clear();
    DfirFacets.sources.showAll();
    _srcMenuSig = "";
    DfirFacets.origins.showAll();
    _originMenuSig = "";
    DfirFacets.hosts.showAll();
    _hostMenuSig = "";
    const sfBtn = document.getElementById("evStarFilterBtn");
    if (sfBtn) {
      sfBtn.textContent = "☆ Starred";
      sfBtn.classList.remove("active");
    }
    showFlaggedIocsOnly = false;
    const ifBtn = document.getElementById("iocFlaggedBtn");
    if (ifBtn) ifBtn.classList.remove("active");
    // Provenance filter is per-case session state (not a persisted pref) — reset to "All IOCs" on case load.
    if (typeof setIocProvenanceFilter === "function")
      setIocProvenanceFilter("all");
    document
      .querySelectorAll(".ioc-prov-btn")
      .forEach((b) =>
        b.classList.toggle("active", b.getAttribute("data-prov") === "all"),
      );
    // hideFpNoIntel / showSignalIocsOnly are NOT reset here — like the corroboration lens
    // controls, they're per-browser preferences (localStorage-backed), not per-case session state.
    DfirFacets.iocTypes.showAll();
    _iocTypeMenuSig = "";
    DfirTimelineView.resetForCase(); // NOT clearFilters(): keeps the id filter, severity boxes and exclude terms
    const gsEl = document.getElementById("globalSearch");
    if (gsEl) gsEl.value = "";
    const ffEl = document.getElementById("filterFrom");
    if (ffEl) ffEl.value = "";
    const ftEl = document.getElementById("filterTo");
    if (ftEl) ftEl.value = "";
    const csBtn = document.getElementById("clearSearch");
    if (csBtn) csBtn.hidden = true;
    const cfBtn = document.getElementById("clearFiltersBtn");
    if (cfBtn) cfBtn.hidden = true;
    const smcEl = document.getElementById("searchMatchCount");
    if (smcEl) smcEl.textContent = "";
    setSearchBarOpen(false, false);
    _updateSearchToggleIndicator();
    // The secondary panels. They were 59 bare calls; they are a table now so the strip at the
    // bottom of the screen can say how many have actually landed — the overlay only ever blocked
    // on the timeline and the lifecycle status, so the dashboard visibly kept filling in after it
    // hid, with nothing telling the analyst how much was still outstanding.
    //
    // They run AFTER the synchronous per-case resets above (they used to straddle them). Order
    // among themselves is preserved; moving them after the resets is strictly safer, since every
    // one of them is async and its response now cannot land before the state it resets.
    //
    // runPanelLoaders observes completion at the transport — none of these returns a promise —
    // and counts a rejected request as settled, because several of these routes 501 by design
    // when their store is not configured and a fulfilled-only tally would never complete.
    const panelGen = ++_panelLoadGen;
    const panelApi = clpApi();
    const CASE_PANEL_LOADERS = [
      ["custody", () => loadCustody(caseId)],
      ["count", () => pollCount(caseId)],
      ["aiToggle", () => loadAiToggle(caseId)],
      ["enrichToggle", () => loadEnrichToggle(caseId)],
      ["anonToggle", () => loadAnonToggle(caseId)],
      ["presidioPending", () => loadPresidioPending(caseId)],
      ["falsePositives", () => loadFalsePositives(caseId)],
      ["learnedPatterns", () => loadLearnedPatterns(caseId)],
      ["sourceTrust", () => loadSourceTrust(caseId)],
      ["scope", () => loadScope(caseId)],
      ["hostScope", () => loadHostScope(caseId)],
      ["hostDuplicates", () => loadHostDuplicates(caseId)],
      ["confidenceControl", () => loadConfidenceControl(caseId)],
      ["corrProfile", () => loadCorrProfile(caseId)],
      ["reportMeta", () => loadReportMeta(caseId)],
      ["caseTemplatePicker", () => loadCaseTemplatePicker(caseId)],
      ["cockpit", () => loadCockpit(caseId)],
      ["assetGraph", () => loadAssetGraph(caseId)],
      ["loginGraph", () => loadLoginGraph(caseId)],
      ["assetOverrides", () => loadAssetOverrides(caseId)],
      ["evidenceGraph", () => loadEvidenceGraph(caseId)],
      ["phases", () => loadPhases(caseId)],
      ["timelineGaps", () => loadTimelineGaps(caseId)],
      ["evidenceGaps", () => loadEvidenceGaps(caseId)],
      ["beacons", () => loadBeacons(caseId)],
      ["anomalies", () => loadAnomalies(caseId)],
      ["sessions", () => loadSessions(caseId)],
      ["adversaryHints", () => loadAdversaryHints(caseId)],
      ["playbookMatch", () => loadPlaybookMatch(caseId)],
      ["hostRanking", () => loadHostRanking(caseId)],
      ["d3fend", () => loadD3fend(caseId)],
      ["attackMitigations", () => loadAttackMitigations(caseId)],
      ["compliance", () => loadCompliance(caseId)],
      ["geoMap", () => loadGeoMap(caseId)],
      ["swimlane", () => loadSwimlane(caseId)],
      ["iocSources", () => loadIocSources(caseId)],
      ["iocProvenance", () => loadIocProvenance(caseId)],
      ["iocRisk", () => loadIocRisk(caseId)],
      ["iocProvenanceChains", () => loadIocProvenanceChains(caseId)],
      ["comments", () => loadComments(caseId)],
      ["activityLog", () => loadActivityLog(caseId)],
      ["tags", () => loadTags(caseId)],
      ["pins", () => loadPins(caseId)],
      ["findingWorkflow", () => loadFindingWorkflow(caseId)],
      ["notebook", () => loadNotebook(caseId)],
      ["nbAiToggle", () => loadNbAiToggle(caseId)],
      ["hypotheses", () => loadHypotheses(caseId)],
      ["savedTimeframes", () => loadSavedTimeframes(caseId)],
      ["superTimeline", () => loadSuperTimeline(caseId)],
      ["savedStarredReport", () => loadSavedStarredReport(caseId)],
      ["playbook", () => loadPlaybook(caseId)],
      ["synthMeta", () => loadSynthMeta(caseId)],
      ["secondOpinion", () => loadSecondOpinion(caseId)],
      ["importMeta", () => loadImportMeta(caseId)],
      ["dropStatus", () => loadDropStatus(caseId)],
      ["jobs", () => loadJobs(caseId)], // #225 background-jobs badge/popover
      ["mcpRun", () => loadMcpRun()], // #296 MCP Analysis — servers + this case's evidence paths
      ["undoStack", () => loadUndoStack(caseId)],
      ["customerExposure", () => loadCustomerExposure(caseId)],
      ["veloTriage", () => loadVeloTriage(caseId)],
      ["huntProfile", () => loadHuntProfile(caseId)], // #157 what's been hunted, what hit/missed
    ];
    if (panelApi) {
      panelApi.hidePanelStrip();
      // Generation-guarded like the state load (#174): switching cases mid-load must not let the
      // abandoned case's panels keep painting the strip for the case now on screen.
      //
      // The signal and the concurrency cap are what make a big case's load survivable. They carry
      // the SAME generation as the state/lifecycle load, so dismissing the overlay or picking
      // another case now cancels these ~60 requests too — previously only state and lifecycle were
      // abortable, and the panels went on holding the connection pool for a case the analyst had
      // already walked away from. The cap then keeps two of the browser's six HTTP/1.1 lanes free
      // for whatever the analyst does next, so "+ New case" (which fetches /cases to suggest an id)
      // and connecting to a different case answer immediately instead of queueing behind the
      // fan-out. See runPanelLoaders for the measurements.
      panelApi.runPanelLoaders(
        CASE_PANEL_LOADERS,
        (tally) => {
          if (panelGen === _panelLoadGen) panelApi.paintPanelStrip(tally);
        },
        { signal: loadSignal, concurrency: PANEL_LOAD_CONCURRENCY },
      );
    } else {
      for (const [, run] of CASE_PANEL_LOADERS) {
        try {
          run();
        } catch {}
      }
    }
    const lifecycleLoadPromise = loadCaseLifecycle(caseId, loadSignal);
    lifecycleLoadPromise.then(
      () => clpStage("lifecycle"),
      () => clpStage("lifecycle"),
    );
    Promise.allSettled([stateLoadPromise, lifecycleLoadPromise]).then(
      hideCaseLoadingOverlay,
    );
    resetVeloHuntSuggest(); // clear AI-suggested fleet hunts; analyst regenerates per case on demand
    resetPlaybookHuntSuggest(); // clear AI-suggested playbook hunts (#70) too
    resetGapHypotheses(); // clear AI gap hypotheses (#96); analyst regenerates per case on demand
    resetMemNextSteps(); // clear AI memory next-steps (#101); analyst regenerates per case on demand
    resetDeepPass(); // #204 — measurements and the last deep-pass result are per case

    // Show whether AI analysis is configured at all.
    fetch("/health")
      .then((r) => r.json())
      .then((h) => {
        if (h.aiEnabled) setAi("idle", "ready (waiting for activity)");
        else setAi("off", "off (no provider configured)");
        veloEnabled = !!h.velociraptorEnabled; // gates the "Run in Velociraptor" button in the hunt modal
        applyVeloEnabled(); // gates the triage panel's Run buttons + disabled note
        if (Array.isArray(h.huntPlatforms))
          enabledHuntPlatforms = new Set(h.huntPlatforms); // hunt-modal allowlist
        renderNlqPlatforms(); // refresh the query-translator platform picker (#100)
        // Both capability flags belong to js/dashboard-second-opinion.js. This poller owns the
        // /health fetch, not the state, so it hands them over and lets the feature re-gate its
        // own button.
        if (typeof setSecondOpinionCapabilities === "function")
          setSecondOpinionCapabilities(h.secondOpinionEnabled, h.aiEnabled);
        // Deep pass runs on the SYNTHESIS provider — aiEnabled is the vision gate and would offer a
        // Run button that can only 501 in a vision-only config (#204).
        setDeepPassSynthesisEnabled(!!h.synthesisEnabled); // js/dashboard-deep-pass.js
        applyDeepPassGate();
      })
      .catch(() => setAi("unknown", "unknown"));
    loadUpdateCheck();

    // Check-on-connect: if screenshots recently arrived for a DIFFERENT case, warn right away
    // (the live WS event only fires on the next capture, which may be a while off).
    fetch("/captures/recent")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d && d.caseId && d.caseId !== caseId && d.ageMs < 120000)
          showCaseMismatch(d.caseId, caseId, "Screenshots");
      })
      .catch(() => {});

    try {
      ws = new WebSocket(
        `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws?caseId=${encodeURIComponent(caseId)}`,
      );
    } catch (wsErr) {
      document.getElementById("status").textContent =
        "live updates unavailable (WebSocket blocked — HTTPS/ws mismatch?)";
      console.warn("WebSocket connection failed:", wsErr);
      ws = null;
      return;
    }
    ws.onopen = () =>
      (document.getElementById("status").textContent = "connected (live)");
    ws.onclose = () =>
      (document.getElementById("status").textContent = "disconnected");
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "state") {
        typeof render === "function" && render(msg.state);
        loadCockpit(caseId);
        scheduleAssetGraphReload();
        scheduleEvidenceGraphReload();
        schedulePhasesReload();
        scheduleTimelineGapsReload();
        scheduleEvidenceGapsReload();
        scheduleBeaconsReload();
        scheduleAnomaliesReload();
        scheduleSessionsReload();
        scheduleAdversaryHintsReload();
        schedulePlaybookMatchReload();
        scheduleHostRankingReload();
        scheduleD3fendReload();
        scheduleAttackMitigationsReload();
        scheduleComplianceReload();
        scheduleGeoMapReload();
        scheduleSwimlaneReload();
        scheduleIocSourcesReload();
        scheduleIocProvenanceReload();
        scheduleIocRiskReload();
        scheduleIocProvenanceChainReload();
        loadSynthMeta(caseId);
        loadPlaybook(caseId);
        loadHypotheses(caseId);
        loadSuperTimeline(caseId);
      } else if (msg.type === "second_opinion_changed")
        loadSecondOpinion(caseId);
      else if (msg.type === "ai_status") applyAiStatus(msg);
      else if (msg.type === "job_changed") scheduleJobUiRefresh(caseId);
      else if (msg.type === "capture_ingest") {
        // A capture arrived somewhere. If it's for OUR case, all good (clear any warning);
        // otherwise the extension is feeding a different case than we're viewing — warn.
        if (msg.caseId && msg.caseId !== caseId)
          showCaseMismatch(msg.caseId, caseId, "Screenshots");
        else hideCaseMismatch();
      } else if (msg.type === "import_ingest") {
        // Same trap for pushed artifacts (extension "Push to DFIR-Companion" → /import): warn when
        // they're landing in a case other than the one we're viewing.
        if (msg.caseId && msg.caseId !== caseId)
          showCaseMismatch(msg.caseId, caseId, "Artifacts");
        else hideCaseMismatch();
      } else if (msg.type === "comments_changed") loadComments(caseId);
      else if (msg.type === "activity_changed") {
        loadActivityLog(caseId);
        loadCockpit(caseId);
      } else if (msg.type === "tags_changed") loadTags(caseId);
      else if (msg.type === "pins_changed") {
        loadPins(caseId);
        loadCockpit(caseId);
      } else if (msg.type === "finding_workflow_changed") {
        loadFindingWorkflow(caseId);
        loadCockpit(caseId);
      } else if (msg.type === "notebook_changed") {
        loadNotebook(caseId);
        loadNbAiToggle(caseId);
      } else if (msg.type === "hypotheses_changed") {
        loadHypotheses(caseId);
        loadCockpit(caseId);
      } else if (msg.type === "dwell_window_changed")
        loadSavedTimeframes(caseId);
      else if (msg.type === "super_timeline_changed") {
        loadSuperTimeline(caseId);
        scheduleLoginGraphReload(caseId);
      } else if (msg.type === "playbook_changed") loadPlaybook(caseId);
      else if (msg.type === "asset_overrides_changed") {
        loadAssetGraph(caseId);
        loadAssetOverrides(caseId);
      } else if (msg.type === "import_meta_changed") {
        loadImportMeta(caseId);
        loadCockpit(caseId);
      } else if (msg.type === "drop_status_changed") loadDropStatus(caseId);
      else if (msg.type === "import_undo_changed") loadUndoStack(caseId);
      else if (msg.type === "velo_hunt_changed") {
        loadVeloHuntJobs(caseId);
        loadHuntProfile(caseId);
      } else if (msg.type === "velo_monitor_changed") loadVeloMonitors(caseId);
      else if (msg.type === "push_token_changed") loadPushToken(caseId);
      else if (msg.type === "importers_changed") {
        if (document.getElementById("stab-importers")) loadImporters();
      } else if (msg.type === "false_positive_changed")
        loadFalsePositives(caseId);
      else if (msg.type === "learned_patterns_changed")
        loadLearnedPatterns(caseId);
      else if (msg.type === "source_trust_changed") loadSourceTrust(caseId);
      else if (msg.type === "clock_skew_changed") loadClockSkew(caseId);
      else if (msg.type === "scope_changed") {
        // The same commit loadScope makes — the window came from the server either way, so the
        // two controls are a sink here. Unlike loadScope this path then redraws, because the
        // change came from outside and nothing else is going to.
        //
        // The hub broadcasts to every subscriber with no sender exclusion (src/live/hub.ts:67-80),
        // so applyScope receives its own echo and this runs a second time after it — which is why
        // applying a scope renders twice and the analyst's typed input is replaced by the
        // server's normalised form. Pre-existing behaviour, preserved.
        DfirScope.receive(msg.start, msg.end);
        // render() projects with the freshly-updated window AND caches its argument as
        // `DfirState.lastState()`, so pass the RAW state — passing an already-projected one would
        // cache a scope-narrowed subset, permanently dropping out-of-window events on the next
        // scope widen/clear until a fresh server state arrives.
        if (DfirState.lastState())
          typeof render === "function" && render(DfirState.lastState());
      }
    };
  }

  // Case templates and incident types moved to js/dashboard-case-templates.js (#415 tier 3).
  // It owns the two caches; js/dashboard-save-template.js calls its invalidateTemplateCache()

  // What the dashboard does with a case id at page load. It lives here rather than in the page's
  // inline script because it is the same decision connect() implements — and the page's inline
  // block is under a size freeze (#384) that new code is meant to stay out of.
  //
  // ?caseId= is an EXPLICIT navigation: a deep link, a bookmark, or the refresh of a session
  // already in a case (proceedConnect replaceState's it there). It opens, as it always did.
  //
  // The REMEMBERED case does not. Landing on a bare /dashboard used to auto-connect to whatever
  // was open last, which on a large case meant arriving into a blocking overlay and a
  // multi-second load nobody asked for — the wrong default, because opening the dashboard is
  // just as often the moment an analyst wants a DIFFERENT case or a new one. It pre-fills the
  // picker instead, so reopening it stays one click and the choice stays theirs.
  function restoreCaseFromUrl() {
    const fromUrl = (
      new URLSearchParams(location.search).get("caseId") || ""
    ).trim();
    const remembered = (localStorage.getItem("dfir.caseId") || "").trim();
    const el = document.getElementById("caseId");
    if (!el) return;
    if (fromUrl) {
      el.value = fromUrl;
      connect();
    } else if (remembered) {
      el.value = remembered;
    }
  }

  // The loading overlay's Cancel button, the cross-case warning's two buttons and the pagehide
  // handler that forgets an unremembered unlock. All four bind to markup, so they are load-time
  // work.
  function initCaseConnect() {
    // Guarded like every other markup binding here: an older cached dashboard.html without the
    // button must not throw and take the rest of this wiring — the mismatch banner and the
    // unlock-forgetting pagehide handler — down with it.
    const cancelBtn = document.getElementById("caseLoadingCancel");
    if (cancelBtn) cancelBtn.onclick = dismissCaseLoading;
    document.getElementById("caseMismatchSwitch").onclick = () => {
      if (!foreignCaptureCase) return;
      document.getElementById("caseId").value = foreignCaptureCase;
      mismatchDismissed = "";
      hideCaseMismatch();
      connect();
    };
    document.getElementById("caseMismatchDismiss").onclick = () => {
      mismatchDismissed = foreignCaptureCase || ""; // suppress this case until a different one appears
      hideCaseMismatch();
    };
    window.addEventListener("pagehide", () => {
      if (activeUnlockedCaseId && !activeUnlockRemembered) {
        navigator.sendBeacon(`/cases/${activeUnlockedCaseId}/lock`);
      }
    });
  }

  window.initCaseConnect = initCaseConnect;
  window.restoreCaseFromUrl = restoreCaseFromUrl;
  window.connect = connect;
  window.proceedConnect = proceedConnect;
})();
