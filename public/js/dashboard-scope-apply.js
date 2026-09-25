// Applying the analyst's scope filter to the loaded case (#415 tier 3).
//
// A single function that sat under the Query Translator's banner and has nothing to do with it. It
// is called from js/dashboard-search-scope.js, which binds the Apply button — so it is a module of
// its own rather than a passenger in whichever neighbour happened to be extracted first.
(function () {
  function applyScope() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const body = {
      start: utcInputToIso(document.getElementById("scopeStart").value),
      end: utcInputToIso(document.getElementById("scopeEnd").value),
    };
    document.getElementById("status").textContent =
      "applying scope…";
    fetch(`/cases/${caseId}/scope`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((s) => {
        // confirm(), not receive(): the two inputs are where this window was READ from, so
        // writing them back is not this path's business. (The server's own scope_changed echo
        // does write them, with its normalised ISO form — see the handler.)
        DfirScope.confirm(s.start, s.end);
        // The view is scope-consistent immediately (client-side projection). A scope change starts
        // no synthesis (#1599): the conclusions are marked out of date and the AI status pill says
        // so, until the analyst presses AI Re-synthesize.
        document.getElementById("status").textContent = !DfirScope.isEmpty()
          ? "scope applied — conclusions out of date (see AI status)"
          : "scope cleared — conclusions out of date (see AI status)";
        fetch(`/cases/${caseId}/state`)
          .then((r) => r.json())
          .then(render)
          .catch(() => {});
        // These panels are derived server-side straight from the (now re-scoped) forensic
        // timeline — no AI call needed, so refresh them right away: no synthesis follows a scope
        // change (#1599), so no WS "state" broadcast will do it.
        scheduleAssetGraphReload();
        scheduleEvidenceGraphReload();
        schedulePhasesReload();
        scheduleTimelineGapsReload();
        scheduleEvidenceGapsReload();
        scheduleCloudCoverageReload();
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
        loadSuperTimeline(caseId);
      })
      .catch(
        () =>
          (document.getElementById("status").textContent =
            "scope failed — restart the companion server to load the latest endpoints."),
      );
  }

  window.applyScope = applyScope;
})();
