// data-act dispatch (CSP: no inline event handlers) (#415 tier 3).
//
// THIS IS WHAT LETS THE SERVER SEND `script-src 'self'`. Markup carries `data-act="<name>"` and the
// behaviour lives in the ACTIONS table here; a delegated listener looks the name up and calls it.
//
// ACTIONS IS A FIXED LITERAL AND MUST STAY ONE. It is deliberately not a `window[name]` lookup,
// because `name` comes from a DOM attribute — a lookup would turn any injected attribute into a
// call to an arbitrary global. Moving the table into a module does not change that and must not be
// taken as licence to.
//
// The four load-time statements bind the delegated listeners and become the initializer.
(function () {
  // ── data-act dispatch (CSP: no inline handlers) ───────────────────────────────────────────
  //
  // Every control that used to carry an inline `onclick=` / `onchange=` / `onsubmit=` now carries
  // `data-act="<name>"` (plus `data-act-on="change|submit"` when it isn't a click), and the
  // behaviour lives in ACTIONS below. This is what lets the server send `script-src 'self'`:
  // an inline handler attribute is script, and CSP blocks it outright — a nonce cannot whitelist
  // one (nonces apply to <script nonce="__CSP_NONCE__"> blocks only), so the attributes had to go.
  //
  // Dispatch is DELEGATED from <main>, so markup rendered later into innerHTML is covered with no
  // re-wiring at each render site — the pattern the pivot-query Copy button already used (#281).
  // ACTIONS is a fixed literal, deliberately NOT a `window[name]` lookup: `name` comes from a DOM
  // attribute, and resolving that against the global scope would hand any future markup-injection
  // bug a call-anything primitive — the opposite of the point of this change.
  //
  // `el` is the element carrying data-act; interpolated ids/values ride in data-* beside it,
  // escAttr-escaped exactly as they were inside the old handler string.
  const ACTIONS = {
    // Now cockpit
    cockpitAction: (el) => cockpitAction(el),
    cockpitOpenTarget: (el) => cockpitOpenTarget(el),
    cockpitJumpEvent: (el) => cockpitJumpEvent(el.dataset.id),
    cockpitWorkspace: (el) => cockpitWorkspace(el),
    cockpitRetry: (el) => loadCockpit(),
    // Geo map
    renderGeoView: (el) => renderGeoView(),
    renderGeoMarkers: (el) => renderGeoMarkers(),
    geoDownloadCsv: (el) => geoDownloadCsv(),
    ensureGeoMap: (el) => ensureGeoMap(),
    // Tagger
    runTagger: (el) => runTagger(),
    clearTaggerTags: (el) => clearTaggerTags(),
    toggleTaggerRules: (el) => toggleTaggerRules(),
    toggleTaggerSuggest: (el) => toggleTaggerSuggest(),
    suggestTaggerRule: (el) => suggestTaggerRule(),
    previewTaggerRule: (el) => previewTaggerRule(),
    addSuggestedTaggerRule: (el) => addSuggestedTaggerRule(),
    discardSuggestedTaggerRule: (el) => discardSuggestedTaggerRule(),
    refreshTaggerRuleList: (el) => refreshTaggerRuleList(),
    resetTaggerRules: (el) => resetTaggerRules(),
    saveTaggerRules: (el) => saveTaggerRules(),
    // Supertimeline
    superPageReset: (el) => superPage(0),
    superPagePrev: (el) => superPage(-1),
    superPageNext: (el) => superPage(1),
    promoteSuperSelected: (el) => promoteSuperSelected(),
    toggleSuperPromote: (el) => toggleSuperPromote(el.dataset.id, el.checked),
    applyTimeframe: (el) => applyTimeframe(),
    saveTimeframe: (el) => saveTimeframe(),
    clearSuperTime: (el) => clearSuperTime(),
    // Findings / remediation
    generateRemediation: (el) => generateRemediation(el),
    // Notebook + hypotheses
    promoteToHypothesis: (el) => promoteToHypothesis(el.dataset.id),
    nbStartEdit: (el) => nbStartEdit(el.dataset.id),
    nbDelete: (el) => nbDelete(el.dataset.id),
    hypPatchStatus: (el) => hypPatch(el.dataset.id, { status: el.value }),
    hypPatchAssignee: (el) => hypPatch(el.dataset.id, { assignee: el.value }),
    hypPatchNotes: (el) => hypPatch(el.dataset.id, { notes: el.value }),
    hypDelete: (el) => hypDelete(el.dataset.id),
    hypApplyReview: (el) => hypApplyReview(el.dataset.id, el.dataset.st),
    linkNextHunt: (el) =>
      linkNextHuntToHypothesis(el.dataset.id, el.getAttribute("data-t")),
    clearPendingHunt: (el, e) => {
      pendingHuntHypothesis = null;
      el.parentElement.textContent = "";
      e.preventDefault();
    },
    // Playbook tasks
    pbJumpFinding: (el, e) => {
      pbJumpFinding();
      e.preventDefault();
    },
    pbPatchStatus: (el) => pbPatch(el.dataset.id, { status: el.value }),
    pbPatchAssignee: (el) => pbPatch(el.dataset.id, { assignee: el.value }),
    pbPatchDueDate: (el) => pbPatch(el.dataset.id, { dueDate: el.value }),
    pbMovePrev: (el) => pbMove(el.dataset.id, -1),
    pbMoveNext: (el) => pbMove(el.dataset.id, 1),
    pbDelete: (el) => pbDelete(el.dataset.id),
    pbToggleDeps: (el) => pbToggleDeps(el.dataset.id),
    pbToggleDep: (el) => pbToggleDep(el.dataset.id, el.dataset.dep, el.checked),
    // Timeline
    evDetailsToggle: (el) => {
      const d = document.getElementById(el.dataset.target);
      if (!d) return;
      d.hidden = !d.hidden;
      el.textContent = d.hidden ? "[details ▶]" : "[details ▼]";
    },
    zoomToTimeWindow: (el) => zoomToTimeWindow(el.dataset.from, el.dataset.to),
    tlPagePrev: (el) => {
      if (tlPage > 0) {
        _tlKeepPage = true;
        tlPage--;
        renderTimelineEvents(DfirState.lastFt());
      }
    },
    tlPageNext: (el) => {
      if (tlPage < Number(el.dataset.total)) {
        _tlKeepPage = true;
        tlPage++;
        renderTimelineEvents(DfirState.lastFt());
      }
    },
    tlSetPageSize: (el) => {
      tlPageSize = +el.value;
      renderTimelineEvents(DfirState.lastFt());
    },
    clearEvIdFilter: (el) => clearEvIdFilter(),
    // IOCs
    iocPagePrev: (el) => iocPageStep(-1),
    iocPageNext: (el) => iocPageStep(1),
    iocSetPageSize: (el) => iocSetPageSize(+el.value),
    // ATT&CK / kill chain / hosts
    huntForTechnique: (el) => huntForTechnique(el.dataset.id, el),
    kcSelect: (el) => {
      if (!el.classList.contains("kc-empty")) kcSelect(el.dataset.tac);
    },
    applyHostRankingScope: (el) => applyHostRankingScope(),
    jumpToGaps: (el) => {
      const g = document.getElementById("sec-gaps");
      if (g) g.scrollIntoView({ behavior: "smooth" });
    },
    // Playbook Match (#230): a matched step jumps to the event that evidences it; an unobserved
    // step sends the analyst to Evidence Gaps, which carries the collection directive for it.
    playbookJumpToEvent: (el) => jumpToEvent(el.dataset.id),
    playbookJumpToGaps: (el) => {
      const g = document.getElementById("sec-evidence-gaps");
      if (g) {
        g.classList.remove("collapsed");
        g.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    },
    // Compliance Impact (#336)
    setComplianceDiscovered: (el) => setComplianceDiscovered(el),
    clearComplianceDiscovered: (el) => clearComplianceDiscovered(),
    toggleComplianceFramework: (el) => toggleComplianceFramework(),
    // Forms that never navigate (were an inline onsubmit returning false)
    noSubmit: (el, e) => e.preventDefault(),
  };

  function dispatchAct(e, type) {
    const el = e.target.closest("[data-act]");
    if (!el) return;
    if ((el.dataset.actOn || "click") !== type) return;
    const fn = ACTIONS[el.dataset.act];
    if (typeof fn !== "function") return; // unknown key: ignore rather than throw mid-render
    fn(el, e);
  }

  // These sit inside collapsible <h2> headers and previously carried an inline click handler
  // to keep a click on the wrapper from toggling the section. The listener has to live ON the element
  // (not delegated at document level) so it runs while the event is still below the <h2> handler.

  // The statements the inline block ran at module scope.
  function initDataAct() {
    ["click", "change", "submit"].forEach((type) => {
      document.addEventListener(type, (e) => dispatchAct(e, type));
    });
    document.querySelectorAll("[data-stop-click]").forEach((el) => {
      el.addEventListener("click", (e) => e.stopPropagation());
    });
    setupCollapsible();
    setupReorder();
  }

  window.initDataAct = initDataAct;
})();
