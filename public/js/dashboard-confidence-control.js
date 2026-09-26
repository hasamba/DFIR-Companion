// Findings min-confidence display floor (#226) (#415 tier 3).
//
// The debounce and its pending edit are the whole state, and both are private: a second script
// nudging confPending would silently change what the unload flush writes. The two unload
// listeners register at load, which is deferred work — nothing here touches the DOM until the
// page calls loadConfidenceControl on case connect.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // Findings min-confidence display floor (#226) — a per-case setting so it survives a page
  // reload, unlike a plain in-browser filter. Loaded on case connect; saved (debounced) on change.
  // A pending debounced save is flushed on unload (beforeunload/pagehide) via `keepalive: true` —
  // otherwise a reload shortly after typing (well within the 500ms debounce) would cancel the
  // in-flight timer and silently drop the edit, reverting to the last-saved value.
  let confSaveTimer = null;
  let confPending = null; // { caseId, minConfidence } once a keystroke schedules a save, else null
  // A push re-reads these controls (#1691), and the hub echoes every push to its sender too. So a
  // response may only paint if it is the newest load, no local edit happened since it started, and
  // its case is still the open one — otherwise an older value overwrites the analyst's newer one.
  let confLoadGen = 0;
  let confEditGen = 0;
  // A save still on its way to the server: a load now would read the value from before it and
  // briefly roll the control back. The load waits instead, and runs once when the last save
  // settles — on failure too, so the control then shows what the server really holds.
  let confSavesInFlight = 0;
  let confReloadOwed = null; // the case id a skipped load was for, else null
  function trackConfidenceSave(saving) {
    confSavesInFlight++;
    return saving.finally(() => {
      confSavesInFlight--;
      if (confSavesInFlight > 0 || !confReloadOwed) return;
      const caseId = confReloadOwed;
      confReloadOwed = null;
      loadConfidenceControl(caseId);
    });
  }
  function putConfidenceControl(caseId, minConfidence, opts) {
    return fetch(`/cases/${caseId}/confidence-control`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        minConfidence: minConfidence > 0 ? minConfidence : null,
      }),
      ...opts,
    });
  }
  function flushConfidenceControl() {
    if (!confPending) return;
    clearTimeout(confSaveTimer);
    const { caseId, minConfidence } = confPending;
    confPending = null;
    putConfidenceControl(caseId, minConfidence, { keepalive: true }).catch(
      () => {},
    );
  }
  function loadConfidenceControl(caseId) {
    // The analyst's own edit is still waiting to save; its echo will re-read the newer value.
    if (confPending && confPending.caseId === caseId) return;
    if (confSavesInFlight > 0) {
      confReloadOwed = caseId;
      return;
    }
    const load = ++confLoadGen;
    const editsAtStart = confEditGen;
    fetch(`/cases/${caseId}/confidence-control`)
      .then((r) => r.json())
      .then((c) => {
        if (load !== confLoadGen || editsAtStart !== confEditGen) return;
        if (document.getElementById("caseId").value.trim() !== caseId) return;
        document.getElementById("confFilter").value = c.minConfidence ?? 0;
        document.getElementById("hideAutoFindings").checked =
          !!c.hideAutoFindings;
        document.getElementById("hideGapFindings").checked =
          !!c.hideGapFindings;
        if (DfirState.lastState())
          typeof render === "function" && render(DfirState.lastState());
      })
      .catch(() => {});
  }
  function saveConfidenceControl(caseId, minConfidence) {
    confEditGen++;
    clearTimeout(confSaveTimer);
    confPending = { caseId, minConfidence };
    confSaveTimer = setTimeout(() => {
      confPending = null;
      trackConfidenceSave(putConfidenceControl(caseId, minConfidence)).catch(
        () => {},
      );
    }, 500);
  }

  // The two finding-origin lenses. Saved IMMEDIATELY rather than joining the min-confidence
  // debounce above: a checkbox click is one discrete edit, not a keystroke stream, so there is
  // nothing to coalesce and nothing to flush on unload. The two save paths PUT disjoint keys and
  // the route patches key by key, but that alone does not prevent the server's read-modify-write
  // from clobbering a field; `ConfidenceControlStore.set` wraps the cycle in a per-case lock, so
  // concurrent saves are safe in either order.
  function saveFindingOriginFilters(caseId, patch) {
    confEditGen++;
    return trackConfidenceSave(
      fetch(`/cases/${caseId}/confidence-control`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      }),
    ).catch(() => {});
  }

  // Registered here rather than at load: see the manifest note. Both events fire long after the
  // page is up, so deferring the registration costs nothing and keeps the module loadable.
  function initConfidenceControl() {
    window.addEventListener("beforeunload", flushConfidenceControl);
    window.addEventListener("pagehide", flushConfidenceControl);
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.initConfidenceControl = initConfidenceControl;
  window.loadConfidenceControl = loadConfidenceControl;
  window.saveConfidenceControl = saveConfidenceControl;
  window.saveFindingOriginFilters = saveFindingOriginFilters;
})();
