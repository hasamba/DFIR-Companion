// Trusted-source activity on the forensic timeline (#2561). The analyst marks an IP, an AWS access key
// id or an AWS principal ARN (the account root included) as "ours" or "responder" — from an IOC row's
// label selector or the "Mark a source" form in the IOC panel — and the server tags that source's
// ROUTINE rows `trusted-activity` (grade unchanged; high-impact actions are never tagged). This file:
//   - loads the rows whose trusted tag still holds (GET /cases/:id/trusted-activity — the server
//     re-checks every tag against the current marks, so a stale tag never hides anything);
//   - the "Hide trusted" toggle in the timeline header and the "N trusted" count beside the total;
//   - the "Mark a source" form (value + label) that PUTs the existing attribution route.
// The timeline render (dashboard.html renderTimelineEvents) asks trustedRowsHidden / isTrustedRow /
// trustedCountIn; every read is guarded, so the page works before this file has loaded.
(function () {
  let rows = {};
  let owner = null; // the case the loaded rows belong to; another case's rows are never applied
  let hide = false;

  function owned() {
    return typeof activeCaseId !== "undefined" && owner && owner === activeCaseId ? rows : {};
  }
  function trustedInfo(id) {
    const hit = owned()[String(id)];
    return hit && typeof hit === "object" ? hit : null;
  }
  function isTrusted(id) {
    return !!trustedInfo(id);
  }
  function trustedHidden() {
    return hide;
  }
  function trustedCountIn(list) {
    let n = 0;
    for (const e of list || []) if (e && isTrusted(e.id)) n++;
    return n;
  }
  function trustedTotal() {
    return Object.keys(owned()).length;
  }
  function paintButton() {
    const b = document.getElementById("evTrustedFilterBtn");
    if (!b) return;
    const total = trustedTotal();
    b.hidden = total === 0 && !hide;
    b.textContent = hide ? `Trusted hidden (${total})` : `Hide trusted (${total})`;
    b.classList.toggle("active", hide);
    b.setAttribute("aria-pressed", hide ? "true" : "false");
  }
  function repaintTimeline() {
    paintButton();
    if (typeof renderTimelineEvents === "function" && typeof DfirState !== "undefined")
      renderTimelineEvents(DfirState.lastFt() || []);
  }
  function loadTrustedActivity(caseId) {
    if (!caseId) return Promise.resolve();
    return fetch(`/cases/${encodeURIComponent(caseId)}/trusted-activity`)
      .then((r) => (r.ok ? r.json() : { rows: {} }))
      .then((body) => {
        if (typeof activeCaseId !== "undefined" && caseId !== activeCaseId) return;
        const next = body && body.rows && typeof body.rows === "object" ? body.rows : {};
        const changed = owner !== caseId || JSON.stringify(next) !== JSON.stringify(rows);
        rows = next;
        if (owner !== caseId) hide = false; // a case switch never carries the toggle over
        owner = caseId;
        if (changed) repaintTimeline();
        else paintButton();
      })
      .catch((err) => console.warn(`[DFIR] trusted-activity rows failed to load: ${err && err.message}`));
  }
  function toggleTrustedHidden() {
    hide = !hide;
    repaintTimeline();
  }

  // The "Mark a source" form: a value the IOC list may not hold (the account root never becomes an
  // IOC) and a friendly label. Reuses setIocAttribution, which writes the custody entry server-side.
  function markSourceFromForm() {
    const input = document.getElementById("trustedSourceValue");
    const sel = document.getElementById("trustedSourceLabel");
    const value = input ? String(input.value || "").trim() : "";
    const label = sel ? sel.value : "";
    if (!value) {
      if (typeof showToast === "function") showToast("Type an IP, an AWS access key id or an ARN first", "error");
      return Promise.resolve();
    }
    if (typeof setIocAttribution !== "function") return Promise.resolve();
    return setIocAttribution(value, label === "ours" || label === "responder" ? label : null).then(() => {
      if (input) input.value = "";
      return loadTrustedActivity(typeof activeCaseId !== "undefined" ? activeCaseId : null);
    });
  }

  // The two buttons dispatch through js/dashboard-data-act.js (trustedToggleHidden, trustedMarkSource).
  window.loadTrustedActivity = loadTrustedActivity;
  window.trustedRowInfo = trustedInfo;
  window.isTrustedRow = isTrusted;
  window.trustedRowsHidden = trustedHidden;
  window.trustedCountIn = trustedCountIn;
  window.trustedRowTotal = trustedTotal;
  window.toggleTrustedHidden = toggleTrustedHidden;
  window.markTrustedSourceFromForm = markSourceFromForm;
})();
