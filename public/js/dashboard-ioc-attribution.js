// The analyst's attribution label on an IOC (#2543): attacker / ours / responder / unknown. A chip
// beside the value and a small selector in the row's actions. The labels live in the case's own
// side file (GET/PUT /cases/:id/ioc-attribution), keyed by the lower-cased value. The IOC block-list
// export leaves an "ours" or "responder" value out, and such a mark on an IP, AWS key id or ARN tags
// that source's routine timeline rows trusted-activity (#2561, js/dashboard-trusted-activity.js).
(function () {
  const LABELS = ["attacker", "ours", "responder", "unknown"];
  const LABEL_TEXT = {
    attacker: "attacker",
    ours: "ours (victim asset)",
    responder: "responder",
    unknown: "unknown",
  };
  let labels = {};
  let owner = null; // the case the loaded labels belong to; another case's labels are never shown

  function ownedLabels() {
    return typeof activeCaseId !== "undefined" && owner && owner === activeCaseId ? labels : {};
  }
  function keyOf(value) {
    return String(value == null ? "" : value).trim().toLowerCase();
  }
  // The IOC's own value first, then any value merged onto it — the server's attributionFor.
  function iocAttributionOf(ioc) {
    const map = ownedLabels();
    const own = map[keyOf(ioc && ioc.value)];
    if (own) return own.label;
    for (const a of (ioc && ioc.aliasValues) || []) {
      const hit = map[keyOf(a)];
      if (hit) return hit.label;
    }
    return null;
  }
  function repaint() {
    if (typeof renderIocs === "function" && typeof DfirState !== "undefined" && DfirState.lastState())
      renderIocs(DfirScope.project(DfirState.lastState()).iocs || []);
  }
  function loadIocAttribution(caseId) {
    if (!caseId) return Promise.resolve();
    return fetch(`/cases/${encodeURIComponent(caseId)}/ioc-attribution`)
      .then((r) => (r.ok ? r.json() : {}))
      .then((m) => {
        if (typeof activeCaseId !== "undefined" && caseId !== activeCaseId) return;
        labels = m && typeof m === "object" ? m : {};
        owner = caseId;
        repaint();
      })
      .catch((err) => console.warn(`[DFIR] IOC labels failed to load: ${err && err.message}`));
  }
  // The chip beside the value: only when a label is set. The label is an enum, escaped anyway.
  function iocAttributionChip(ioc) {
    const label = iocAttributionOf(ioc);
    if (!label || !LABELS.includes(label)) return "";
    return ` <span class="ioc-attr-chip ioc-attr-${esc(label)}" title="Analyst label: ${escAttr(LABEL_TEXT[label])}">${esc(label)}</span>`;
  }
  // The selector in the actions cell. The value rides in data-value (escAttr), never in script.
  function iocAttributionSelect(ioc) {
    const cur = iocAttributionOf(ioc) || "";
    const opts = [`<option value=""${cur ? "" : " selected"}>label…</option>`]
      .concat(LABELS.map((l) => `<option value="${l}"${cur === l ? " selected" : ""}>${esc(LABEL_TEXT[l])}</option>`))
      .join("");
    return `<select class="ioc-attr-sel" aria-label="Label this indicator" title="Whose is this value? attacker / ours / responder / unknown" data-act="iocSetAttribution" data-act-on="change" data-value="${escAttr(String(ioc.value))}">${opts}</select>`;
  }
  function setIocAttribution(value, label) {
    const caseId = typeof activeCaseId !== "undefined" ? activeCaseId : null;
    if (!caseId || !value) return Promise.resolve();
    // The analyst's name for the custody entry, the same source the false-positive marking uses.
    const actor = typeof investigatorName === "function" ? investigatorName() : "";
    const body = { value, label: LABELS.includes(label) ? label : null, actor };
    return fetch(`/cases/${encodeURIComponent(caseId)}/ioc-attribution`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((m) => {
        if (caseId !== activeCaseId) return;
        labels = m && typeof m === "object" ? m : {};
        owner = caseId;
        repaint();
        if (typeof loadTrustedActivity === "function") loadTrustedActivity(caseId); // #2561
      })
      .catch((err) => {
        if (typeof showToast === "function") showToast(`Could not save the IOC label: ${err.message}`, "error");
        else console.warn(`[DFIR] IOC label save failed: ${err.message}`);
      });
  }
  window.loadIocAttribution = loadIocAttribution;
  window.iocAttributionOf = iocAttributionOf;
  window.iocAttributionChip = iocAttributionChip;
  window.iocAttributionSelect = iocAttributionSelect;
  window.setIocAttribution = setIocAttribution;
})();
