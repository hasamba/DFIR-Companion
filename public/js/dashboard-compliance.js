// Regulatory notification clocks (#178) (#415 tier 3).
//
// A derived panel plus the analyst's discovery-date controls. Everything it stores is a cached
// response and a debounce timer.
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // ── Compliance Impact (#234 / #336) — control failures & regulatory obligations ─────────────
  // Derived server-side from the case's CONFIRMED findings; offline, no AI. Two rules this
  // renderer exists to keep:
  //   - the "not legal advice" disclaimer and the framework editions render WITH the mapping,
  //     never as a tooltip or a separate page. A control-failure list without them reads as a
  //     compliance verdict.
  //   - a countdown appears only where the API returned a real `deadline`. Rows with no
  //     notification clock (control cadences: back up, train, review) get none, and nothing is
  //     computed at all until the analyst sets a discovery date, because every clock starts on a
  //     legal determination rather than on a forensic timestamp.
  let complianceData = null;
  function loadCompliance(caseId) {
    fetch(`/cases/${caseId}/compliance`).then(r => r.ok ? r.json() : null).then(d => {
      complianceData = (d && typeof d === "object" && Array.isArray(d.results)) ? d : null;
      renderCompliance();
    }).catch(() => {});
  }
  let complianceTimer = null;
  function scheduleComplianceReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(complianceTimer);
    complianceTimer = setTimeout(() => loadCompliance(caseId), 800);
  }
  function patchComplianceControl(patch) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/compliance/control`, {
      method: "PATCH", headers: { "content-type": "application/json" },
      body: JSON.stringify(patch),
    }).then(r => r.ok ? r.json() : null).then(() => loadCompliance(caseId)).catch(() => {});
  }
  function setComplianceDiscovered(el) {
    // <input type="date"> gives "YYYY-MM-DD"; send it as an explicit UTC instant so the stored
    // value does not shift by a day depending on the viewer's timezone.
    const v = (el.value || "").trim();
    patchComplianceControl({ discoveredAt: v ? `${v}T00:00:00.000Z` : null });
  }
  function clearComplianceDiscovered() {
    const input = document.getElementById("complianceDiscovered");
    if (input) input.value = "";
    patchComplianceControl({ discoveredAt: null });
  }
  function toggleComplianceFramework() {
    const boxes = [...document.querySelectorAll("#complianceFilter input[type=checkbox]")];
    const checked = boxes.filter(b => b.checked).map(b => b.dataset.fw);
    // All boxes ticked === no filter at all (null), so the case does not carry a stale explicit
    // list that would silently hide a framework added to the dataset later.
    patchComplianceControl({ frameworks: checked.length === boxes.length ? null : checked });
  }
  function renderComplianceFilter(d) {
    const el = document.getElementById("complianceFilter");
    if (!el) return;
    const all = d.availableFrameworks || [];
    if (!all.length) { el.innerHTML = ""; return; }
    const active = Array.isArray(d.frameworks) ? new Set(d.frameworks) : null;
    el.innerHTML = `<span class="cmp-ctl-label">Frameworks</span>` + all.map(f =>
      `<label class="cmp-fw"><input type="checkbox" data-act="toggleComplianceFramework" data-act-on="change" data-fw="${escAttr(f)}"${!active || active.has(f) ? " checked" : ""}>${esc(f)}</label>`
    ).join("");
  }
  function renderCompliance() {
    const el = document.getElementById("compliancePanel");
    if (!el) return;
    const d = complianceData;
    if (!d) { el.innerHTML = `<div class="cmp-empty">—</div>`; return; }

    renderComplianceFilter(d);
    const input = document.getElementById("complianceDiscovered");
    if (input && d.discoveredAt) input.value = String(d.discoveredAt).slice(0, 10);
    const hint = document.getElementById("complianceDiscoveredHint");
    if (hint) {
      hint.textContent = d.discoveredAt
        ? "each clock starts on its own legal trigger — confirm the real start date with counsel"
        : "set a date to compute notification deadlines";
    }

    // The disclaimer leads, always — before a single obligation.
    const caveat = d.disclaimer ? `<div class="cmp-caveat">⚖️ ${esc(d.disclaimer)}</div>` : "";
    const editions = d.frameworkVersions
      ? `<div class="cmp-editions">Control identifiers drawn from: ${Object.entries(d.frameworkVersions).map(([k, v]) => `${esc(k)} ${esc(v)}`).join(" · ")}</div>`
      : "";

    if (!d.results.length) {
      el.innerHTML = caveat + `<div class="cmp-empty">No confirmed finding maps to a control failure in the bundled mapping.</div>` + editions;
      return;
    }

    const clocks = d.results.reduce((n, r) => n + r.frameworks.filter(f => f.notification).length, 0);
    const meta = `<div class="cmp-meta">${esc(d.results.length)} technique instance(s) with mapped obligations · ${esc(clocks)} notification obligation(s)${d.discoveredAt ? "" : " (no deadlines computed — no discovery date set)"}</div>`;

    const cards = d.results.map(r => {
      const u = attackUrl(r.technique);
      const id = u
        ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="cmp-tech-id">${esc(r.technique)}</a>`
        : `<span class="cmp-tech-id">${esc(r.technique)}</span>`;
      const groups = new Map();
      for (const row of r.frameworks) {
        const key = String(row.framework);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(row);
      }
      const body = [...groups.entries()].map(([fw, rows]) => {
        const items = rows.map(row => {
          const clock = row.notification
            ? `<div class="cmp-clock">${complianceDueBadge(row.deadline)}${row.deadline ? " · " : ""}${esc(row.notification.within)} ${row.notification.unit === "business" ? "business days" : "calendar time"}, from ${esc(row.notification.from)}</div>`
            : "";
          return `<div class="cmp-row"><span class="cmp-ctrl">${esc(row.control)}</span> <span class="cmp-title">${esc(row.title)}</span><div class="cmp-obl">${esc(row.obligation)}</div>${clock}</div>`;
        }).join("");
        return `<div class="cmp-fw-group"><div class="cmp-fw-h">${esc(fw)}</div>${items}</div>`;
      }).join("");
      return `<div class="cmp-tech"><div class="cmp-tech-h">${id}<span class="cmp-tech-finding">finding ${esc(r.findingId)}</span></div>${body}</div>`;
    }).join("");

    el.innerHTML = caveat + meta + cards + editions;
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.loadCompliance = loadCompliance;
  window.scheduleComplianceReload = scheduleComplianceReload;
  window.setComplianceDiscovered = setComplianceDiscovered;
  window.clearComplianceDiscovered = clearComplianceDiscovered;
  window.toggleComplianceFramework = toggleComplianceFramework;
})();
