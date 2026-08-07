// Attack Phases (temporal bursts, grouped by time gap, derived server-side, no AI) — extracted
// from dashboard.html (issue #415, tier 3).
//
// Reunited first: renderPhases and its click handler had been separated from loadPhases by 230
// lines of IOC provenance code that shared the banner for no reason. Splitting that banner took
// this block from five state escapes to one.
//
// That one is phasesData, and both readers are the same line in two refresh paths:
// `if (phasesData.length) renderPhases()`. They are asking whether there is anything to redraw,
// so they ask hasPhases(). A stub answers falsy and the refresh simply skips this panel.
(function () {
  "use strict";

  let phasesData = [];
  const phOpen = new Set(); // ids of expanded phases — persist across re-renders
  let phasesTimer = null;

  function loadPhases(caseId) {
    fetch(`/cases/${caseId}/phases`)
      .then((r) => r.json())
      .then((p) => {
        phasesData = Array.isArray(p) ? p : [];
        renderPhases();
      })
      .catch(() => {});
  }
  // State changes (imports / synthesis) re-derive the phases — debounced, like the graphs.
  function schedulePhasesReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(phasesTimer);
    phasesTimer = setTimeout(() => loadPhases(caseId), 800);
  }

  // Per-IOC corroboration (#35 Phase 3): { iocId: [tools that observed it] }, derived server-side
  // from the forensic events' sources. Powers the "⊕ N sources" badge in the IOC panel.
  function renderPhases() {
    const el = document.getElementById("phases");
    if (!el) return;
    if (!phasesData.length) {
      el.innerHTML =
        "<span data-safe-style='color:var(--text-muted)'>No dated events to group into phases yet.</span>";
      return;
    }
    // Event details for expansion come from the in-scope timeline already on the page.
    const evById = {};
    for (const e of DfirState.lastFt() || []) evById[String(e.id)] = e;
    // Honor the global search-bar filter: keep only each phase's matching events, and drop phases
    // with none — so "I searched an IP" narrows the phases the same way it narrows the timeline.
    const filtered = _hasActiveFilter();
    const rows = phasesData
      .map((p, i) => {
        const ids = (p.eventIds || []).map(String);
        const matchIds = filtered
          ? ids.filter((id) => {
              const e = evById[id];
              return e && _matchesGlobalFilter(e);
            })
          : ids;
        if (filtered && !matchIds.length) return ""; // hide phases with no events matching the filter
        const color = KC_SEV_COLOR[p.maxSeverity] || "var(--border-color)";
        const when =
          p.endTimestamp && p.endTimestamp !== p.startTimestamp
            ? `${esc(p.startTimestamp)} → ${esc(p.endTimestamp)}`
            : esc(p.startTimestamp || "(undated)");
        const isOpen = phOpen.has(p.id);
        const ttps = (p.inferredTechniques || []).length;
        const evRows = matchIds
          .map((id) => {
            const e = evById[String(id)];
            if (!e)
              return `<div class="ph-ev-row"><span class="ph-ev-desc" data-safe-style="color:var(--text-muted)">${esc(String(id))}</span></div>`;
            const desc = String(e.description || "")
              .replace(/\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i, "")
              .replace(/\s*\[more\]$/, "");
            return (
              `<div class="ph-ev-row">` +
              `<span class="ph-ev-time sev-${esc(e.severity)}">${esc(e.timestamp || "(undated)")}</span>` +
              `<span class="ph-ev-desc">${esc(desc)}</span>` +
              `${e.mitreTechniques && e.mitreTechniques.length ? `<small class="kc-ev-mitre">${mitreLinks(e.mitreTechniques)}</small>` : ""}` +
              `</div>`
            );
          })
          .join("");
        const countMeta = filtered
          ? `${matchIds.length} of ${p.eventCount} event${p.eventCount === 1 ? "" : "s"} match`
          : `${esc(p.eventCount)} event${p.eventCount === 1 ? "" : "s"}${ttps ? ` · ${esc(ttps)} TTP${ttps === 1 ? "" : "s"}` : ""}`;
        return (
          `<div class="ph-row${isOpen ? " ph-open" : ""}">` +
          `<div class="ph-head" data-safe-style="border-left-color:${color}" data-phid="${escAttr(p.id)}">` +
          `<span class="ph-caret">▶</span>` +
          `<span class="ph-num">${i + 1}.</span>` +
          `<span class="ph-label" data-safe-style="color:${color}">${esc(p.label)}</span>` +
          `<span class="ph-when">${when}</span>` +
          `<span class="ph-meta">${countMeta}</span>` +
          `</div>` +
          `<div class="ph-events"${isOpen ? "" : " hidden"}>${evRows || "<span data-safe-style='color:var(--text-muted)'>No events.</span>"}</div>` +
          `</div>`
        );
      })
      .join("");
    el.innerHTML = `<div class="ph-list">${rows || "<span data-safe-style='color:var(--text-muted)'>No phases match the filter.</span>"}</div>`;
  }

  // Expand/collapse a phase to reveal its events (event-delegated; survives re-renders).

  // The refresh fan-out's question: is there anything to redraw?
  function hasPhases() {
    return phasesData.length > 0;
  }

  // Delegated expand/collapse on the phase list — binds to markup, so it is load-time work.
  function initAttackPhases() {
    document.getElementById("phases").addEventListener("click", function (e) {
      const head = e.target.closest(".ph-head");
      if (!head) return;
      const id = head.dataset.phid;
      if (phOpen.has(id)) phOpen.delete(id);
      else phOpen.add(id);
      renderPhases();
    });
  }

  window.initAttackPhases = initAttackPhases;
  window.loadPhases = loadPhases;
  window.schedulePhasesReload = schedulePhasesReload;
  window.renderPhases = renderPhases;
  window.hasPhases = hasPhases;
})();
