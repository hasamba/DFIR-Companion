// Timeline Gaps (#83) — the stretches of wall-clock time the evidence says nothing about
// (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the last-computed gap list and the debounce timer that
// coalesces reload requests. In a CLASSIC script those two would be page-wide globals.
//
// NO INITIALIZER: nothing here runs at load, and nothing outside binds one of these functions while
// the page parses — the panel is refreshed from the reload chain and from the WebSocket handler,
// both of which are calls rather than bindings.
(function () {
  // ── Timeline Gaps (#83) ───────────────────────────────────────────────────────────────
  // Suspiciously long silent periods in the forensic timeline. A COMPLETE gap (every source dark)
  // is the classic signature of cleared logs / a stopped collector → High; a PARTIAL gap is one tool
  // going quiet while others keep logging → Medium. Derived server-side (GET /cases/:id/timeline-gaps)
  // from the in-scope timeline; re-derived (debounced) on each state change, like the phases panel.
  // A lead, NOT proof of tampering.
  let timelineGapsData = [];
  let timelineGapsTimer = null;
  function loadTimelineGaps(caseId) {
    fetch(`/cases/${caseId}/timeline-gaps`)
      .then((r) => r.json())
      .then((g) => {
        timelineGapsData = Array.isArray(g) ? g : [];
        renderTimelineGaps();
      })
      .catch(() => {});
  }
  function scheduleTimelineGapsReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(timelineGapsTimer);
    timelineGapsTimer = setTimeout(() => loadTimelineGaps(caseId), 800);
  }

  function renderTimelineGaps() {
    const el = document.getElementById("timelineGaps");
    if (!el) return;
    if (!timelineGapsData.length) {
      el.innerHTML =
        "<span data-safe-style='color:var(--text-muted)'>No suspicious silent periods detected in the forensic timeline.</span>";
      return;
    }
    const rows = timelineGapsData
      .map((g) => {
        const sevColor = KC_SEV_COLOR[g.severity] || "var(--border-color)";
        const kind = g.complete
          ? "<span title='Every source went silent — the classic log-tampering signature' data-safe-style='color:var(--sev-critical);font-weight:bold'>complete silence</span>"
          : "<span title='One tool went quiet while others kept logging — a coverage blindspot' data-safe-style='color:var(--text-muted)'>partial</span>";
        const silent =
          g.silentSources && g.silentSources.length
            ? g.silentSources.map(esc).join(", ")
            : "all sources";
        const active =
          g.activeSources && g.activeSources.length
            ? g.activeSources.map(esc).join(", ")
            : "<span data-safe-style='color:var(--text-muted)'>—</span>";
        return (
          `<tr>` +
          `<td><span class="sev-${esc(g.severity)}" data-safe-style="color:${sevColor};font-weight:bold">${esc(g.severity)}</span></td>` +
          `<td>${kind}</td>` +
          `<td title="${escAttr((g.startTimestamp || "") + " → " + (g.endTimestamp || ""))}"><strong>${esc(g.durationLabel)}</strong></td>` +
          `<td data-safe-style="color:var(--text-muted);font-size:11px">${esc(g.startTimestamp || "")} → ${esc(g.endTimestamp || "")}</td>` +
          `<td>${silent}</td>` +
          `<td>${active}</td>` +
          `</tr>`
        );
      })
      .join("");
    el.innerHTML =
      `<div data-safe-style="color:var(--text-muted);font-size:11px;margin-bottom:6px">A coverage gap is a lead, not proof — an analyst may have collected logs for a limited window, or activity genuinely paused. A gap where every source went silent is the classic signature of cleared logs or a stopped collector; confirm against the collection scope and host clocks.</div>` +
      `<div class="vql-result-wrap"><table class="vql-result"><thead><tr>` +
      `<th>Severity</th><th>Type</th><th>Duration</th><th>When</th><th>Silent sources</th><th>Still active</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  // Gap Hypotheses (#96) moved to js/dashboard-gap-hypotheses.js (#415 tier 3). No initializer:
  // nothing here runs at load. A missing file is reported through DfirFacade.filled, below.

  window.loadTimelineGaps = loadTimelineGaps;
  window.scheduleTimelineGapsReload = scheduleTimelineGapsReload;
})();
