// Case activity log (#415 tier 3) (#415 tier 3).
//
// THE FILTER WIRING IS AN INITIALIZER, NOT AN IIFE. In the inline script it ran immediately,
// which was safe there because that block runs after the markup. This file is a <head> script:
// the same code at load would query for #activityFilter before it exists, find nothing, and
// wire no listener — a filter that silently never filters. The page calls initActivityLog()
// once everything is parsed.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  const ACTIVITY_CATEGORY_LABELS = {
    import: "Import",
    triage: "Mark/Unmark",
    ai: "AI run",
    enrichment: "Enrichment",
    anonymization: "Anonymization",
    settings: "Settings",
    playbook: "Playbook",
    collaboration: "Comment/Tag",
    hunt: "Hunt",
    export: "Export",
  };
  let activityFilterValue = "";
  function renderActivityLog(entries) {
    const el = document.getElementById("activityLogPanel");
    if (!el) return;
    if (!entries.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px'>No activity recorded yet.</div>";
      return;
    }
    el.innerHTML =
      "<table data-safe-style='width:100%;font-size:12px;border-collapse:collapse'>" +
      entries
        .map(
          (
            e,
          ) => `<tr data-safe-style="border-bottom:1px solid var(--border-color)">
        <td data-safe-style="padding:4px 8px;white-space:nowrap;color:var(--text-muted)" title="${escAttr(e.timestamp)}">${activityTimeAgo(e.timestamp)}</td>
        <td data-safe-style="padding:4px 8px;white-space:nowrap">${esc(ACTIVITY_CATEGORY_LABELS[e.category] || e.category)}</td>
        <td data-safe-style="padding:4px 8px;white-space:nowrap;color:var(--text-muted)">${esc(e.actor)}</td>
        <td data-safe-style="padding:4px 8px">${esc(e.detail)}</td>
        <td data-safe-style="padding:4px 8px;white-space:nowrap">${e.outcome === "error" ? "<span data-safe-style='color:#e5484d'>error</span>" : ""}</td>
      </tr>`,
        )
        .join("") +
      "</table>";
  }
  function loadActivityLog(caseId) {
    const qs = activityFilterValue
      ? `?category=${encodeURIComponent(activityFilterValue)}`
      : "";
    fetch(`/cases/${caseId}/activity-log${qs}`)
      .then((r) => (r.ok ? r.json() : []))
      .then(renderActivityLog)
      .catch(() => {});
  }
  function initActivityLog() {
    const sel = document.getElementById("activityFilter");
    if (!sel) return;
    Object.entries(ACTIVITY_CATEGORY_LABELS).forEach(([value, label]) => {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = label;
      sel.appendChild(opt);
    });
    sel.addEventListener("change", () => {
      activityFilterValue = sel.value;
      const caseId = document.getElementById("caseId").value.trim();
      if (caseId) loadActivityLog(caseId);
    });
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.loadActivityLog = loadActivityLog;
  window.initActivityLog = initActivityLog;
})();
