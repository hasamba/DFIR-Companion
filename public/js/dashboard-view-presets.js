// Dashboard view presets (#142) — the saved panel layouts an analyst switches between, and
// applying one to the page (#415 tier 3).
//
// SPLIT FROM THE .env SETTINGS CODE that shared its heading. The cohesion check reported clusters
// of 12, 6, 3 and 1; the 12 is this, and the rest are the settings save path.
//
// NOT the "Dashboard Views editor (#142)" already extracted — that edits the presets, this applies
// them. Same issue number, different feature.
(function () {
  // ── Timeline row display toggles ───────────────────────────────────────────
  // Per-browser choice of which sub-elements appear in each forensic-timeline event row.
  // Timeline row display toggles moved to js/dashboard-timeline-display.js (#415 tier 3).
  // re-arranges panels (reusing the section show/hide + order machinery above) and applies a
  // severity / top-N filter to the findings list and forensic timeline. The choice is remembered
  // per-case in this browser. "Custom" = no preset (your own layout, no view filter).
  // (DASHBOARD_VIEWS is up top with the render-state globals; the active view is in DfirState.)
  const RT_FRIENDLY = {
    standard: "Standard report",
    "executive-brief": "Executive Brief",
    "technical-detailed": "Technical Detailed",
  };
  function viewStorageKey() {
    const c = (document.getElementById("caseId").value || "").trim();
    return c ? "dfir.dashView." + c : "";
  }
  function viewFilters() {
    const v = DfirState.activeView();
    return (v && v.filters) || {};
  }
  // True when a severity is at or above the active view's threshold. Fails OPEN (unknown
  // severity / no threshold → shown) — missing a real finding is worse than one extra row.
  function viewMeetsMinSev(sev) {
    const min = viewFilters().minSeverity;
    if (!min) return true;
    const mi = SEV.indexOf(min);
    if (mi < 0) return true;
    const si = SEV.indexOf(sev);
    if (si < 0) return true;
    return si <= mi;
  }
  function viewTopN() {
    const n = viewFilters().topN;
    return typeof n === "number" && n > 0 ? n : 0;
  }

  // Friendly label for the active view's matching report template (built-in names; custom ids show raw).
  function dashViewReportLabel() {
    const view = DfirState.activeView();
    if (!view || !view.reportTemplateId) return "";
    return RT_FRIENDLY[view.reportTemplateId] || "matching report";
  }
  function updateDashViewButton() {
    const btn = document.getElementById("dashViewBtn");
    if (!btn) return;
    const view = DfirState.activeView();
    btn.classList.toggle("dv-on", !!view);
    btn.title = view
      ? `Dashboard view: ${view.name} — click to switch or edit`
      : "Dashboard view: Custom — click to choose a layout preset";
  }
  function closeDashViewMenu() {
    const m = document.getElementById("dashViewMenu");
    if (m) m.style.display = "none";
    const b = document.getElementById("dashViewBtn");
    if (b) b.setAttribute("aria-expanded", "false");
  }
  // Build the popover: Custom + every view (active ticked), then a divider, the matching-report
  // action (only when the active view has one), and "Edit views…".
  function renderDashViewMenu() {
    const m = document.getElementById("dashViewMenu");
    if (!m) return;
    const tick = (on) => `<span class="dv-tick">${on ? "✓" : ""}</span>`;
    const rows = [];
    const view = DfirState.activeView();
    rows.push(
      `<div class="dv-item ${!view ? "dv-active" : ""}" data-view="">${tick(!view)}Custom <small>(your layout)</small></div>`,
    );
    for (const v of DASHBOARD_VIEWS) {
      const active = !!view && view.id === v.id;
      const tag = v.customized
        ? " <small>(edited)</small>"
        : v.builtIn
          ? ""
          : " <small>(custom)</small>";
      rows.push(
        `<div class="dv-item ${active ? "dv-active" : ""}" data-view="${escAttr(v.id)}" title="${escAttr(v.description || "")}">${tick(active)}${esc(v.name)}${tag}</div>`,
      );
    }
    rows.push(`<div class="dv-sep"></div>`);
    const repLabel = dashViewReportLabel();
    if (repLabel)
      rows.push(
        `<div class="dv-item dv-item-action" data-action="report">↳ Generate ${esc(repLabel)}</div>`,
      );
    rows.push(
      `<div class="dv-item dv-item-action" data-action="edit">✎ Edit views…</div>`,
    );
    m.innerHTML = rows.join("");
    m.querySelectorAll(".dv-item").forEach((el) =>
      el.addEventListener("click", () => {
        const action = el.dataset.action;
        if (action === "edit") {
          closeDashViewMenu();
          openDashViewEditor();
          return;
        }
        if (action === "report") {
          closeDashViewMenu();
          generateViewReport();
          return;
        }
        const id = el.dataset.view;
        const v = id ? DASHBOARD_VIEWS.find((x) => x.id === id) : null;
        closeDashViewMenu();
        applyDashboardView(v, { persist: true, rerender: true });
      }),
    );
  }
  function openDashViewEditor() {
    openSettingsTab("dashboard-views");
  }
  // Set the per-case report template to the active view's match, then fire the normal report export.
  async function generateViewReport() {
    const view = DfirState.activeView();
    if (!view || !view.reportTemplateId) return;
    const c = (document.getElementById("caseId").value || "").trim();
    if (!c) return;
    try {
      await fetch(`/cases/${encodeURIComponent(c)}/report-template`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ templateId: view.reportTemplateId }),
      });
    } catch {}
    const tsel = document.getElementById("rm-reportTemplate");
    if (tsel) tsel.value = view.reportTemplateId;
    const ex = document.getElementById("exportSelect");
    if (ex) {
      ex.value = "report";
      ex.dispatchEvent(new Event("change"));
    }
  }

  // Apply a view's curated layout: its `sections` list = the VISIBLE sections (in order),
  // everything else hidden. We write the SAME localStorage keys the Settings → sections editor
  // uses, so the two stay in sync and the layout survives reloads / re-renders.
  function applyViewLayout(view) {
    if (!view || !Array.isArray(view.sections) || !view.sections.length) return;
    const want = view.sections.filter((id) =>
      SECTION_DEFS.some((d) => d.id === id),
    );
    const wantSet = new Set(want);
    const prev = loadSectionsVis();
    const vis = {};
    SECTION_DEFS.forEach(({ id }) => {
      // A data-gated section (e.g. Memory Next Steps) is never part of a view's curated list —
      // its own evidence gate decides whether it can appear at all — so "absent from the view"
      // must NOT be read as "hide it", which would pin it off even once its evidence lands.
      // Carry the analyst's existing choice through untouched instead.
      const el = document.getElementById(id);
      if (el && el.dataset.gateOpen !== undefined) {
        if (prev[id] !== undefined) vis[id] = prev[id];
        return;
      }
      vis[id] = wantSet.has(id);
    });
    // Order: the view's visible sections first (in its order), then the rest (hidden) in their
    // canonical order so re-enabling one later lands it somewhere sensible.
    const order = [
      ...want,
      ...SECTION_DEFS.map((d) => d.id).filter((id) => !wantSet.has(id)),
    ];
    localStorage.setItem(SECTIONS_VIS_KEY, JSON.stringify(vis));
    localStorage.setItem(SECTIONS_ORDER_KEY, JSON.stringify(order));
    applySectionsVis();
    renderSecChecks(); // keep the Settings checkboxes in sync if the modal is open
  }

  function applyDashboardView(view, opts) {
    opts = opts || {};
    // Applying a layout ends any palette detour (the reveal set in js/dashboard-section-order.js).
    //
    // THIS IS THE SEAM, not applyViewLayout(), because "Custom" applies no layout at all — the call
    // below is skipped when view is null — and two paths reach Custom: the view menu, and
    // applySavedViewForCase() restoring a case whose saved preference is Custom. A reveal left
    // standing across either reads as part of the layout, and across the second it follows the
    // analyst into the NEXT CASE, which is a different investigation.
    //
    // opts.keepReveals is the one exception, for the drag handlers. They pass null to record "this
    // is a Custom layout now" as a side effect of a REORDER, not to apply a layout — and the
    // analyst may be dragging the very panel they just revealed, so making it vanish mid-drag would
    // be worse than the mismatch this clear exists to prevent.
    if (!opts.keepReveals && typeof clearSectionReveals === "function")
      clearSectionReveals();
    DfirState.setActiveView(view);
    if (view) applyViewLayout(view);
    updateDashViewButton();
    renderDashViewMenu();
    if (opts.persist !== false) {
      const k = viewStorageKey();
      // An explicit "Custom" pick is stored as a marker (not removed) so it stays distinct from a
      // case that has never had a view chosen — the latter falls back to the default view below.
      if (k) localStorage.setItem(k, view ? view.id : CUSTOM_VIEW_MARKER);
    }
    if (opts.rerender !== false && DfirState.lastState())
      render(DfirState.lastState());
  }

  // Re-apply the per-case saved view (no persist, no forced re-render — the caller's state fetch
  // renders shortly and picks up the filter; we just set the active view + section visibility now).
  function applySavedViewForCase() {
    const k = viewStorageKey();
    if (!k || !DASHBOARD_VIEWS.length) return;
    const id = localStorage.getItem(k);
    // No key at all = a new case / new install with no preference yet -> default to Now.
    // The CUSTOM_VIEW_MARKER = an explicit "Custom" pick, which stays Custom.
    const view =
      id === null
        ? DASHBOARD_VIEWS.find((v) => v.id === DEFAULT_DASHBOARD_VIEW_ID) ||
          null
        : id === CUSTOM_VIEW_MARKER
          ? null
          : DASHBOARD_VIEWS.find((v) => v.id === id) || null;
    applyDashboardView(view, { persist: false, rerender: false });
  }

  function loadDashboardViews() {
    return fetch("/dashboard-views")
      .then((r) => (r.ok ? r.json() : { views: [] }))
      .then((j) => {
        DASHBOARD_VIEWS = Array.isArray(j.views) ? j.views : [];
        applySavedViewForCase();
        renderDashViewMenu();
        updateDashViewButton();
      })
      .catch(() => {});
  }

  // The statements the inline block ran at module scope, in order.
  function initViewPresets() {
    {
      const btn = document.getElementById("dashViewBtn");
      const menu = document.getElementById("dashViewMenu");
      if (btn && menu) {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          if (menu.style.display !== "none") {
            closeDashViewMenu();
            return;
          }
          renderDashViewMenu();
          menu.style.display = "block";
          btn.setAttribute("aria-expanded", "true");
        });
        document.addEventListener("click", (e) => {
          if (
            menu.style.display !== "none" &&
            !menu.contains(e.target) &&
            !btn.contains(e.target)
          )
            closeDashViewMenu();
        });
        document.addEventListener("keydown", (e) => {
          if (e.key === "Escape") closeDashViewMenu();
        });
      }
    }
    loadDashboardViews();
  }

  window.viewFilters = viewFilters;
  window.viewMeetsMinSev = viewMeetsMinSev;
  window.viewTopN = viewTopN;
  window.applyDashboardView = applyDashboardView;
  window.applySavedViewForCase = applySavedViewForCase;
  window.loadDashboardViews = loadDashboardViews;
  window.initViewPresets = initViewPresets;
})();
