// Dashboard Views (#142) — the global panel-layout presets an analyst switches between, and the
// editor deciding which sections each one shows (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the fetched view list, which view is being edited, and the
// section rows in the editor. In a CLASSIC script those three would be page-wide globals.
//
// NOT "Dashboard view presets (#142)", which is a separate and larger block that APPLIES a view to
// the page. They share an issue number, not a boundary.
(function () {
  // --- Dashboard Views (#142) — global panel-layout presets, Settings → Dashboard Views ----------
  let dvViews = []; // last fetched list of views (with builtIn/customized flags)
  let dvCurrentId = ""; // id of the view being edited ("" = new/unsaved)
  let dvEditSections = []; // [{ id, enabled }] over all sections, ordered (enabled = visible in this view)

  function loadDashboardViewsEditor(selectId) {
    // Populate the report-template choices FIRST (so dvFillEditor's value sticks), then the views.
    return fetch("/report-templates")
      .then((r) => (r.ok ? r.json() : []))
      .then((list) => {
        const sel = document.getElementById("dvReportTemplate");
        if (sel)
          sel.innerHTML =
            `<option value="">(none)</option>` +
            (Array.isArray(list) ? list : [])
              .map(
                (t) =>
                  `<option value="${escAttr(t.id)}">${esc(t.name || t.id)}</option>`,
              )
              .join("");
      })
      .catch(() => {})
      .then(() =>
        fetch("/dashboard-views").then((r) =>
          r.ok ? r.json() : { views: [] },
        ),
      )
      .then((j) => {
        dvViews = Array.isArray(j.views) ? j.views : [];
        const picker = document.getElementById("dvPicker");
        picker.innerHTML =
          dvViews
            .map(
              (v) =>
                `<option value="${escAttr(v.id)}">${esc(v.name || v.id)}${v.builtIn ? (v.customized ? " (built-in, edited)" : " (built-in)") : ""}</option>`,
            )
            .join("") + `<option value="">✚ New custom view…</option>`;
        const pick =
          selectId !== undefined
            ? selectId
            : dvViews.some((v) => v.id === dvCurrentId)
              ? dvCurrentId
              : dvViews[0]
                ? dvViews[0].id
                : "";
        picker.value = pick;
        dvFillEditor(pick);
      })
      .catch(() => {});
  }

  function dvFindView(id) {
    return dvViews.find((v) => v.id === id);
  }
  function dvSectionLabel(id) {
    const d = SECTION_DEFS.find((s) => s.id === id);
    return d ? d.label : id;
  }

  function dvFillEditor(id) {
    const v = dvFindView(id);
    dvCurrentId = v ? v.id : "";
    const set = (elId, val) => {
      const el = document.getElementById(elId);
      if (el) el.value = val == null ? "" : val;
    };
    set("dvName", v ? v.name : "");
    set("dvDescription", v ? v.description : "");
    set("dvMinSeverity", (v && v.filters && v.filters.minSeverity) || "");
    set("dvTopN", (v && v.filters && v.filters.topN) || "");
    set("dvReportTemplate", (v && v.reportTemplateId) || "");
    // Sections: the view's visible ids first (enabled, in order), then the rest (disabled) in canonical order.
    const visible =
      v && Array.isArray(v.sections)
        ? v.sections.filter((sid) => SECTION_DEFS.some((d) => d.id === sid))
        : [];
    const visibleSet = new Set(visible);
    dvEditSections = visible.map((sid) => ({ id: sid, enabled: true }));
    for (const d of SECTION_DEFS)
      if (!visibleSet.has(d.id))
        dvEditSections.push({ id: d.id, enabled: false });
    const del = document.getElementById("dvDeleteBtn");
    del.textContent = v && v.builtIn ? "Reset to default" : "Delete";
    del.style.display = v ? "" : "none";
    document.getElementById("dvSaveBtn").textContent =
      v && v.builtIn ? "Save (override built-in)" : "Save view";
    document.getElementById("dvMsg").textContent = "";
    dvRenderSections();
  }

  function dvRenderSections() {
    const el = document.getElementById("dvSections");
    el.innerHTML = dvEditSections
      .map(
        (s, i) =>
          `<div data-safe-style="display:flex;align-items:center;gap:8px;padding:3px 4px;border-bottom:1px solid #1a1f28;font-size:12px">` +
          `<input type="checkbox" class="dv-sec-en" data-i="${i}" ${s.enabled ? "checked" : ""} data-safe-style="width:auto;margin:0" />` +
          `<span data-safe-style="flex:1;${s.enabled ? "" : "color:#7e8aa0"}">${esc(dvSectionLabel(s.id))}</span>` +
          `<button type="button" class="dv-sec-up" data-i="${i}" title="Move up" ${i === 0 ? "disabled" : ""} data-safe-style="background:#2a2f3a;border:none;color:#cbd3df;border-radius:4px;padding:0 7px;cursor:pointer">▲</button>` +
          `<button type="button" class="dv-sec-down" data-i="${i}" title="Move down" ${i === dvEditSections.length - 1 ? "disabled" : ""} data-safe-style="background:#2a2f3a;border:none;color:#cbd3df;border-radius:4px;padding:0 7px;cursor:pointer">▼</button>` +
          `</div>`,
      )
      .join("");
    el.querySelectorAll(".dv-sec-en").forEach((cb) =>
      cb.addEventListener("change", (e) => {
        dvEditSections[+e.target.dataset.i].enabled = e.target.checked;
        dvRenderSections();
      }),
    );
    el.querySelectorAll(".dv-sec-up").forEach((b) =>
      b.addEventListener("click", (e) =>
        dvMoveSection(+e.currentTarget.dataset.i, -1),
      ),
    );
    el.querySelectorAll(".dv-sec-down").forEach((b) =>
      b.addEventListener("click", (e) =>
        dvMoveSection(+e.currentTarget.dataset.i, 1),
      ),
    );
  }

  function dvMoveSection(i, dir) {
    const j = i + dir;
    if (j < 0 || j >= dvEditSections.length) return;
    const tmp = dvEditSections[i];
    dvEditSections[i] = dvEditSections[j];
    dvEditSections[j] = tmp;
    dvRenderSections();
  }

  function dvSave() {
    const name = document.getElementById("dvName").value.trim();
    const msg = document.getElementById("dvMsg");
    if (!name) {
      msg.textContent = "name is required";
      return;
    }
    const sections = dvEditSections.filter((s) => s.enabled).map((s) => s.id);
    if (!sections.length) {
      msg.textContent = "select at least one section to show";
      return;
    }
    const minSeverity =
      document.getElementById("dvMinSeverity").value || undefined;
    const topNraw = parseInt(document.getElementById("dvTopN").value, 10);
    const topN = Number.isFinite(topNraw) && topNraw > 0 ? topNraw : undefined;
    const reportTemplateId =
      document.getElementById("dvReportTemplate").value || undefined;
    const body = {
      id: dvCurrentId || undefined,
      name,
      description: document.getElementById("dvDescription").value.trim(),
      sections,
      filters: { minSeverity, topN },
      reportTemplateId,
    };
    msg.textContent = "saving…";
    fetch("/dashboard-views", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((saved) => {
        msg.textContent = "saved ✓";
        setTimeout(() => (msg.textContent = ""), 2000);
        loadDashboardViewsEditor(saved.id);
        loadDashboardViews();
      })
      .catch(
        (e) =>
          (msg.textContent =
            "save failed: " +
            e.message +
            " — restart the companion server if this 404s"),
      );
  }

  function dvDelete() {
    if (!dvCurrentId) return;
    const v = dvFindView(dvCurrentId);
    const msg = document.getElementById("dvMsg");
    const verb =
      v && v.builtIn
        ? "Reset this built-in view to its shipped default?"
        : "Delete this view?";
    if (!confirm(verb)) return;
    msg.textContent = "…";
    fetch("/dashboard-views/" + encodeURIComponent(dvCurrentId), {
      method: "DELETE",
    })
      .then((r) => {
        if (!r.ok && r.status !== 204) throw new Error("HTTP " + r.status);
        dvCurrentId = "";
        loadDashboardViewsEditor();
        loadDashboardViews();
        msg.textContent = "";
      })
      .catch((e) => (msg.textContent = "failed: " + e.message));
  }

  // The four controls the Settings block used to bind. Order unchanged.
  function initDashboardViewsEditor() {
    document
      .getElementById("dvPicker")
      .addEventListener("change", (e) => dvFillEditor(e.target.value));
    document.getElementById("dvNewBtn").addEventListener("click", () => {
      document.getElementById("dvPicker").value = "";
      dvFillEditor("");
      document.getElementById("dvName").focus();
    });
    document.getElementById("dvSaveBtn").addEventListener("click", dvSave);
    document.getElementById("dvDeleteBtn").addEventListener("click", dvDelete);
  }

  window.loadDashboardViewsEditor = loadDashboardViewsEditor;
  window.dvFillEditor = dvFillEditor;
  window.dvSave = dvSave;
  window.dvDelete = dvDelete;
  window.initDashboardViewsEditor = initDashboardViewsEditor;
})();
