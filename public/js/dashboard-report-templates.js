// Report Templates (#60) — the global branded report layouts an analyst picks between, and the
// section list each one turns on (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the fetched template list, which one is being edited, the
// section rows in the editor, and the set of sections a template may not turn off. In a CLASSIC
// script — which this is, so a missing sibling cannot take the page down — those four top-level
// bindings would otherwise join the shared global lexical environment.
//
// ITS WIRING IS AN INITIALIZER even though the block runs nothing at load. Four controls (the
// picker, New, Save and Delete) were bound in the Settings block, and two of them — rtSave and
// rtDelete — were passed as VALUES, so with the functions moved out a 404 here would throw while
// the page parses rather than leaving one Settings tab inert.
(function () {
  // --- Report Templates (#60) — global branded report layouts, Settings → Report Templates ----
  // Section keys + labels mirror REPORT_SECTION_DEFS in reportTemplate.ts (the server is the source
  // of truth; this is just the editor UI). The order here is the canonical default order.
  const RT_SECTIONS = [
    ["titlePage", "Title / cover page"],
    ["reportMetadata", "1 · Report metadata"],
    ["executiveSummary", "2 · Executive summary"],
    ["businessImpact", "2.1 · Business Impact Analysis"],
    ["investigationLimitations", "2.2 · Investigation limitations"],
    ["investigationGoals", "2.3 · Investigation goals & targets"],
    ["glossary", "2.4 · Glossary of terms"],
    ["timeline", "3 · Timeline of events"],
    ["investigation", "4 · Investigation"],
    ["conclusions", "5 · Conclusions & recommendations"],
    ["sessions", "Attacker Sessions (the timeline as per-host chapters)"],
    ["hypotheses", "Hypotheses"],
    ["playbook", "Response Playbook"],
    ["d3fend", "Mitigation & defensive countermeasures (ATT&CK + D3FEND)"],
    [
      "compliance",
      "Compliance Impact (control failures & notification obligations)",
    ],
    ["notebook", "Analyst Notebook"],
    ["chainOfCustody", "Chain of Custody (per-artifact custody chain)"],
  ];
  const RT_LABELS = Object.fromEntries(RT_SECTIONS);
  let rtTemplates = []; // last fetched list of templates
  let rtCurrentId = ""; // id of the template being edited ("" = new/unsaved)
  let rtEditSections = []; // [{ key, enabled }] for the editor, ordered
  let rtRequiredSections = new Set();

  function loadReportTemplates(selectId) {
    return fetch("/report-templates")
      .then((r) => (r.ok ? r.json() : []))
      .then((list) => {
        rtTemplates = Array.isArray(list) ? list : [];
        const picker = document.getElementById("rtPicker");
        picker.innerHTML =
          rtTemplates
            .map(
              (t) =>
                `<option value="${escAttr(t.id)}">${esc(t.name || t.id)}${t.builtIn ? (t.customized ? " (built-in, edited)" : " (built-in)") : ""}</option>`,
            )
            .join("") + `<option value="">✚ New custom template…</option>`;
        const pick =
          selectId !== undefined
            ? selectId
            : rtTemplates.some((t) => t.id === rtCurrentId)
              ? rtCurrentId
              : rtTemplates[0]
                ? rtTemplates[0].id
                : "";
        picker.value = pick;
        rtFillEditor(pick);
      })
      .catch(() => {});
  }

  function rtFindTemplate(id) {
    return rtTemplates.find((t) => t.id === id);
  }

  // Populate the editor form from a template (or blank defaults for a new one).
  function rtFillEditor(id) {
    const t = rtFindTemplate(id);
    rtCurrentId = t ? t.id : "";
    const v = (elId, val) => {
      document.getElementById(elId).value = val == null ? "" : val;
    };
    v("rtName", t ? t.name : "");
    v("rtDescription", t ? t.description : "");
    const accent = (t && t.accentColor) || "#2d6cdf";
    v("rtAccent", accent);
    try {
      document.getElementById("rtAccentPick").value = accent;
    } catch (e) {}
    v("rtCoverTitle", t ? t.coverTitle : "Incident Investigation Report");
    v("rtCoverSubtitle", t ? t.coverSubtitle : "");
    v("rtHeaderText", t ? t.headerText : "");
    v("rtFooterText", t ? t.footerText : "");
    document.getElementById("rtShowLogo").checked = t
      ? t.showLogo !== false
      : true;
    document.getElementById("rtShowCompanyName").checked = t
      ? t.showCompanyName !== false
      : true;
    const releaseReq = t?.releaseRequirements || {};
    document.getElementById("rtRequireIndependentReview").checked =
      releaseReq.requireIndependentReview === true;
    document.getElementById("rtRequireEvidenceLinks").checked =
      releaseReq.requireEvidenceLinks === true;
    rtRequiredSections = new Set(
      Array.isArray(releaseReq.requiredSections)
        ? releaseReq.requiredSections
        : [],
    );
    // Sections: start from the template's order (full coverage guaranteed server-side) or the default.
    const src =
      t && Array.isArray(t.sections) && t.sections.length
        ? t.sections
        : RT_SECTIONS.map(([key]) => ({ key, enabled: true }));
    rtEditSections = src
      .filter((s) => RT_LABELS[s.key])
      .map((s) => ({ key: s.key, enabled: s.enabled !== false }));
    // Append any missing canonical key (enabled), mirroring normalizeSections.
    for (const [key] of RT_SECTIONS)
      if (!rtEditSections.some((s) => s.key === key))
        rtEditSections.push({ key, enabled: true });
    const del = document.getElementById("rtDeleteBtn");
    del.textContent = t && t.builtIn ? "Reset to default" : "Delete";
    del.style.display = t ? "" : "none";
    document.getElementById("rtSaveBtn").textContent =
      t && t.builtIn ? "Save (override built-in)" : "Save template";
    document.getElementById("rtMsg").textContent = "";
    rtRenderSections();
  }

  function rtRenderSections() {
    const el = document.getElementById("rtSections");
    el.innerHTML = rtEditSections
      .map(
        (s, i) =>
          `<div data-safe-style="display:flex;align-items:center;gap:8px;padding:3px 4px;border-bottom:1px solid #1a1f28;font-size:12px">` +
          `<input type="checkbox" class="rt-sec-en" data-i="${i}" ${s.enabled ? "checked" : ""} data-safe-style="width:auto;margin:0" />` +
          `<span data-safe-style="flex:1;${s.enabled ? "" : "color:#7e8aa0"}">${esc(RT_LABELS[s.key] || s.key)}</span>` +
          `<label title="Block release unless this section is included" data-safe-style="display:flex;align-items:center;gap:3px;color:var(--text-muted)"><input type="checkbox" class="rt-sec-req" data-i="${i}" ${rtRequiredSections.has(s.key) ? "checked" : ""} data-safe-style="width:auto;margin:0" /> require</label>` +
          `<button type="button" class="rt-sec-up" data-i="${i}" title="Move up" ${i === 0 ? "disabled" : ""} data-safe-style="background:#2a2f3a;border:none;color:#cbd3df;border-radius:4px;padding:0 7px;cursor:pointer">▲</button>` +
          `<button type="button" class="rt-sec-down" data-i="${i}" title="Move down" ${i === rtEditSections.length - 1 ? "disabled" : ""} data-safe-style="background:#2a2f3a;border:none;color:#cbd3df;border-radius:4px;padding:0 7px;cursor:pointer">▼</button>` +
          `</div>`,
      )
      .join("");
    el.querySelectorAll(".rt-sec-en").forEach((cb) =>
      cb.addEventListener("change", (e) => {
        const section = rtEditSections[+e.target.dataset.i];
        section.enabled = e.target.checked;
        if (!section.enabled) rtRequiredSections.delete(section.key);
        rtRenderSections();
      }),
    );
    el.querySelectorAll(".rt-sec-req").forEach((cb) =>
      cb.addEventListener("change", (e) => {
        const section = rtEditSections[+e.target.dataset.i];
        if (e.target.checked) {
          rtRequiredSections.add(section.key);
          section.enabled = true;
        } else rtRequiredSections.delete(section.key);
        rtRenderSections();
      }),
    );
    el.querySelectorAll(".rt-sec-up").forEach((b) =>
      b.addEventListener("click", (e) =>
        rtMoveSection(+e.currentTarget.dataset.i, -1),
      ),
    );
    el.querySelectorAll(".rt-sec-down").forEach((b) =>
      b.addEventListener("click", (e) =>
        rtMoveSection(+e.currentTarget.dataset.i, 1),
      ),
    );
  }

  function rtMoveSection(i, dir) {
    const j = i + dir;
    if (j < 0 || j >= rtEditSections.length) return;
    const tmp = rtEditSections[i];
    rtEditSections[i] = rtEditSections[j];
    rtEditSections[j] = tmp;
    rtRenderSections();
  }

  function rtSave() {
    const name = document.getElementById("rtName").value.trim();
    const msg = document.getElementById("rtMsg");
    if (!name) {
      msg.textContent = "name is required";
      return;
    }
    const body = {
      id: rtCurrentId || undefined,
      name,
      description: document.getElementById("rtDescription").value.trim(),
      accentColor: document.getElementById("rtAccent").value.trim(),
      coverTitle: document.getElementById("rtCoverTitle").value,
      coverSubtitle: document.getElementById("rtCoverSubtitle").value,
      headerText: document.getElementById("rtHeaderText").value,
      footerText: document.getElementById("rtFooterText").value,
      showLogo: document.getElementById("rtShowLogo").checked,
      showCompanyName: document.getElementById("rtShowCompanyName").checked,
      sections: rtEditSections,
      releaseRequirements: {
        requiredSections: [...rtRequiredSections],
        requireIndependentReview: document.getElementById(
          "rtRequireIndependentReview",
        ).checked,
        requireEvidenceLinks: document.getElementById("rtRequireEvidenceLinks")
          .checked,
      },
    };
    msg.textContent = "saving…";
    fetch("/report-templates", {
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
        loadReportTemplates(saved.id);
        refreshCaseTemplatePicker();
      })
      .catch(
        (e) =>
          (msg.textContent =
            "save failed: " +
            e.message +
            " — restart the companion server if this 404s"),
      );
  }

  function rtDelete() {
    if (!rtCurrentId) return;
    const t = rtFindTemplate(rtCurrentId);
    const msg = document.getElementById("rtMsg");
    const verb =
      t && t.builtIn
        ? "Reset this built-in template to its shipped default?"
        : "Delete this template?";
    if (!confirm(verb)) return;
    msg.textContent = "…";
    fetch("/report-templates/" + encodeURIComponent(rtCurrentId), {
      method: "DELETE",
    })
      .then((r) => {
        if (!r.ok && r.status !== 204) throw new Error("HTTP " + r.status);
        rtCurrentId = "";
        loadReportTemplates();
        refreshCaseTemplatePicker();
        msg.textContent = "";
      })
      .catch((e) => (msg.textContent = "failed: " + e.message));
  }

  // The four controls the Settings block used to bind. Order unchanged.
  function initReportTemplates() {
    document
      .getElementById("rtPicker")
      .addEventListener("change", (e) => rtFillEditor(e.target.value));
    document.getElementById("rtNewBtn").addEventListener("click", () => {
      document.getElementById("rtPicker").value = "";
      rtFillEditor("");
      document.getElementById("rtName").focus();
    });
    document.getElementById("rtSaveBtn").addEventListener("click", rtSave);
    document.getElementById("rtDeleteBtn").addEventListener("click", rtDelete);
  }

  window.loadReportTemplates = loadReportTemplates;
  window.rtFillEditor = rtFillEditor;
  window.rtSave = rtSave;
  window.rtDelete = rtDelete;
  window.initReportTemplates = initReportTemplates;
})();
