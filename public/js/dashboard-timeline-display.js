// Timeline row display toggles — which columns and badges each timeline row shows (#415 tier 3).
//
// ITS WIRING IS AN INITIALIZER: the checkbox list plus Select all / Deselect all, bound at module
// scope in the page. In a <head> script they would query #tlDisplayChecks before it exists.
(function () {
  // ── Timeline row display toggles ───────────────────────────────────────────
  // Per-browser choice of which sub-elements appear in each forensic-timeline event row.
  // The timestamp + message are always shown ("the event itself"); everything else is opt-out.
  // Default = all ON (current behavior). Read by renderTimelineEvents via tlShow().
  const TL_DISPLAY_KEY = "dfir.tlDisplay";
  const TL_FIELDS = [
    [
      "icons",
      "Action icons (★ star · 💬 comment · 🏷 tag · 🔍 hunt · 💡 explain · 📍 map)",
    ],
    ["tags", "Analyst tag pills"],
    ["badges", "Badges (×count · ⊕ sources · chain · NEW)"],
    ["host", "Host / asset chip"],
    ["mitre", "MITRE techniques"],
    ["findings", "Related findings"],
    ["evidence", "Evidence links"],
  ];
  function loadTlDisplay() {
    try {
      return JSON.parse(localStorage.getItem(TL_DISPLAY_KEY) || "{}");
    } catch {
      return {};
    }
  }
  // A field is shown unless the user explicitly turned it off (default ON).
  function tlShow(key, d) {
    d = d || loadTlDisplay();
    return d[key] !== false;
  }
  function saveTlDisplay(d) {
    try {
      localStorage.setItem(TL_DISPLAY_KEY, JSON.stringify(d));
    } catch {}
  }
  function renderTlChecks() {
    const container = document.getElementById("tlDisplayChecks");
    if (!container) return;
    const d = loadTlDisplay();
    container.innerHTML = TL_FIELDS.map(
      ([key, label]) =>
        `<label class="sec-check" data-safe-style="cursor:pointer"><input type="checkbox" class="tl-disp-cb" data-key="${esc(key)}" ${tlShow(key, d) ? "checked" : ""}> ${esc(label)}</label>`,
    ).join("");
  }
  // Apply the checkbox states → localStorage and re-render the timeline immediately.
  function applyTlDisplayFromChecks() {
    const d = {};
    document.querySelectorAll("#tlDisplayChecks .tl-disp-cb").forEach((cb) => {
      d[cb.dataset.key] = cb.checked;
    });
    saveTlDisplay(d);
    if (typeof DfirState.lastFt() !== "undefined")
      renderTimelineEvents(DfirState.lastFt());
  }

  // The controls the page bound at module scope. Order unchanged.
  function initTimelineDisplay() {
    document
      .getElementById("tlDisplayChecks")
      .addEventListener("change", applyTlDisplayFromChecks);
    document.getElementById("tlSelectAll").addEventListener("click", () => {
      document
        .querySelectorAll("#tlDisplayChecks .tl-disp-cb")
        .forEach((cb) => {
          cb.checked = true;
        });
      applyTlDisplayFromChecks();
    });
    document.getElementById("tlDeselectAll").addEventListener("click", () => {
      document
        .querySelectorAll("#tlDisplayChecks .tl-disp-cb")
        .forEach((cb) => {
          cb.checked = false;
        });
      applyTlDisplayFromChecks();
    });
  }

  window.loadTlDisplay = loadTlDisplay;
  window.renderTlChecks = renderTlChecks;
  window.applyTlDisplayFromChecks = applyTlDisplayFromChecks;
  window.tlShow = tlShow;
  window.initTimelineDisplay = initTimelineDisplay;
})();
