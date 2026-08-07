// Section order and visibility (#238) — which dashboard panels are shown and in what order
// (#415 tier 3).
//
// The other half of the command-palette banner. Its own localStorage preferences, its own checkbox
// list, and no reference in either direction to the palette's action registry.
//
// NO INITIALIZER: everything here runs when the Settings panel asks for it.
(function () {
  function loadSectionsOrder() {
    try {
      return JSON.parse(localStorage.getItem(SECTIONS_ORDER_KEY) || "[]");
    } catch {
      return [];
    }
  }
  function saveSectionsOrder(ids) {
    localStorage.setItem(SECTIONS_ORDER_KEY, JSON.stringify(ids));
  }
  function getEffectiveOrder() {
    const saved = loadSectionsOrder();
    if (!saved.length) return [...SECTION_DEFS];
    const byId = Object.fromEntries(SECTION_DEFS.map((d) => [d.id, d]));
    const result = saved.filter((id) => byId[id]).map((id) => byId[id]);
    const savedSet = new Set(saved);
    // Insert any section missing from the saved order at its CANONICAL position (right after its
    // nearest preceding SECTION_DEFS sibling that's already placed) rather than dumping it at the
    // end — so a newly-added section (e.g. Playbook) appears where it's defined, not at the bottom.
    SECTION_DEFS.forEach((def, i) => {
      if (savedSet.has(def.id)) return;
      let insertAt = result.length;
      for (let j = i - 1; j >= 0; j--) {
        const idx = result.findIndex((d) => d.id === SECTION_DEFS[j].id);
        if (idx >= 0) {
          insertAt = idx + 1;
          break;
        }
      }
      result.splice(insertAt, 0, def);
    });
    return result;
  }
  function applySecOrder() {
    const main = document.querySelector("main");
    if (!main) return;
    getEffectiveOrder().forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el && el.parentElement === main) main.appendChild(el);
    });
  }

  function applySectionsVis() {
    applySecOrder();
    const vis = loadSectionsVis();
    SECTION_DEFS.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el)
        el.style.display =
          isSectionVisible(id, vis) && isSectionDataOpen(el) ? "" : "none";
    });
  }

  function renderSecChecks() {
    const container = document.getElementById("secChecks");
    if (!container) return;
    const vis = loadSectionsVis();
    const ordered = getEffectiveOrder();
    container.innerHTML = ordered
      .map(
        ({ id, label }) =>
          `<label class="sec-check" draggable="true" data-id="${esc(id)}"><span class="drag-handle" title="Drag to reorder">⠿</span><input type="checkbox" id="scb-${esc(id)}" ${isSectionVisible(id, vis) ? "checked" : ""}> ${esc(label)}</label>`,
      )
      .join("");
    let dragSrc = null;
    container.querySelectorAll(".sec-check").forEach((row) => {
      row.addEventListener("dragstart", (e) => {
        dragSrc = row;
        e.dataTransfer.effectAllowed = "move";
      });
      row.addEventListener("dragover", (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        if (row !== dragSrc) {
          container
            .querySelectorAll(".sec-check")
            .forEach((r) => r.classList.remove("drag-over"));
          row.classList.add("drag-over");
        }
      });
      row.addEventListener("dragleave", () =>
        row.classList.remove("drag-over"),
      );
      row.addEventListener("drop", (e) => {
        e.preventDefault();
        row.classList.remove("drag-over");
        if (dragSrc && dragSrc !== row) {
          container.insertBefore(dragSrc, row);
          saveSectionsOrder(
            [...container.querySelectorAll(".sec-check")].map(
              (r) => r.dataset.id,
            ),
          );
          applySecOrder();
          // Same as the in-page drag grip: a manual reorder here makes this a Custom layout, so
          // the next load's applySavedViewForCase() doesn't overwrite it with the active preset.
          if (typeof applyDashboardView === "function")
            applyDashboardView(null, { persist: true, rerender: false });
        }
      });
      row.addEventListener("dragend", () => {
        dragSrc = null;
        container
          .querySelectorAll(".sec-check")
          .forEach((r) => r.classList.remove("drag-over"));
      });
    });
  }

  window.saveSectionsOrder = saveSectionsOrder;
  window.getEffectiveOrder = getEffectiveOrder;
  window.applySecOrder = applySecOrder;
  window.applySectionsVis = applySectionsVis;
  window.renderSecChecks = renderSecChecks;
})();
