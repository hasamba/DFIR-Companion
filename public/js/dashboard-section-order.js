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
  // Put the sections in their configured order, MOVING ONLY THE ONES THAT ARE OUT OF PLACE.
  //
  // The obvious version of this — appendChild() every section in order — is not a no-op when the
  // order already matches. appendChild() on a node that is already a child is defined as a REMOVE
  // followed by an INSERT, so every section left the document for an instant on every call. That
  // is fine at init and ruinous afterwards, because render() reaches here on every redraw
  // (render -> renderCollectionPlan -> applySectionsVis -> applySecOrder). Removing the section
  // the viewport is sitting on makes Chrome blur whatever had focus inside it and reset
  // window.scrollY to 0: one click on a findings filter, and the analyst was thrown back to the
  // top of a fifty-section page. Every other control that re-renders — the confidence floor, the
  // corroboration lenses — did the same thing.
  //
  // So walk the desired order against the children already there and only call insertBefore for a
  // section that is genuinely in the wrong place. An unchanged order now touches the DOM zero
  // times, and a real reorder still moves the minimum.
  function applySecOrder() {
    const main = document.querySelector("main");
    if (!main) return;
    const ordered = getEffectiveOrder()
      .map(({ id }) => document.getElementById(id))
      .filter((el) => el && el.parentElement === main);
    // Children that no section def claims (and any section rendered outside the ordered list) keep
    // their relative order ahead of the ordered run — which is where appendChild() left them, since
    // it only ever moved sections to the end.
    const orderedSet = new Set(ordered);
    const want = [
      ...Array.prototype.filter.call(
        main.children,
        (el) => !orderedSet.has(el),
      ),
      ...ordered,
    ];
    // `cursor` is the child currently occupying the slot `el` must end up in. If it is already the
    // right node, step over it and touch nothing; otherwise insert `el` in front of it, which
    // leaves `cursor` sitting on the next slot for the following iteration.
    let cursor = main.firstElementChild;
    for (const el of want) {
      if (el === cursor) {
        cursor = cursor.nextElementSibling;
        continue;
      }
      main.insertBefore(el, cursor);
    }
  }

  // Sections the analyst reached from the command palette during THIS page load.
  //
  // The palette has to be able to jump to a panel the active dashboard view hides — that is what it
  // is for. The obvious way, writing `true` into SECTIONS_VIS_KEY, is wrong: that key cannot record
  // intent. applyViewLayout() stamps `false` on every section a view omits, and saveSettings()
  // stamps an explicit true/false on EVERY section on any Settings save, whatever the analyst was
  // actually changing. So neither an explicit `false` nor an absent entry tells you whether anyone
  // decided anything, and a palette jump that wrote to it would be editing a layout preference the
  // analyst never expressed — permanently and browser-wide, since one key covers every case and no
  // later write undoes a data-gated entry.
  //
  // Holding the reveal in memory makes it exactly what it claims to be: a detour for this page load.
  // The stored preference is untouched, the Settings checkbox keeps showing the real one, and a
  // reload puts the layout back. The two moves that ARE explicit layout decisions — switching view
  // and saving Settings — clear the set, so neither is fought by a stale reveal.
  const sessionRevealed = new Set();

  // Both mutators REPAINT, because the set is not what the analyst sees — display:none is written by
  // applySectionsVis(), and mutating the set without re-running it changes nothing. Leaving that to
  // callers cost three review rounds on the clear alone, so neither half leaves it to them now.
  function markSectionRevealed(id) {
    if (sessionRevealed.has(id)) return;
    sessionRevealed.add(id);
    applySectionsVis();
  }
  // The clear is the half that proved it: the case-connect boundary called no repaint at all, and
  // the per-case restore passes rerender:false, so the Custom path had none either — both then
  // depended on an async render that the connect path swallows on failure. The policy was right and
  // the screen was still stale.
  //
  // The early return keeps this free: with nothing revealed there is nothing to undo, which is the
  // usual case on a view switch or a Settings save.
  function clearSectionReveals() {
    if (!sessionRevealed.size) return;
    sessionRevealed.clear();
    applySectionsVis();
  }

  function applySectionsVis() {
    applySecOrder();
    const vis = loadSectionsVis();
    SECTION_DEFS.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el)
        el.style.display =
          (isSectionVisible(id, vis) || sessionRevealed.has(id)) &&
          isSectionDataOpen(el)
            ? ""
            : "none";
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
          // It keeps any palette reveal, though — the analyst may be dragging that very panel.
          if (typeof applyDashboardView === "function")
            applyDashboardView(null, {
              persist: true,
              rerender: false,
              keepReveals: true,
            });
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
  window.markSectionRevealed = markSectionRevealed;
  window.clearSectionReveals = clearSectionReveals;
  window.renderSecChecks = renderSecChecks;
})();
