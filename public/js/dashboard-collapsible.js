// Collapsible + reorderable dashboard sections — extracted from dashboard.html (issue #415,
// tier 3). Collapse state and section order are keyed by content-div id and persisted, so a
// layout survives reloads; render() only rewrites the inner divs, never the <section>/<h2>.
//
// This block was reported as blocked on a `sections` escape for most of #415, and it never was.
// `const sections = () => [...]` is a FUNCTION, and the inventory was counting it as state
// because of the keyword that declared it. Three other modules declare their own local
// `sections`, and the scope-blind sibling scan counted those as needing ours published too.
// Both are fixed in this commit; what is left to publish is two names.
(function () {
  "use strict";

  // Click a section header to collapse/expand it; state is keyed by the section's
  // content-div id and persisted so your layout survives reloads. render() only
  // rewrites the inner divs (not the <section>/<h2>), so collapse state sticks.
  const COLLAPSE_KEY = "dfir.collapsed";
  const sections = () => [...document.querySelectorAll("main > section")];
  // Prefer the section's DIRECT-child content div as its key, so nested controls (e.g. the
  // manual add-entry forms with their own input ids) don't shadow it.
  const sectionKey = (sec) => {
    const el = sec.querySelector(":scope > [id]") || sec.querySelector("[id]");
    return el ? el.id : "";
  };
  const loadCollapsed = () => {
    try {
      return JSON.parse(localStorage.getItem(COLLAPSE_KEY) || "{}");
    } catch {
      return {};
    }
  };
  const saveCollapsed = (map) =>
    localStorage.setItem(COLLAPSE_KEY, JSON.stringify(map));

  // Drag-to-reorder sections (via the ⠿ grip on a section header). The order is persisted to the
  // SAME authoritative store as the Settings → section-list reorder (SECTIONS_ORDER_KEY, keyed by
  // <section> id) — NOT a separate key — so the two ordering systems can't fight. On load the order
  // is applied by applySectionsVis() → applySecOrder() (which runs last in init), so a drag survives
  // a refresh. render() rewrites inner divs (not <section>s), so a reordered layout sticks.
  function setupReorder() {
    const main = document.querySelector("main");
    let dragged = null;
    sections().forEach((sec) => {
      const h2 = sec.querySelector("h2");
      if (h2 && !h2.querySelector(".drag-grip")) {
        const grip = document.createElement("span");
        grip.className = "drag-grip";
        grip.textContent = "⠿";
        grip.title = "Drag to reorder this section";
        grip.setAttribute("draggable", "true");
        grip.addEventListener("click", (e) => e.stopPropagation()); // don't toggle collapse
        grip.addEventListener("dragstart", (e) => {
          dragged = sec;
          sec.classList.add("dragging");
          e.dataTransfer.effectAllowed = "move";
          try {
            e.dataTransfer.setData("text/plain", sectionKey(sec));
          } catch {}
        });
        grip.addEventListener("dragend", () => {
          sec.classList.remove("dragging");
          sections().forEach((s) => s.classList.remove("drop-target"));
          dragged = null;
        });
        h2.insertBefore(grip, h2.firstChild);
      }
      sec.addEventListener("dragover", (e) => {
        if (!dragged || dragged === sec) return;
        e.preventDefault();
        sec.classList.add("drop-target");
      });
      sec.addEventListener("dragleave", () =>
        sec.classList.remove("drop-target"),
      );
      sec.addEventListener("drop", (e) => {
        e.preventDefault();
        sec.classList.remove("drop-target");
        if (!dragged || dragged === sec) return;
        const r = sec.getBoundingClientRect();
        const after = e.clientY - r.top > r.height / 2; // drop in the lower half → place after
        main.insertBefore(dragged, after ? sec.nextSibling : sec);
        // Persist to the authoritative order store (by <section> id) that the load path applies
        // last — the same store the Settings section-list reorder writes — so the drag survives a
        // refresh and the two systems agree. renderSecChecks() re-reads it, so the Settings list
        // and its up/down arrows reflect the new order too.
        saveSectionsOrder(
          [...main.querySelectorAll(":scope > section[id]")].map((s) => s.id),
        );
        if (typeof renderSecChecks === "function") renderSecChecks();
        // A manual drag makes this a Custom layout — otherwise the next page load's
        // applySavedViewForCase() re-applies the active preset's canned order over this one,
        // silently discarding the drag (the layout looked "reset" after refresh).
        if (typeof applyDashboardView === "function")
          applyDashboardView(null, { persist: true, rerender: false });
      });
    });
    // The initial order is applied by applySectionsVis() → applySecOrder() (runs last in init),
    // so no separate apply here (a second, key-mismatched apply is exactly what caused #6).
  }

  function updateToggleAllLabel() {
    const anyOpen = sections().some((s) => !s.classList.contains("collapsed"));
    document.getElementById("toggleAll").textContent = anyOpen
      ? "Collapse all"
      : "Expand all";
  }

  function setupCollapsible() {
    const collapsed = loadCollapsed();
    sections().forEach((sec) => {
      const h2 = sec.querySelector("h2");
      if (!h2) return;
      const key = sectionKey(sec);
      if (!h2.querySelector(".chev"))
        h2.insertAdjacentHTML("afterbegin", '<span class="chev">▾</span>');
      if (key && collapsed[key]) sec.classList.add("collapsed");
      h2.onclick = (e) => {
        // Don't collapse when the click landed on an interactive control living inside the header
        // (filter toggles like "⚠ Flagged only" / "☆ Starred", the + add-toggle, dropdown buttons,
        // severity checkboxes). Those are driven by their own listeners — some delegated on <main>,
        // an ANCESTOR of this h2 — so the click bubbles here first and would collapse the section,
        // hiding the very list the filter just rendered (the cause of "1 flagged but list empty").
        if (e.target.closest("button, input, select, a, label")) return;
        sec.classList.toggle("collapsed");
        const map = loadCollapsed();
        if (key) map[key] = sec.classList.contains("collapsed");
        saveCollapsed(map);
        updateToggleAllLabel();
      };
    });
    updateToggleAllLabel();
  }

  // Moved to js/dashboard-data-act.js (#415 tier 3).

  // #toggleAll and the initial paint. Both need the <main> sections to exist, so neither can run
  // at module scope in a <head> script.
  function initCollapsible() {
    document.getElementById("toggleAll").onclick = () => {
      const collapseAll = sections().some(
        (s) => !s.classList.contains("collapsed"),
      ); // collapse if anything is open
      const map = loadCollapsed();
      sections().forEach((sec) => {
        sec.classList.toggle("collapsed", collapseAll);
        const key = sectionKey(sec);
        if (key) map[key] = collapseAll;
      });
      saveCollapsed(map);
      updateToggleAllLabel();
    };
  }

  window.initCollapsible = initCollapsible;
  window.setupCollapsible = setupCollapsible;
  window.setupReorder = setupReorder;
})();
