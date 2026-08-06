// Command palette registry (#238) — the list of actions the palette offers, and jumping to the
// section an action belongs to (#415 tier 3).
//
// SPLIT FROM THE SECTION-ORDER CODE that shares its banner. The two clusters the cohesion check
// reported are the palette's action table and the sections' order/visibility preferences; nothing
// in one calls anything in the other.
//
// `window.DfirPaletteConfig` is published as an INITIALIZER rather than at module scope, because
// this is a <head> script and the assignment has to happen once, in order, where the inline block
// used to do it. Both fields stay thunks: the registry and DfirState.lastState() are re-read on
// every open, so a palette opened before the case loads is correct the moment it does.
(function () {
  // ── Command palette registry (issue #238) ────────────────────────────────────────────────────
  // The matching, ranking and overlay live in /js/command-palette.js; only the registry lives
  // here, because this is the only scope that can see the dashboard's own functions and state.
  //
  // Almost every entry is DERIVED from a control that already exists — the section list, the two
  // export <select>s, the toolbar buttons — rather than transcribed into a parallel list. A
  // hand-written registry is stale the day someone adds a panel or an export, and stale entries
  // are worse than missing ones: they point at ids that no longer resolve.

  // The un-collapse + scroll idiom used by the panel deep-links elsewhere in this file.
  function revealSection(id) {
    const sec = document.getElementById(id);
    if (!sec) return;
    sec.classList.remove("collapsed");
    sec.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Curated entries: the toolbar controls, driven by .click() so each one reuses the handler that
  // is already wired to it. Availability comes free — buttons the dashboard hides or disables for
  // the current case state (2nd opinion, undo import, lifecycle, demo seed) drop out of the
  // palette on their own, with no second copy of the gating logic to keep in sync.
  const PALETTE_BUTTONS = [
    {
      id: "act.synthesize",
      btn: "synthesize",
      category: "Actions",
      label: "AI Re-synthesize",
      keywords: ["synthesize", "ai", "analysis", "rerun"],
    },
    {
      id: "act.deepPass",
      btn: "deepPassBtn",
      category: "Actions",
      label: "Run Deep Pass",
      keywords: ["deep", "pass", "reasoning"],
    },
    {
      id: "act.secondOpinion",
      btn: "secondOpinion",
      category: "Actions",
      label: "Second Opinion",
      keywords: ["second", "opinion", "review", "model"],
    },
    {
      id: "act.import",
      btn: "importBtn",
      category: "Actions",
      label: "Import Evidence",
      keywords: ["import", "ingest", "upload", "evidence"],
    },
    {
      id: "act.importUndo",
      btn: "importUndoBtn",
      category: "Actions",
      label: "Undo Import",
      keywords: ["undo", "import", "revert"],
    },
    {
      id: "act.importRedo",
      btn: "importRedoBtn",
      category: "Actions",
      label: "Redo Import",
      keywords: ["redo", "import"],
    },
    {
      id: "act.present",
      btn: "presentBtn",
      category: "Actions",
      label: "Presentation Mode",
      keywords: ["present", "slides", "deck", "briefing"],
    },
    {
      id: "nav.filter",
      btn: "toggleSearchBar",
      category: "Navigation",
      label: "Search & Filter",
      keywords: ["search", "filter", "find", "query"],
    },
    {
      id: "nav.toggleAll",
      btn: "toggleAll",
      category: "Navigation",
      label: "Collapse / Expand All Sections",
      keywords: ["collapse", "expand", "all", "sections"],
    },
    {
      id: "nav.jobs",
      btn: "jobsBadge",
      category: "Navigation",
      label: "Background Jobs",
      keywords: ["jobs", "queue", "background", "tasks"],
    },
    {
      id: "set.settings",
      btn: "settingsBtn",
      category: "Settings",
      label: "Open Settings",
      keywords: ["settings", "preferences", "config", "options"],
    },
    {
      id: "set.theme",
      btn: "themeToggle",
      category: "Settings",
      label: "Change Theme",
      keywords: [
        "theme",
        "dark",
        "light",
        "appearance",
        "colour",
        "color",
        "nord",
        "gruvbox",
      ],
    },
    {
      id: "set.ai",
      btn: "aiToggle",
      category: "Settings",
      label: "Toggle AI",
      keywords: ["ai", "llm", "enable", "disable"],
    },
    {
      id: "set.enrich",
      btn: "enrichToggle",
      category: "Settings",
      label: "Toggle Enrichment",
      keywords: ["enrich", "threatintel", "lookup"],
    },
    {
      id: "set.anon",
      btn: "anonToggle",
      category: "Settings",
      label: "Toggle Anonymization",
      keywords: ["anon", "anonymize", "redact", "privacy"],
    },
    {
      id: "set.views",
      btn: "dashViewBtn",
      category: "Settings",
      label: "Dashboard Views",
      keywords: ["view", "layout", "dashboard", "saved"],
    },
    {
      id: "set.manual",
      btn: "helpBtn",
      category: "Settings",
      label: "Open User Manual",
      keywords: ["help", "manual", "docs", "documentation"],
    },
    {
      id: "case.new",
      btn: "newCaseBtn",
      category: "Case",
      label: "New Case",
      keywords: ["new", "case", "create"],
    },
    {
      id: "case.connect",
      btn: "connect",
      category: "Case",
      label: "Connect to Case",
      keywords: ["connect", "open", "switch", "case"],
    },
    {
      id: "case.import",
      btn: "importCaseBtn",
      category: "Case",
      label: "Import Case",
      keywords: ["import", "case", "restore"],
    },
    {
      id: "case.lifecycle",
      btn: "lifecycleBtn",
      category: "Case",
      label: "Case Lifecycle (archive, close, delete)",
      keywords: ["archive", "close", "delete", "lifecycle", "status"],
    },
    {
      id: "case.demo",
      btn: "seedDemoBtn",
      category: "Case",
      label: "Seed Demo Case",
      keywords: ["demo", "seed", "sample", "example"],
    },
  ];

  // Turns the options of one toolbar <select> into actions. Running one sets the value and fires
  // change, which is exactly what picking it with the mouse does — the existing onchange handler
  // stays the single implementation of every export.
  function paletteSelectActions(selectId, idPrefix, keywords, gate) {
    const sel = document.getElementById(selectId);
    if (!sel) return [];
    return [...sel.options]
      .filter((o) => o.value)
      .map((o) => ({
        id: idPrefix + o.value,
        label: o.textContent.replace(/…\s*$/, "").trim(),
        category: "Exports",
        keywords: keywords,
        available: () => gate() && !o.disabled && !sel.disabled,
        run: () => {
          sel.value = o.value;
          sel.dispatchEvent(new Event("change"));
        },
      }));
  }

  function buildPaletteActions() {
    const vis = loadSectionsVis(); // read once per keystroke, not once per panel
    const caseIdEl = document.getElementById("caseId");
    const hasCase = () => !!(caseIdEl && caseIdEl.value.trim());

    const nav = SECTION_DEFS.map((s) => ({
      id: "nav." + s.id,
      label: "Go to " + s.label,
      category: "Navigation",
      keywords: paletteSectionKeywords(s.label),
      // A panel the analyst has switched off in Settings is not somewhere to jump to.
      available: () =>
        !!document.getElementById(s.id) && isSectionVisible(s.id, vis),
      run: () => revealSection(s.id),
    }));

    const buttons = PALETTE_BUTTONS.map((b) => ({
      id: b.id,
      label: b.label,
      category: b.category,
      keywords: b.keywords,
      available: () => {
        const el = document.getElementById(b.btn);
        return paletteVisible(el) && !el.disabled;
      },
      run: () => document.getElementById(b.btn).click(),
    }));

    // Every export needs a connected case — the onchange handler bails without one, so offering
    // them on an empty dashboard would produce actions that silently do nothing.
    const exports = paletteSelectActions(
      "exportSelect",
      "exp.",
      ["export", "download", "save"],
      hasCase,
    );
    const pushes = paletteSelectActions(
      "pushSelect",
      "push.",
      ["push", "send", "integration"],
      () => hasCase() && paletteVisible(document.getElementById("pushSelect")),
    );

    const extras = [
      {
        id: "set.shortcuts",
        label: "Keyboard Shortcuts",
        category: "Settings",
        keywords: ["keyboard", "shortcuts", "keys", "cheat", "help"],
        run: () => kbdOpenHelp(),
      },
    ];

    return [...nav, ...buttons, ...exports, ...pushes, ...extras];
  }

  // Published as a global rather than passed in a call because module scripts run AFTER this
  // inline one — the palette module reads this when it loads, so neither side has to wait on the
  // other. Both fields are thunks: the registry and `DfirState.lastState()` are re-read on every keystroke,
  // so a palette opened before the case loads is correct the moment it does.

  // The statement the inline block ran at module scope.
  function initPaletteConfig() {
    window.DfirPaletteConfig = {
      actions: buildPaletteActions,
      state: () => DfirState.lastState(),
    };
  }

  window.revealSection = revealSection;
  window.buildPaletteActions = buildPaletteActions;
  window.initPaletteConfig = initPaletteConfig;
})();
