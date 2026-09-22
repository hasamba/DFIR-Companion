// Case picker — the toolbar box shows the case NAME (#1523).
//
// The dashboard reads the open case's id from #caseId in ~200 places, and the extension, deep
// links and localStorage all carry the id too. So the id stays where it is: #caseId is now a
// hidden input, and #casePicker is the visible box the analyst types in and picks from. This
// module keeps the two in step — a pick or a keystroke in the picker resolves to an id and lands
// in #caseId (with the input/change events its listeners expect), and anything that sets #caseId
// directly calls syncCasePicker() so the box shows that case's name.
//
// Text the analyst types that matches no case is passed through as an id, exactly as the old box
// did: Connect creates a case by that id. Two cases with the same name are listed as `name (id)`
// so a pick is never ambiguous.
(function () {
  let byId = new Map(); // caseId -> the text the picker shows for it
  let byText = new Map(); // that text -> caseId

  function displayTextFor(c, dupNames) {
    const name = String(c.name || "").trim();
    if (!name || name === c.caseId) return c.caseId;
    return dupNames.has(name) ? `${name} (${c.caseId})` : name;
  }

  function dupNamesOf(cases) {
    const seen = new Set();
    const dups = new Set();
    for (const c of cases) {
      const name = String(c.name || "").trim();
      if (!name) continue;
      if (seen.has(name)) dups.add(name);
      seen.add(name);
    }
    return dups;
  }

  // Populate the datalist with existing cases from the server, so the field shows a dropdown of
  // available cases while still accepting free text. Safe on older servers / offline — it just
  // leaves the field as free text.
  function loadCaseList() {
    return fetch("/cases")
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((cases) => {
        const showArchived = document.getElementById("showArchivedToggle")?.checked;
        const dl = document.getElementById("caseList");
        if (!dl) return;
        dl.innerHTML = "";
        const nextById = new Map();
        const nextByText = new Map();
        const dups = dupNamesOf(cases);
        for (const c of cases) {
          const text = displayTextFor(c, dups);
          nextById.set(c.caseId, text);
          nextByText.set(text, c.caseId);
          if (c.status === "archived" && !showArchived) continue;
          const o = document.createElement("option");
          o.value = text;
          // a lock prefix marks password-protected cases, an [Archived] prefix marks cases moved
          // to _archived/ (both can apply at once); shown beside the name, never typed into it
          const lockPrefix = c.hasPassword ? "\u{1F512} " : "";
          if (c.status === "archived") o.label = `[Archived] ${lockPrefix}${text}`;
          else if (c.hasPassword) o.label = lockPrefix + text;
          dl.appendChild(o);
        }
        byId = nextById;
        byText = nextByText;
        syncCasePicker();
        // The "Demo case" button is an onboarding affordance — show it only on an empty instance.
        const demoBtn = document.getElementById("seedDemoBtn");
        if (demoBtn) demoBtn.style.display = cases.length === 0 ? "" : "none";
      })
      .catch(() => {});
  }

  function resolveCaseId(text) {
    const t = String(text || "").trim();
    if (byText.has(t)) return byText.get(t);
    const m = /\(([^()]+)\)$/.exec(t); // `name (id)` typed by hand or half-edited
    if (m && byId.has(m[1])) return m[1];
    return t;
  }

  // Make the visible box show the name of whatever id #caseId holds. Called after every
  // programmatic write to #caseId and after each list refresh (a freshly created case's name is
  // only known once the list has it).
  function syncCasePicker() {
    const picker = document.getElementById("casePicker");
    const idEl = document.getElementById("caseId");
    if (!picker || !idEl) return;
    const id = idEl.value.trim();
    picker.value = byId.get(id) || id;
  }

  function pushPickerToCaseId() {
    const picker = document.getElementById("casePicker");
    const idEl = document.getElementById("caseId");
    if (!picker || !idEl) return;
    const id = resolveCaseId(picker.value);
    if (idEl.value === id) return;
    idEl.value = id;
    // Listeners on #caseId (the hunt workbench reloads its saved hunts on a case change) fire on
    // user input only; a programmatic write is silent, so replay the events by hand.
    idEl.dispatchEvent(new Event("input", { bubbles: true }));
    idEl.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function initCasePicker() {
    const picker = document.getElementById("casePicker");
    if (!picker) return;
    picker.addEventListener("input", pushPickerToCaseId);
    picker.addEventListener("change", pushPickerToCaseId);
    picker.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      pushPickerToCaseId();
      if (typeof connect === "function") connect();
    });
    // A <datalist> filters its suggestions by the field's current text, so a pre-filled name hides
    // every other case. On focus: refresh the list and clear the box so the FULL dropdown shows;
    // on blur, restore the prior text if the analyst didn't pick or type one. #caseId is untouched
    // while the box is empty, so a focus-then-blur is not a case change.
    let prev = "";
    picker.addEventListener("focus", () => {
      loadCaseList();
      prev = picker.value;
      picker.value = "";
    });
    picker.addEventListener("blur", () => {
      if (!picker.value.trim()) picker.value = prev;
    });
    document.getElementById("showArchivedToggle")?.addEventListener("change", loadCaseList);
  }

  window.initCasePicker = initCasePicker;
  window.loadCaseList = loadCaseList;
  window.syncCasePicker = syncCasePicker;
})();
