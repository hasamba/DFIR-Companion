// Vim-style keyboard navigation for the Forensic Timeline (#415 tier 3).
//
// j/k to move, f to flag, i to add as IOC, p to pin, n to note, ? for help — plus the focus ring
// that tracks which row the keyboard is on.
//
// ITS BANNER COVERS A WIRING RUN THAT IS MOSTLY NOT ITS OWN. Fifteen statements run at load under
// that heading; four are the keyboard's. The severity legend, the timeline listeners, the
// confidence filter, the collection-plan click handler and five self-calling IIFEs all stay.
//
// The fourth one nearly did not come. `#miValue`'s Escape handler looks like part of the manual-IOC
// form until you read it: it clears `_kbdIocFormAutoOpened`, the one-shot that records whether the
// keyboard opened that form. Escape has to undo what `i` did, so the handler belongs here.
//
// IIFE-WRAPPED BECAUSE IT OWNS FOCUS STATE: which event row the keyboard is on, and that one-shot.
(function () {
  // --- Vim-style keyboard navigation (Forensic Timeline) ----------------------
  const KBD_SHORTCUTS_KEY = "dfir.kbdShortcuts.enabled";
  function kbdShortcutsEnabled() {
    const v = localStorage.getItem(KBD_SHORTCUTS_KEY);
    return v === null ? true : v === "1";
  }
  function setKbdShortcutsEnabled(on) {
    localStorage.setItem(KBD_SHORTCUTS_KEY, on ? "1" : "0");
  }

  let focusedEventId = null; // currently vim-focused timeline row (session-only, cleared on re-render)

  function kbdVisibleRows() {
    return [...document.querySelectorAll("#forensicTimeline .ev-row")];
  }

  function kbdSetFocus(id) {
    const prev = document.querySelector("#forensicTimeline .ev-row.ev-focused");
    if (prev) prev.classList.remove("ev-focused");
    focusedEventId = id;
    if (!id) return;
    const row = document.querySelector(
      `#forensicTimeline .ev-row[data-evid="${CSS.escape(id)}"]`,
    );
    if (row) {
      row.classList.add("ev-focused");
      row.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }
  function kbdClearFocus() {
    kbdSetFocus(null);
  }

  // Move focus to the next/previous row on the CURRENT page (clamps at either end rather than
  // auto-paging). Starts at the first/last row when nothing is focused yet, or when the previously
  // focused row scrolled out of the current page/filter (e.g. a re-render dropped it).
  function kbdMoveFocus(dir) {
    const rows = kbdVisibleRows();
    if (!rows.length) return;
    const ids = rows.map((r) => r.getAttribute("data-evid"));
    let idx = focusedEventId ? ids.indexOf(focusedEventId) : -1;
    idx =
      idx === -1
        ? dir > 0
          ? 0
          : ids.length - 1
        : Math.min(ids.length - 1, Math.max(0, idx + dir));
    kbdSetFocus(ids[idx]);
  }

  function kbdFocusedEvent() {
    if (!focusedEventId) return null;
    return (
      (DfirState.lastFt() || []).find((e) => String(e.id) === focusedEventId) ||
      null
    );
  }

  function kbdToggleFlag() {
    if (!focusedEventId) return;
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const id = focusedEventId;
    toggleStar(caseId, id); // re-renders the timeline, which drops DOM-level focus state
    kbdSetFocus(id); // ...so restore the highlight on the same row
  }

  // No dedicated "add as IOC" hook exists on events, so prefill the manual IOC-add form (in the
  // IOCs section) from the focused event's most likely indicator and let the analyst confirm/edit
  // the type before submitting, rather than guessing and posting silently.
  let _kbdIocFormAutoOpened = false; // whether kbdAddFocusedAsIoc revealed the form itself — if
  // so, Esc collapses it back; if the analyst had it open
  // already (via the section's own + toggle), Esc leaves it.
  function kbdAddFocusedAsIoc() {
    const e = kbdFocusedEvent();
    if (!e) return;
    const isIp = !!(e.dstIp || e.srcIp);
    const candidate = e.dstIp || e.srcIp || e.asset || "";
    if (!candidate) return;
    const sec = document.getElementById("sec-iocs");
    if (!sec) return;
    sec.classList.remove("collapsed");
    const wrap = sec.querySelector(".manual-add");
    if (wrap) {
      _kbdIocFormAutoOpened = wrap.hasAttribute("hidden");
      wrap.removeAttribute("hidden");
    }
    const typeSel = document.getElementById("miType");
    const valInput = document.getElementById("miValue");
    if (typeSel) typeSel.value = isIp ? "ip" : "other";
    if (valInput) valInput.value = candidate;
    sec.scrollIntoView({ behavior: "smooth", block: "start" });
    if (valInput) {
      valInput.focus();
      valInput.select();
    }
  }

  // Escape while the value field has focus cancels the "i" flow: clear the (possibly hand-edited)
  // value, blur back out to the timeline, and re-collapse the form if this flow is what opened it.
  // Scoped to this one field, mirroring #globalSearch's own Escape handler — the GLOBAL keydown
  // handler below deliberately skips INPUT targets, so it can't reach this itself.

  // Pinning is a Findings-section concept, not a per-event one — a timeline event only cites
  // findings via relatedFindingIds. Only act when the focused event cites exactly one finding;
  // otherwise it's ambiguous which one the analyst means, so this is a no-op.
  function kbdTogglePin() {
    const e = kbdFocusedEvent();
    if (!e) return;
    const fids = e.relatedFindingIds || [];
    if (fids.length !== 1) return;
    togglePin(fids[0]);
  }

  function kbdAddNote() {
    if (!focusedEventId) return;
    openCommentModal("event", focusedEventId);
  }

  function kbdOpenHelp() {
    document.getElementById("kbdHelpOverlay").classList.add("open");
  }
  function kbdCloseHelp() {
    document.getElementById("kbdHelpOverlay").classList.remove("open");
  }

  // Global vim-style shortcuts. Ignored while typing/focused in any field or when a modifier key
  // is held, so text entry and browser/OS shortcuts (Ctrl+F, Cmd+…) are never intercepted — same
  // guard style as the existing "/" focus-search handler. "/" itself is deliberately NOT handled
  // here since that handler already owns it.

  // The four statements that are the keyboard's, in their original order.
  function initKeyboardNav() {
    document.getElementById("miValue").addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.target.value = "";
      e.target.blur();
      if (_kbdIocFormAutoOpened) {
        const wrap = document.querySelector("#sec-iocs .manual-add");
        if (wrap) wrap.setAttribute("hidden", "");
        _kbdIocFormAutoOpened = false;
      }
    });
    document.getElementById("kbdHelpOverlay").addEventListener("click", (e) => {
      if (e.target.id === "kbdHelpOverlay") kbdCloseHelp();
    });
    document
      .getElementById("kbdHelpClose")
      .addEventListener("click", kbdCloseHelp);
    document.addEventListener("keydown", (e) => {
      if (!kbdShortcutsEnabled()) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = e.target && e.target.tagName;
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        (e.target && e.target.isContentEditable)
      )
        return;
      switch (e.key) {
        case "j":
          e.preventDefault();
          kbdMoveFocus(1);
          break;
        case "k":
          e.preventDefault();
          kbdMoveFocus(-1);
          break;
        case "f":
          e.preventDefault();
          kbdToggleFlag();
          break;
        case "i":
          e.preventDefault();
          kbdAddFocusedAsIoc();
          break;
        case "p":
          e.preventDefault();
          kbdTogglePin();
          break;
        case "n":
          e.preventDefault();
          kbdAddNote();
          break;
        case "?":
          e.preventDefault();
          kbdOpenHelp();
          break;
        case "Escape":
          if (
            document.getElementById("kbdHelpOverlay").classList.contains("open")
          )
            kbdCloseHelp();
          else if (focusedEventId) kbdClearFocus();
          break;
      }
    });
  }

  window.kbdShortcutsEnabled = kbdShortcutsEnabled;
  window.setKbdShortcutsEnabled = setKbdShortcutsEnabled;
  window.kbdOpenHelp = kbdOpenHelp;
  window.initKeyboardNav = initKeyboardNav;
})();
