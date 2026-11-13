// Import undo / redo (#76) — rolls the WHOLE case back to exactly before the latest import, and
// forward again (#415 tier 3).
//
// IIFE-WRAPPED AS A MATTER OF COURSE: no top-level binding today, but this is a CLASSIC script and
// anything added at this level later would join the shared global lexical environment.
//
// ITS BANNER ALSO COVERED THE AI "Ask" BOX, which stayed behind — a wholly different feature that
// happened to sit under this heading (since retired: Watson answers case questions). The cohesion
// check reported this block as a single component and was wrong about it; reading the block is what
// caught it.
//
// ITS WIRING IS AN INITIALIZER, and it came from somewhere else. The two toolbar buttons were bound
// beside the Narrative Timeline's controls, hundreds of lines away, purely by proximity — the
// narrative extraction deliberately left them behind rather than carry them into a module named for
// something else. They belong here, with the function they call.
(function () {
  // --- Import undo / redo (#76) -------------------------------------------------------------
  // Imports can flood the dashboard; this rolls the WHOLE case (findings, IOCs, timeline, MITRE,
  // attacker path) back to exactly before the latest import (and redo). The Undo/Redo buttons live
  // in the top toolbar next to Import; they enable/label from the undo-stack summary.
  //
  // ONE WRITER DECIDES WHETHER THE BUTTONS ARE LIVE (#2413). The undo-stack read (case load and the
  // import_undo_changed push) and the undo click both used to write `disabled`, so the push the undo
  // itself triggers re-enabled both buttons mid-undo and a second click rolled back a second import.
  // Now every read only RECORDS the summary; paintUndoButtons() draws it, and keeps both buttons
  // disabled while an undo or redo for the case on screen is in flight. The busy mark comes off in a
  // finally — this is a button-click POST, never under the case load's abandon contract.
  //
  // An answer belongs to the case it was asked for: a read for the case being left, or older than a
  // newer read, is dropped (undoStackSeq). The undo's own answer is NOT drawn — it was captured
  // before the server finished, and a read that saw a later import may already be on screen — so a
  // finished undo re-reads the stack and the buttons stay disabled until that read lands.
  //
  // Busy is tracked PER CASE: an undo for B must neither unlock nor be blocked by one still running
  // for A, and returning to A while its undo runs must find A's buttons still disabled.
  let undoStackSeq = 0;
  let undoSummary = null; // { caseId, s } — the newest summary for the case on screen
  const undoBusy = new Map(); // caseId -> token of the undo/redo in flight for it
  const undoCurrentCase = () => (document.getElementById("caseId") || {}).value?.trim?.() || "";

  function loadUndoStack(caseId) {
    const seq = ++undoStackSeq;
    return fetch(`/cases/${caseId}/import/undo-stack`)
      .then((r) => (r.ok ? r.json() : null))
      .then((s) => {
        if (seq !== undoStackSeq || caseId !== undoCurrentCase()) return;
        renderUndoStack(s, caseId);
      })
      .catch(() => {});
  }
  function renderUndoStack(s, caseId) {
    undoSummary = { caseId: caseId || undoCurrentCase(), s };
    paintUndoButtons();
  }
  function paintUndoButtons() {
    const undoBtn = document.getElementById("importUndoBtn");
    const redoBtn = document.getElementById("importRedoBtn");
    if (!undoBtn || !redoBtn) return;
    const current = undoCurrentCase();
    const s = undoSummary && undoSummary.caseId === current ? undoSummary.s : null;
    const busy = !!current && undoBusy.has(current);
    // Hide the buttons only when the endpoint is unavailable (older server / not restarted yet).
    // Once it responds they're ALWAYS shown so the capability is discoverable, disabled (with a
    // hint) until there's something to undo/redo.
    if (!s && !busy) {
      undoBtn.style.display = "none";
      redoBtn.style.display = "none";
      return;
    }
    const canUndo = !!(s && s.canUndo),
      canRedo = !!(s && s.canRedo);
    undoBtn.style.display = "";
    redoBtn.style.display = "";
    undoBtn.disabled = busy || !canUndo;
    redoBtn.disabled = busy || !canRedo;
    if (busy) return; // the in-flight button keeps its "undoing…" / "redoing…" label
    // Keep the LABELS short + fixed — the import name can be long, and a long toolbar label makes
    // fitToolbar() wrap the row and collapse everything to icons (even on a wide screen). The
    // specific import + counts go in the hover tooltip instead.
    undoBtn.textContent = "Undo import";
    redoBtn.textContent = "Redo";
    const undoTip =
      canUndo && s.nextUndo
        ? `Undo the last import — roll the whole case back to before "${s.nextUndo.label}" (restores ${s.nextUndo.events} events, ${s.nextUndo.iocs} IOCs, ${s.nextUndo.findings} findings)`
        : "Nothing to undo yet — run an import first";
    const redoTip =
      canRedo && s.nextRedo
        ? `Redo — re-apply "${s.nextRedo.label}"`
        : "Nothing to redo";
    undoBtn.dataset.tip = undoTip;
    redoBtn.dataset.tip = redoTip;
  }
  function doImportUndoRedo(which) {
    const caseId = undoCurrentCase();
    if (!caseId || undoBusy.has(caseId)) return;
    const undoBtn = document.getElementById("importUndoBtn");
    const redoBtn = document.getElementById("importRedoBtn");
    if (!undoBtn || !redoBtn) return;
    const token = {};
    undoBusy.set(caseId, token);
    const active = which === "undo" ? undoBtn : redoBtn;
    active.textContent = which === "undo" ? "undoing…" : "redoing…";
    paintUndoButtons();
    fetch(`/cases/${caseId}/import/${which}`, { method: "POST" })
      .then((r) => {
        if (!r.ok)
          return r.json().then((j) => {
            throw new Error(j.error || "HTTP " + r.status);
          });
        return r.json();
      })
      .then(() => {
        if (caseId !== undoCurrentCase()) return; // the analyst moved on; that case's own load re-reads
        // The restore is instant + verbatim (no AI). Pull fresh state so findings/IOCs/timeline
        // all update at once; the server also broadcasts it over the WS.
        fetch(`/cases/${caseId}/state`)
          .then((r) => r.json())
          .then(render)
          .catch(() => {});
        loadImportMeta(caseId);
        return loadUndoStack(caseId); // still busy until the fresh stack is on screen
      })
      .catch((e) => {
        if (caseId !== undoCurrentCase()) return;
        alert(
          `${which} failed: ${e.message}\n(restart the companion server if this 404s)`,
        );
        return loadUndoStack(caseId);
      })
      .finally(() => {
        if (undoBusy.get(caseId) === token) undoBusy.delete(caseId);
        paintUndoButtons();
      });
  }

  // The two toolbar buttons, reunited with the feature they drive.
  function initImportUndoRedo() {
    document
      .getElementById("importUndoBtn")
      .addEventListener("click", () => doImportUndoRedo("undo"));
    document
      .getElementById("importRedoBtn")
      .addEventListener("click", () => doImportUndoRedo("redo"));
  }

  window.loadUndoStack = loadUndoStack;
  window.doImportUndoRedo = doImportUndoRedo;
  window.initImportUndoRedo = initImportUndoRedo;
})();
