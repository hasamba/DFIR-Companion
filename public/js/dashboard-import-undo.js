// Import undo / redo (#76) — rolls the WHOLE case back to exactly before the latest import, and
// forward again (#415 tier 3).
//
// IIFE-WRAPPED AS A MATTER OF COURSE: no top-level binding today, but this is a CLASSIC script and
// anything added at this level later would join the shared global lexical environment.
//
// ITS BANNER ALSO COVERS doAsk, WHICH STAYED. That is the AI "Ask" box — a wholly different
// feature that happens to sit under this heading, wired from the Settings block along with the ask
// input. The cohesion check reported this block as a single component and was wrong about it;
// reading the block is what caught it.
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
  function loadUndoStack(caseId) {
    fetch(`/cases/${caseId}/import/undo-stack`)
      .then((r) => (r.ok ? r.json() : null))
      .then(renderUndoStack)
      .catch(() => {});
  }
  function renderUndoStack(s) {
    const undoBtn = document.getElementById("importUndoBtn");
    const redoBtn = document.getElementById("importRedoBtn");
    if (!undoBtn || !redoBtn) return;
    // Hide the buttons only when the endpoint is unavailable (older server / not restarted yet).
    // Once it responds they're ALWAYS shown so the capability is discoverable, disabled (with a
    // hint) until there's something to undo/redo.
    if (!s) {
      undoBtn.style.display = "none";
      redoBtn.style.display = "none";
      return;
    }
    const canUndo = !!s.canUndo,
      canRedo = !!s.canRedo;
    undoBtn.style.display = "";
    redoBtn.style.display = "";
    undoBtn.disabled = !canUndo;
    redoBtn.disabled = !canRedo;
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
    undoBtn.title = undoTip;
    undoBtn.dataset.tip = undoTip;
    redoBtn.title = redoTip;
    redoBtn.dataset.tip = redoTip;
  }
  function doImportUndoRedo(which) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const undoBtn = document.getElementById("importUndoBtn");
    const redoBtn = document.getElementById("importRedoBtn");
    undoBtn.disabled = true;
    redoBtn.disabled = true;
    const active = which === "undo" ? undoBtn : redoBtn;
    const prev = active.textContent;
    active.textContent = which === "undo" ? "undoing…" : "redoing…";
    fetch(`/cases/${caseId}/import/${which}`, { method: "POST" })
      .then((r) => {
        if (!r.ok)
          return r.json().then((j) => {
            throw new Error(j.error || "HTTP " + r.status);
          });
        return r.json();
      })
      .then((s) => {
        // The restore is instant + verbatim (no AI). Pull fresh state so findings/IOCs/timeline
        // all update at once; the server also broadcasts it over the WS.
        fetch(`/cases/${caseId}/state`)
          .then((r) => r.json())
          .then(render)
          .catch(() => {});
        loadImportMeta(caseId);
        renderUndoStack(s);
      })
      .catch((e) => {
        active.textContent = prev;
        alert(
          `${which} failed: ${e.message}\n(restart the companion server if this 404s)`,
        );
        loadUndoStack(caseId);
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
