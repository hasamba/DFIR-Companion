// Import minimum-severity preference — the floor below which imported findings are dropped
// (#415 tier 3).
//
// NO INITIALIZER: both statements the splitter reported at load are guard stanzas left by the
// unified import and unified export extractions, and they stay in the page.
(function () {
  // ── Import minimum-severity preference (per-browser) ──────────────────────
  // Stored as { value, remember }. When remember is set, askMinSeverity() returns the
  // saved value WITHOUT showing the dialog. Settings → General → Import severity manages it.
  const IMPORT_SEV_KEY = "dfir_import_min_severity";
  const VALID_SEV = ["critical", "high", "medium", "low", "info"];
  function getImportSevPref() {
    try {
      const o = JSON.parse(localStorage.getItem(IMPORT_SEV_KEY) || "null");
      return o && typeof o === "object" ? o : null;
    } catch (e) {
      return null;
    }
  }
  function setImportSevPref(value, remember) {
    try {
      if (!remember) localStorage.removeItem(IMPORT_SEV_KEY);
      else
        localStorage.setItem(
          IMPORT_SEV_KEY,
          JSON.stringify({ value, remember: true }),
        );
    } catch (e) {
      /* quota — non-fatal */
    }
  }
  // Resolve the minimum severity for an import batch. Returns a normalized severity string,
  // or null if the user cancelled the whole import. A remembered choice skips the dialog.
  function askMinSeverity() {
    return new Promise((resolve) => {
      const pref = getImportSevPref();
      if (pref && pref.remember && VALID_SEV.includes(pref.value)) {
        resolve(pref.value);
        return;
      }
      const overlay = document.getElementById("importSevOverlay");
      const sel = document.getElementById("importSevSelect");
      const remember = document.getElementById("importSevRemember");
      sel.value = pref && VALID_SEV.includes(pref.value) ? pref.value : "info";
      remember.checked = false;
      overlay.classList.add("open");
      const cleanup = () => {
        overlay.classList.remove("open");
        document.getElementById("importSevOk").onclick = null;
        document.getElementById("importSevCancel").onclick = null;
        overlay.onclick = null;
      };
      document.getElementById("importSevOk").onclick = () => {
        const value = sel.value.trim().toLowerCase();
        setImportSevPref(value, remember.checked);
        syncImportSevDefaultSelect();
        cleanup();
        resolve(value);
      };
      const cancel = () => {
        cleanup();
        resolve(null);
      };
      document.getElementById("importSevCancel").onclick = cancel;
      overlay.onclick = (ev) => {
        if (ev.target.id === "importSevOverlay") cancel();
      };
    });
  }
  // Mirror the remembered preference into the Settings → General select (and react to edits there).
  function syncImportSevDefaultSelect() {
    const el = document.getElementById("importSevDefault");
    if (!el) return;
    const pref = getImportSevPref();
    el.value =
      pref && pref.remember && VALID_SEV.includes(pref.value) ? pref.value : "";
  }

  window.askMinSeverity = askMinSeverity;
  window.setImportSevPref = setImportSevPref;
  window.syncImportSevDefaultSelect = syncImportSevDefaultSelect;
})();
