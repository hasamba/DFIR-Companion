// Import progress bar helpers (#415 tier 3).
//
// The progress strip an import drives: show, hide, cancel, the permission check that stops a
// read-only import before the picker opens, and the chunked file read that feeds the percentage.
//
// SPLIT FROM THE AI STATUS BANNER that shared its heading — the cohesion check reported clusters
// of 8 and 1, and the singleton is fifty lines of unrelated feature.
(function () {
  // ── Import progress bar helpers ───────────────────────────────────────────
  // The bar is a fixed strip whose ::after pseudo-element is driven by --ipb-w.
  // Indeterminate mode uses a CSS animation on ::after instead of the custom property.
  const _ipb = () => document.getElementById("importProgressBar");
  function showImportProgress(pct) {
    const b = _ipb();
    if (!b) return;
    b.classList.remove("ipb-indeterminate");
    b.classList.add("ipb-active");
    b.style.setProperty(
      "--ipb-w",
      Math.min(95, Math.max(0, pct)).toFixed(1) + "%",
    );
  }
  function showImportProgressIndeterminate() {
    const b = _ipb();
    if (!b) return;
    b.classList.remove("ipb-indeterminate");
    b.classList.add("ipb-active");
    void b.offsetWidth; // force reflow so the animation restarts cleanly
    b.classList.add("ipb-indeterminate");
  }
  function hideImportProgress() {
    const b = _ipb();
    if (!b) return;
    b.classList.remove("ipb-indeterminate");
    b.style.setProperty("--ipb-w", "100%");
    setTimeout(() => {
      b.classList.remove("ipb-active");
      b.style.setProperty("--ipb-w", "0%");
    }, 400);
  }
  function cancelImportProgress() {
    const b = _ipb();
    if (!b) return;
    b.classList.remove("ipb-active", "ipb-indeterminate");
    b.style.setProperty("--ipb-w", "0%");
  }
  function importPermissionMessage(caseId) {
    const state = window.dfirAuthState;
    if (!state || !state.enabled || !state.authenticated) return "";
    if (state.identity && state.identity.globalRole === "administrator")
      return "";
    const role = state.caseRoles && state.caseRoles[caseId];
    if (role === "investigator" || role === "administrator") return "";
    if (role) {
      return `Your ${role} role does not permit importing evidence. Ask a case administrator for the investigator or administrator role.`;
    }
    return "You do not have a case role that permits importing evidence. Ask a case administrator for the investigator or administrator role.";
  }
  // Read a File as text while driving the progress bar (0 → 40%).
  function readFileTextWithProgress(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onprogress = (e) => {
        if (e.lengthComputable) showImportProgress((e.loaded / e.total) * 40);
      };
      fr.onload = (e) => resolve(e.target.result);
      fr.onerror = () => reject(new Error("file read failed"));
      fr.readAsText(file);
    });
  }

  window.showImportProgress = showImportProgress;
  window.showImportProgressIndeterminate = showImportProgressIndeterminate;
  window.hideImportProgress = hideImportProgress;
  window.cancelImportProgress = cancelImportProgress;
  window.importPermissionMessage = importPermissionMessage;
  window.readFileTextWithProgress = readFileTextWithProgress;
})();
