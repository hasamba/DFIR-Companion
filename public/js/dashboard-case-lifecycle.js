// Case lifecycle (#119) — where a case sits between open, on hold, closed and archived, and the
// buttons that move it (#415 tier 3).
//
// IIFE-WRAPPED AS A MATTER OF COURSE: no top-level binding today, but this is a CLASSIC script and
// anything added at this level later would join the shared global lexical environment.
//
// ITS WIRING WAS ALREADY SELF-CALLING — `(function wireLifecycleButtons(){…})()` — which is the
// same trap in a shape that looks deliberate: in a <head> script it runs before the buttons exist
// and binds nothing, silently. It becomes a named initializer the page calls behind a guard, at the
// point the IIFE used to run. 113 of this feature's 149 lines are that wiring.
(function () {
  // ── Case lifecycle (#119) ───────────────────────────────────────────────
  // Load the case's status (open/closed) and update the toolbar button + label. Returns its
  // promise so proceedConnect() can gate the loading overlay on it (see showCaseLoadingOverlay).
  function loadCaseLifecycle(caseId, signal) {
    return fetch("/cases", signal ? { signal } : undefined)
      .then((r) => (r.ok ? r.json() : []))
      .then((cases) => {
        const meta = cases.find((c) => c.caseId === caseId);
        const isClosed = meta && meta.status === "closed";
        const isArchived = meta && meta.status === "archived";
        const btn = document.getElementById("lifecycleBtn");
        const closeBtn = document.getElementById("closeBtn");
        const reopenBtn = document.getElementById("reopenBtn");
        const archiveZipBtn = document.getElementById("archiveZipBtn");
        const archiveEncryptedBtn = document.getElementById(
          "archiveEncryptedBtn",
        );
        const restoreCaseBtn = document.getElementById("restoreCaseBtn");
        const deleteCaseBtn = document.getElementById("deleteCaseBtn");
        if (btn) {
          btn.style.display = caseId ? "inline-flex" : "none";
          btn.classList.toggle("lc-closed", isClosed);
          btn.classList.toggle("lc-archived", isArchived);
          btn.title = isArchived
            ? "Case ARCHIVED — click to restore"
            : isClosed
              ? "Case CLOSED — click to reopen or archive"
              : "Case ACTIVE — click to close or archive";
        }
        // Archived cases can only be restored — close/reopen/archive don't apply until then.
        if (closeBtn)
          closeBtn.style.display = !isArchived && !isClosed ? "block" : "none";
        if (reopenBtn)
          reopenBtn.style.display = !isArchived && isClosed ? "block" : "none";
        if (archiveZipBtn)
          archiveZipBtn.style.display = isArchived ? "none" : "block";
        if (archiveEncryptedBtn)
          archiveEncryptedBtn.style.display = isArchived ? "none" : "block";
        if (restoreCaseBtn)
          restoreCaseBtn.style.display = isArchived ? "block" : "none";
        // Delete is available once a case is closed OR archived — never for an open case.
        if (deleteCaseBtn)
          deleteCaseBtn.style.display =
            isClosed || isArchived ? "block" : "none";
      })
      .catch(() => {});
  }

  // Was (function wireLifecycleButtons(){…})() at the bottom of the block.
  function initCaseLifecycle() {
    const btn = document.getElementById("lifecycleBtn");
    const menu = document.getElementById("lifecycleMenu");
    const closeBtn = document.getElementById("closeBtn");
    const reopenBtn = document.getElementById("reopenBtn");
    const archiveZipBtn = document.getElementById("archiveZipBtn");
    const archiveEncryptedBtn = document.getElementById("archiveEncryptedBtn");
    const restoreCaseBtn = document.getElementById("restoreCaseBtn");
    const deleteCaseBtn = document.getElementById("deleteCaseBtn");
    if (!btn || !menu) return;

    // Toggle menu on button click — position fixed relative to button so it works
    // even though the menu lives outside the toolbar (prevents fitToolbar flicker).
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (menu.style.display !== "none") {
        menu.style.display = "none";
        return;
      }
      const r = btn.getBoundingClientRect();
      menu.style.top = r.bottom + 4 + "px";
      menu.style.left = r.left + "px";
      menu.style.display = "block";
    });

    // Close menu when clicking outside
    document.addEventListener("click", () => {
      menu.style.display = "none";
    });

    // Close case, then nudge toward archiving it now as an encrypted .dfircase.
    closeBtn.addEventListener("click", async () => {
      menu.style.display = "none";
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      try {
        const r = await fetch(`/cases/${caseId}/status`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ status: "closed" }),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          alert("Failed to close case: " + (err.error || "HTTP " + r.status));
          return;
        }
        loadCaseLifecycle(caseId);
        loadCaseList();
        if (
          confirm(
            `Case "${esc(caseId)}" closed. Archive it now as an encrypted .dfircase?`,
          )
        ) {
          openEncryptedExport();
        }
      } catch (e) {
        alert("Error: " + e.message);
      }
    });

    // Reopen case
    reopenBtn.addEventListener("click", async () => {
      menu.style.display = "none";
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      try {
        const r = await fetch(`/cases/${caseId}/status`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ status: "open" }),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          alert("Failed to reopen case: " + (err.error || "HTTP " + r.status));
          return;
        }
        loadCaseLifecycle(caseId);
        loadCaseList();
      } catch (e) {
        alert("Error: " + e.message);
      }
    });

    // Archive to ZIP — opens the ZIP archive dialog (with the removal checkbox) instead
    // of archiving immediately.
    archiveZipBtn.addEventListener("click", () => {
      menu.style.display = "none";
      openZipArchive();
    });

    // Archive (encrypted) — reuses the encrypted export dialog (with the removal checkbox).
    archiveEncryptedBtn.addEventListener("click", () => {
      menu.style.display = "none";
      openEncryptedExport();
    });

    // Restore an archived case back to the active list (status becomes "closed").
    restoreCaseBtn.addEventListener("click", async () => {
      menu.style.display = "none";
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      try {
        const r = await fetch(`/cases/${caseId}/restore`, { method: "POST" });
        const body = await r.json().catch(() => ({}));
        if (!r.ok) {
          alert("Restore failed: " + (body.error || "HTTP " + r.status));
          return;
        }
        loadCaseLifecycle(caseId);
        loadCaseList();
        document.getElementById("status").textContent =
          `case "${caseId}" restored (now closed)`;
      } catch (e) {
        alert("Restore error: " + e.message);
      }
    });

    // Delete case — opens the delete confirmation dialog (archive choice + Delete/Cancel).
    deleteCaseBtn.addEventListener("click", () => {
      menu.style.display = "none";
      openDeleteCase();
    });
  }

  window.loadCaseLifecycle = loadCaseLifecycle;
  window.initCaseLifecycle = initCaseLifecycle;
})();
