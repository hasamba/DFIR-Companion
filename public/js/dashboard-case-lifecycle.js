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
  //
  // #2443: a live push can trigger this, so an answer for a case that is no longer on screen (a
  // switch, or a cancelled load that set activeCaseId to null) is dropped, never painted.
  let paintedLifecycle = null; // { caseId, status } last painted — see the menu hide below
  function loadCaseLifecycle(caseId, signal) {
    return fetch("/cases", signal ? { signal } : undefined)
      .then((r) => (r.ok ? r.json() : []))
      .then((cases) => {
        if (typeof activeCaseId !== "undefined" && activeCaseId !== caseId)
          return;
        const meta = cases.find((c) => c.caseId === caseId);
        const status = meta ? meta.status : null;
        // A menu opened before the change would offer an action that no longer applies.
        const menu = document.getElementById("lifecycleMenu");
        if (
          menu &&
          paintedLifecycle &&
          paintedLifecycle.caseId === caseId &&
          paintedLifecycle.status !== status
        )
          menu.style.display = "none";
        paintedLifecycle = { caseId, status };
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
          // data-tip, not title — a native title draws a second bubble over the styled card.
          btn.dataset.tip = isArchived
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

  // #2443: someone closed, reopened, archived or restored a case — maybe this one, maybe another
  // in the case list. The push is bare, so re-read both; GET /cases applies this viewer's access.
  function loadLifecycleChange(caseId) {
    if (typeof loadCaseList === "function") loadCaseList();
    return loadCaseLifecycle(caseId);
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
    // The close dialog that asks about the case's cloud credentials (#2347, dashboard-case-close.js).
    if (typeof window.initCaseClose === "function") window.initCaseClose();

    // Toggle menu on button click — position fixed relative to button so it works
    // even though the menu lives outside the toolbar (prevents fitToolbar flicker).
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (menu.style.display !== "none") {
        menu.style.display = "none";
        return;
      }
      const z = window.pageZoom ? window.pageZoom() : 1; // text-size zoom (js/dashboard-theme.js)
      const r = btn.getBoundingClientRect();
      menu.style.top = (r.bottom + 4) / z + "px";
      menu.style.left = r.left / z + "px";
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
        // Asks about the case's cloud credentials first when it has any (#2347).
        const closed = await window.closeCaseWithCredentials(caseId);
        if (!closed) return;
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

    // Restore an archived case back to the active list. It always comes back closed — even one that
    // was open when it was archived — so the status line says so and names the way out (#2466).
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
          `case "${caseId}" restored — it comes back closed; use Reopen case to make changes`;
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
  window.loadLifecycleChange = loadLifecycleChange;
  window.initCaseLifecycle = initCaseLifecycle;
})();
