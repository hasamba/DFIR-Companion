// Encrypted case archive export — the password-protected archive of a whole case (#415 tier 3).
//
// IIFE-WRAPPED AS A MATTER OF COURSE. In a CLASSIC script any top-level binding added here later
// would join the shared global lexical environment.
//
// ITS WIRING IS AN INITIALIZER even though the block runs nothing at load: the Download and Cancel
// buttons and the overlay backdrop were bound in the page's shared modal-wiring block, and two of
// the three pass one of these functions as a VALUE.
(function () {
  // ── Encrypted case archive export (replaces #56's JSON snapshot) ─────────
  function openEncryptedExport() {
    document.getElementById("eePassword").value = "";
    document.getElementById("eePasswordConfirm").value = "";
    document.getElementById("eeRemoveFromList").checked = false;
    document.getElementById("eeMsg").textContent = "";
    document.getElementById("encryptedExportOverlay").classList.add("open");
    document.getElementById("eePassword").focus();
  }
  function closeEncryptedExport() {
    document.getElementById("encryptedExportOverlay").classList.remove("open");
  }
  async function doEncryptedExport() {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("eeMsg");
    if (!caseId) {
      msg.textContent = "no case loaded";
      return;
    }
    const password = document.getElementById("eePassword").value;
    const confirmPassword = document.getElementById("eePasswordConfirm").value;
    if (password.length < 8) {
      msg.textContent = "password must be at least 8 characters";
      return;
    }
    if (password !== confirmPassword) {
      msg.textContent = "passwords do not match";
      return;
    }
    const removeFromList = document.getElementById("eeRemoveFromList").checked;
    const btn = document.getElementById("eeDownload");
    btn.disabled = true;
    msg.textContent = "building… (may take a while for large cases)";
    try {
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/export/encrypted`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ password, removeFromList }),
        },
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || "HTTP " + res.status);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      // Server names the file "<caseId> - <case name>.dfircase" (falls back to just the caseId
      // when the case has no distinct name); read it from the response instead of hardcoding it.
      const cd = res.headers.get("content-disposition") || "";
      const cdMatch = cd.match(/filename="([^"]*)"/);
      a.download = cdMatch ? cdMatch[1] : `${caseId}.dfircase`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      closeEncryptedExport();
      const wasRemoved = res.headers.get("x-case-removed-from-list") === "true";
      loadCaseLifecycle(caseId);
      loadCaseList();
      document.getElementById("status").textContent = wasRemoved
        ? "encrypted case archive downloaded and removed from the active list"
        : "encrypted case archive downloaded";
    } catch (err) {
      msg.textContent = "export failed: " + err.message;
    } finally {
      btn.disabled = false;
    }
  }

  // The three controls the shared modal-wiring block used to bind.
  function initEncryptedExport() {
    document.getElementById("eeDownload").onclick = doEncryptedExport;
    document.getElementById("eeCancel").onclick = closeEncryptedExport;
    document
      .getElementById("encryptedExportOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "encryptedExportOverlay") closeEncryptedExport();
      });
  }

  window.openEncryptedExport = openEncryptedExport;
  window.closeEncryptedExport = closeEncryptedExport;
  window.doEncryptedExport = doEncryptedExport;
  window.initEncryptedExport = initEncryptedExport;
})();
