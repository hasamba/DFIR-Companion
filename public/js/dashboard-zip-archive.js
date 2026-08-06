// ZIP case archive (unencrypted) — the plain archive of a whole case (#415 tier 3).
//
// Sibling of the encrypted archive export already extracted. Same shape: nothing runs at load in
// the block, and its three controls were bound in the page's shared modal-wiring block with two of
// them passing a function as a VALUE.
(function () {
  // ── ZIP case archive (unencrypted, "(no password)" in the filename) ─────
  function openZipArchive() {
    document.getElementById("zaRemoveFromList").checked = false;
    document.getElementById("zaMsg").textContent = "";
    document.getElementById("zipArchiveOverlay").classList.add("open");
  }
  function closeZipArchive() {
    document.getElementById("zipArchiveOverlay").classList.remove("open");
  }
  async function doZipArchive() {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("zaMsg");
    if (!caseId) {
      msg.textContent = "no case loaded";
      return;
    }
    const removeFromList = document.getElementById("zaRemoveFromList").checked;
    const btn = document.getElementById("zaArchive");
    btn.disabled = true;
    msg.textContent = "archiving… (may take a while for large cases)";
    try {
      const res = await fetch(`/cases/${encodeURIComponent(caseId)}/archive`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ removeFromList }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || "HTTP " + res.status);
      closeZipArchive();
      loadCaseLifecycle(caseId);
      loadCaseList();
      document.getElementById("status").textContent = removeFromList
        ? "case archived to ZIP and removed from the active list"
        : "case archived to ZIP";
    } catch (err) {
      msg.textContent = "archive failed: " + err.message;
    } finally {
      btn.disabled = false;
    }
  }

  // Encrypted case archive export moved to js/dashboard-encrypted-export.js (#415 tier 3).

  // The controls the page bound at module scope. Order unchanged.
  function initZipArchive() {
    document.getElementById("zaArchive").onclick = doZipArchive;
    document.getElementById("zaCancel").onclick = closeZipArchive;
    document
      .getElementById("zipArchiveOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "zipArchiveOverlay") closeZipArchive();
      });
  }

  window.openZipArchive = openZipArchive;
  window.closeZipArchive = closeZipArchive;
  window.doZipArchive = doZipArchive;
  window.initZipArchive = initZipArchive;
})();
