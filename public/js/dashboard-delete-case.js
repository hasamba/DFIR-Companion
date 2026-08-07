// Delete case (optionally archiving first) (#415 tier 3).
//
// The archive-choice radios were wired at module scope; the modal's own buttons are bound in the
// page's shared modal-wiring block and stay there, because that block is not this feature's to
// move.
(function () {
  // ── Delete case (optionally archive first) ────────────────────────────────
  function openDeleteCase() {
    const caseId = document.getElementById("caseId").value.trim();
    document.getElementById("dcCaseName").textContent =
      `Delete case "${caseId}"? This permanently removes all its data and cannot be undone.`;
    document.getElementById("dcArchiveNone").checked = true;
    document.getElementById("dcPasswordFields").style.display = "none";
    document.getElementById("dcPassword").value = "";
    document.getElementById("dcPasswordConfirm").value = "";
    document.getElementById("dcMsg").textContent = "";
    document.getElementById("deleteCaseOverlay").classList.add("open");
  }
  function closeDeleteCase() {
    document.getElementById("deleteCaseOverlay").classList.remove("open");
  }
  async function doDeleteCase() {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("dcMsg");
    if (!caseId) {
      msg.textContent = "no case loaded";
      return;
    }
    const archiveFirst = document.querySelector(
      'input[name="dcArchiveFirst"]:checked',
    ).value;
    let password;
    if (archiveFirst === "encrypted") {
      password = document.getElementById("dcPassword").value;
      const confirmPassword =
        document.getElementById("dcPasswordConfirm").value;
      if (password.length < 8) {
        msg.textContent = "password must be at least 8 characters";
        return;
      }
      if (password !== confirmPassword) {
        msg.textContent = "passwords do not match";
        return;
      }
    }
    const btn = document.getElementById("dcDelete");
    btn.disabled = true;
    msg.textContent = "deleting… (may take a while for large cases)";
    try {
      const res = await fetch(`/cases/${encodeURIComponent(caseId)}/delete`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          archiveFirst,
          ...(password ? { password } : {}),
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || "HTTP " + res.status);
      }
      let deleted;
      if (archiveFirst === "encrypted") {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const cd = res.headers.get("content-disposition") || "";
        const cdMatch = cd.match(/filename="([^"]*)"/);
        a.download = cdMatch ? cdMatch[1] : `${caseId}.dfircase`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        deleted = res.headers.get("x-case-deleted") === "true";
      } else {
        const body = await res.json();
        deleted = body.deleted;
      }
      closeDeleteCase();
      if (deleted) {
        // The case is gone — reset the whole dashboard to "no case selected" rather than trying
        // to unwind the dozens of per-panel load*(caseId) calls connect() fired for it.
        localStorage.removeItem("dfir.caseId");
        document.getElementById("status").textContent =
          archiveFirst === "none"
            ? "case deleted"
            : `case archived (${archiveFirst}) and deleted`;
        window.location.href = location.pathname;
      } else {
        document.getElementById("status").textContent =
          archiveFirst === "none"
            ? "delete failed — the case still exists, unchanged"
            : `archived (${archiveFirst}), but deleting the case folder afterward failed — it was not removed`;
        loadCaseLifecycle(caseId);
        loadCaseList();
      }
    } catch (err) {
      msg.textContent = "delete failed: " + err.message;
    } finally {
      btn.disabled = false;
    }
  }

  // The controls the inline block bound at module scope.
  function initDeleteCase() {
    // The modal's own three controls. They were in the page's shared modal-wiring block; every
    // other modal in this PR took its own lines out of there and so does this one.
    document.getElementById("dcDelete").onclick = doDeleteCase;
    document.getElementById("dcCancel").onclick = closeDeleteCase;
    document
      .getElementById("deleteCaseOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "deleteCaseOverlay") closeDeleteCase();
      });
    document.querySelectorAll('input[name="dcArchiveFirst"]').forEach((r) => {
      r.addEventListener("change", () => {
        document.getElementById("dcPasswordFields").style.display =
          document.getElementById("dcArchiveEncrypted").checked
            ? "block"
            : "none";
      });
    });
  }

  window.openDeleteCase = openDeleteCase;
  window.closeDeleteCase = closeDeleteCase;
  window.doDeleteCase = doDeleteCase;
  window.initDeleteCase = initDeleteCase;
})();
