// Case password protection — setting, changing and removing the password that guards a case
// (#415 tier 3).
//
// Nothing outside calls into it: the five controls are its own, and they were bound at module
// scope, so the whole feature is body plus one initializer.
(function () {
  // ── Case password protection ─────────────────────────────────────────────
  async function openCasePassword() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) {
      alert("open a case first");
      return;
    }
    document.getElementById("cpNewPassword").value = "";
    const msg = document.getElementById("cpMsg");
    msg.textContent = "";
    const saveBtn = document.getElementById("cpSave");
    const removeBtn = document.getElementById("cpRemove");
    saveBtn.disabled = false;
    removeBtn.disabled = true; // disabled until we confirm a password actually exists
    document.getElementById("casePasswordOverlay").classList.add("open");
    document.getElementById("cpNewPassword").focus();
    try {
      const status = await fetch(`/cases/${caseId}/lock-status`).then((r) =>
        r.ok ? r.json() : null,
      );
      if (!status) return;
      removeBtn.disabled = !status.hasPassword;
      if (status.hasPassword && !status.unlocked) {
        // Setting/changing/removing a password requires already being unlocked (same rule
        // that protects the case itself) — this browser isn't, so neither action would work.
        saveBtn.disabled = true;
        removeBtn.disabled = true;
        msg.textContent =
          "This case is locked — reload the page and enter the password first to change or remove it.";
      }
    } catch (e) {
      // offline / older server — leave the safe defaults (Remove disabled, Save enabled)
    }
  }
  function closeCasePassword() {
    document.getElementById("casePasswordOverlay").classList.remove("open");
  }
  async function saveCasePassword() {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("cpMsg");
    const newPassword = document.getElementById("cpNewPassword").value;
    if (newPassword.length < 6) {
      msg.textContent = "password must be at least 6 characters";
      return;
    }
    try {
      const r = await fetch(`/cases/${caseId}/password`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ newPassword }),
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        msg.textContent = body.error || "HTTP " + r.status;
        return;
      }
      closeCasePassword();
      loadCaseList();
      alert("Case password set.");
    } catch (e) {
      msg.textContent = "error: " + e.message;
    }
  }
  async function removeCasePassword() {
    const caseId = document.getElementById("caseId").value.trim();
    if (
      !confirm(
        `Remove the password from case "${esc(caseId)}"? Anyone with dashboard access will be able to open it without a password.`,
      )
    )
      return;
    const msg = document.getElementById("cpMsg");
    try {
      const r = await fetch(`/cases/${caseId}/password`, { method: "DELETE" });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        msg.textContent = body.error || "HTTP " + r.status;
        return;
      }
      closeCasePassword();
      loadCaseList();
      alert("Case password removed.");
    } catch (e) {
      msg.textContent = "error: " + e.message;
    }
  }

  // The controls the inline block bound at module scope.
  function initCasePassword() {
    document.getElementById("casePasswordBtn").addEventListener("click", () => {
      document.getElementById("lifecycleMenu").style.display = "none";
      openCasePassword();
    });
    document
      .getElementById("cpSave")
      .addEventListener("click", saveCasePassword);
    document
      .getElementById("cpRemove")
      .addEventListener("click", removeCasePassword);
    document
      .getElementById("cpCancel")
      .addEventListener("click", closeCasePassword);
    document
      .getElementById("casePasswordOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "casePasswordOverlay") closeCasePassword();
      });
  }

  window.initCasePassword = initCasePassword;
})();
