// Case unlock prompt — asking for the password that a protected case is guarded by (#415 tier 3).
//
// Its four controls were bound at module scope. What follows them in the inline block is the page's
// own startup sequence — loadCaseList(), the restore() IIFE and two guard stanzas from earlier
// extractions — and none of that came with it.
(function () {
  // ── Case unlock prompt ──────────────────────────────────────────────────
  function promptCaseUnlock(caseId) {
    document.getElementById("cuPassword").value = "";
    document.getElementById("cuRemember").checked = false;
    document.getElementById("cuMsg").textContent = "";
    document.getElementById("cuCaseLabel").textContent =
      `Case "${caseId}" is password-protected.`;
    const overlay = document.getElementById("caseUnlockOverlay");
    overlay.dataset.caseId = caseId;
    overlay.classList.add("open");
    document.getElementById("cuPassword").focus();
  }
  function closeCaseUnlock() {
    document.getElementById("caseUnlockOverlay").classList.remove("open");
  }
  async function doCaseUnlock() {
    const overlay = document.getElementById("caseUnlockOverlay");
    const caseId = overlay.dataset.caseId;
    const msg = document.getElementById("cuMsg");
    const password = document.getElementById("cuPassword").value;
    const remember = document.getElementById("cuRemember").checked;
    if (!password) {
      msg.textContent = "enter the password";
      return;
    }
    try {
      const r = await fetch(`/cases/${caseId}/unlock`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password, remember }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        msg.textContent = body.error || "incorrect password";
        return;
      }
      activeUnlockedCaseId = caseId;
      activeUnlockRemembered = remember;
      closeCaseUnlock();
      proceedConnect(caseId);
    } catch (e) {
      msg.textContent = "error: " + e.message;
    }
  }

  // The controls the inline block bound at module scope.
  function initCaseUnlock() {
    document.getElementById("cuUnlock").addEventListener("click", doCaseUnlock);
    document
      .getElementById("cuCancel")
      .addEventListener("click", closeCaseUnlock);
    document.getElementById("cuPassword").addEventListener("keydown", (e) => {
      if (e.key === "Enter") doCaseUnlock();
    });
    document
      .getElementById("caseUnlockOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "caseUnlockOverlay") closeCaseUnlock();
      });
  }

  window.promptCaseUnlock = promptCaseUnlock;
  window.initCaseUnlock = initCaseUnlock;
})();
