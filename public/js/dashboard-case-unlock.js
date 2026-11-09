// Case unlock prompt — asking for the password that a protected case is guarded by (#415 tier 3).
//
// Its four controls were bound at module scope. What follows them in the inline block is the page's
// own startup sequence — loadCaseList(), the restore() IIFE and two guard stanzas from earlier
// extractions — and none of that came with it.
//
// It also owns the unlock bookkeeping (activeUnlockedCaseId / activeUnlockRemembered, declared in
// dashboard.html) and the case-switch generation (#2442), moved here from dashboard-case-connect.js.
(function () {
  // The newest case switch. Any answer for an older one — a lock probe, an unlock POST — is dropped,
  // so a slow reply can never connect a case the analyst has already moved away from (#2442).
  // Bumped in exactly two places: beginCaseSwitch() and cancelCaseUnlock().
  let switchGen = 0;

  // Tracks the currently-connected password-protected case's unlock, so a NOT-"remembered"
  // unlock can be explicitly forgotten (POST /cases/:id/lock) the moment we leave it. A
  // session cookie otherwise survives switching cases within the same tab — only an actual
  // browser close clears it — which is stricter persistence than "don't remember" should
  // give: without this, unchecking "remember" would only matter across browser restarts,
  // not across simply switching to another case and back.
  function forgetActiveCaseIfNotRemembered() {
    if (activeUnlockedCaseId && !activeUnlockRemembered) {
      fetch(`/cases/${activeUnlockedCaseId}/lock`, { method: "POST" }).catch(
        () => {},
      );
    }
    activeUnlockedCaseId = null;
    activeUnlockRemembered = true;
  }
  // The unlock follows the case that actually LOADS (#2442): the case being left is forgotten
  // only now, never when a switch merely starts, so a cancelled prompt leaves it usable.
  function adoptCaseUnlock(caseId, remembered) {
    if (activeUnlockedCaseId && activeUnlockedCaseId !== caseId) forgetActiveCaseIfNotRemembered();
    activeUnlockedCaseId = caseId;
    activeUnlockRemembered = remembered;
  }

  // A new Connect: retire every older switch and close a prompt still open for one of them. The
  // pick is NOT reset here — that would flash the old case's name in the box during the lock probe.
  function beginCaseSwitch() {
    closeCaseUnlock();
    return ++switchGen;
  }
  function isCurrentCaseSwitch(gen) {
    return gen === switchGen;
  }

  // ── Case unlock prompt ──────────────────────────────────────────────────
  function promptCaseUnlock(caseId) {
    document.getElementById("cuPassword").value = "";
    document.getElementById("cuRemember").checked = false;
    document.getElementById("cuMsg").textContent = "";
    document.getElementById("cuCaseLabel").textContent =
      `Case "${caseId}" is password-protected.`;
    const overlay = document.getElementById("caseUnlockOverlay");
    overlay.dataset.caseId = caseId;
    overlay.dataset.switchGen = String(switchGen);
    overlay.classList.add("open");
    document.getElementById("cuPassword").focus();
  }
  function closeCaseUnlock() {
    const overlay = document.getElementById("caseUnlockOverlay");
    if (!overlay) return;
    overlay.classList.remove("open");
    overlay.dataset.caseId = "";
  }
  // The analyst said no (Cancel, or a click on the backdrop): the switch is over, so a late unlock
  // answer must not connect, and the box goes back to naming the case on screen.
  function cancelCaseUnlock() {
    closeCaseUnlock();
    switchGen++;
    if (typeof clearCasePick === "function") clearCasePick();
  }
  async function doCaseUnlock() {
    const overlay = document.getElementById("caseUnlockOverlay");
    const caseId = overlay.dataset.caseId;
    const gen = Number(overlay.dataset.switchGen);
    // Still the prompt this answer is for: open, and no newer switch or cancel since (#2442).
    const current = () => gen === switchGen && overlay.classList.contains("open");
    if (!caseId || !current()) return;
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
      if (!current()) return; // the analyst moved on; a double submit lands here too
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        msg.textContent = body.error || "incorrect password";
        return;
      }
      closeCaseUnlock();
      proceedConnect(caseId, { remembered: remember });
    } catch (e) {
      if (current()) msg.textContent = "error: " + e.message;
    }
  }

  // The controls the inline block bound at module scope.
  function initCaseUnlock() {
    document.getElementById("cuUnlock").addEventListener("click", doCaseUnlock);
    document
      .getElementById("cuCancel")
      .addEventListener("click", cancelCaseUnlock);
    document.getElementById("cuPassword").addEventListener("keydown", (e) => {
      if (e.key === "Enter") doCaseUnlock();
    });
    document
      .getElementById("caseUnlockOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "caseUnlockOverlay") cancelCaseUnlock();
      });
  }

  window.promptCaseUnlock = promptCaseUnlock;
  window.forgetActiveCaseIfNotRemembered = forgetActiveCaseIfNotRemembered;
  window.adoptCaseUnlock = adoptCaseUnlock;
  window.beginCaseSwitch = beginCaseSwitch;
  window.isCurrentCaseSwitch = isCurrentCaseSwitch;
  window.initCaseUnlock = initCaseUnlock;
})();
