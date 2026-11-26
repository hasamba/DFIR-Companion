// Correlation profile (per-case matching strictness) — how tightly the correlator joins events
// before it calls them the same activity (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS THE WINDOW TABLE: CORR_PROFILE_WINDOWS maps each profile to its
// time window, and unwrapped it would be a page-wide global.
(function () {
  // --- Correlation profile (per-case cross-source event merge window) -------------------------
  const CORR_PROFILE_WINDOWS = { strict: 0, moderate: 2, aggressive: 300 };
  // #2904: is `caseId` still the case on screen? Fails open when there is no #caseId to read.
  function corrOnScreen(caseId) {
    const el = document.getElementById("caseId");
    return !el || typeof el.value !== "string" || el.value.trim() === caseId;
  }
  // #2904: a load for another case blanks the previous case's profile at once (no option selected,
  // no window, no info — not a claim about this case); only the newest answer for it paints.
  let corrCase = null;
  let corrSeq = 0;
  let corrGen = 0; // #2933: Apply's answer paints only in the generation it was sent in (owner change / cancel)
  function blankCorrProfile() {
    const sel = document.getElementById("corrProfileSel");
    const winEl = document.getElementById("corrWindowSec");
    const info = document.getElementById("corrProfileInfo");
    if (sel) sel.value = "";
    if (winEl) winEl.style.display = "none";
    if (info) info.textContent = "";
  }
  // #2915: a cancelled or failed case load blanks the profile; the next open (same case too) reads again.
  function onCorrReset(caseId) {
    if (caseId !== null) return;
    corrSeq++;
    corrGen++;
    corrCase = null;
    blankCorrProfile();
  }
  function loadCorrProfile(caseId) {
    if (!corrOnScreen(caseId)) return; // a late caller for a case the analyst has left
    typeof DfirPanelDefer !== "undefined" && typeof DfirPanelDefer.onReset === "function" && DfirPanelDefer.onReset(onCorrReset);
    if (corrCase !== caseId) {
      corrGen++;
      corrCase = caseId;
      blankCorrProfile();
    }
    const seq = ++corrSeq;
    fetch(`/cases/${caseId}/correlation-profile`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((p) => {
        if (seq !== corrSeq || !corrOnScreen(caseId)) return;
        const sel = document.getElementById("corrProfileSel");
        const winEl = document.getElementById("corrWindowSec");
        if (!sel) return;
        const name = p.profileName || "moderate";
        sel.value = name;
        if (name === "custom" && winEl) {
          winEl.style.display = "";
          winEl.value = p.windowSeconds ?? 2;
        } else if (winEl) winEl.style.display = "none";
        _updateCorrProfileInfo(p);
      })
      .catch(() => {}); // endpoint absent on older servers — silently skip
  }
  function _updateCorrProfileInfo(p) {
    const el = document.getElementById("corrProfileInfo");
    if (!el) return;
    const labels = {
      strict: "exact match only",
      moderate: "±2 s window",
      aggressive: "±5 min window",
    };
    el.textContent = labels[p.profileName] || `±${p.windowSeconds}s window`;
  }
  function applyCorrProfile() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const sel = document.getElementById("corrProfileSel");
    const winEl = document.getElementById("corrWindowSec");
    if (!sel) return;
    const profileName = sel.value;
    const windowSeconds =
      profileName === "custom"
        ? winEl
          ? Math.max(0, parseInt(winEl.value, 10) || 0)
          : 2
        : (CORR_PROFILE_WINDOWS[profileName] ?? 2);
    const gen = corrGen, live = () => gen === corrGen && corrOnScreen(caseId);
    fetch(`/cases/${caseId}/correlation-profile`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ profileName, windowSeconds }),
    })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          // A closed case answers 423 with its own sentence (#2437); say that, not "restart".
          const err = new Error(body.error || "HTTP " + r.status);
          err.serverMessage = body.error;
          throw err;
        }
        return r.json();
      })
      .then((p) => {
        if (!live()) return; // #2933: the analyst switched case, or cancelled and reopened it
        _updateCorrProfileInfo(p);
        document.getElementById("status").textContent =
          "Correlation profile saved — takes effect on next synthesis.";
      })
      .catch((e) => {
        if (!live()) return;
        document.getElementById("status").textContent =
          e && e.serverMessage
            ? "Correlation profile not saved: " + e.serverMessage
            : "Correlation profile save failed — restart the companion server.";
      });
  }

  // The statements the inline block ran at module scope, in their original order.
  function initCorrelationProfile() {
    document
      .getElementById("corrProfileSel")
      .addEventListener("change", function () {
        const winEl = document.getElementById("corrWindowSec");
        if (!winEl) return;
        winEl.style.display = this.value === "custom" ? "" : "none";
      });
    document
      .getElementById("applyCorrProfile")
      .addEventListener("click", applyCorrProfile);
  }

  window.loadCorrProfile = loadCorrProfile;
  window.applyCorrProfile = applyCorrProfile;
  window.initCorrelationProfile = initCorrelationProfile;
})();
