// Correlation profile (per-case matching strictness) — how tightly the correlator joins events
// before it calls them the same activity (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS THE WINDOW TABLE: CORR_PROFILE_WINDOWS maps each profile to its
// time window, and unwrapped it would be a page-wide global.
(function () {
  // --- Correlation profile (per-case cross-source event merge window) -------------------------
  const CORR_PROFILE_WINDOWS = { strict: 0, moderate: 2, aggressive: 300 };
  function loadCorrProfile(caseId) {
    fetch(`/cases/${caseId}/correlation-profile`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((p) => {
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
    fetch(`/cases/${caseId}/correlation-profile`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ profileName, windowSeconds }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((p) => {
        _updateCorrProfileInfo(p);
        document.getElementById("status").textContent =
          "Correlation profile saved — takes effect on next synthesis.";
      })
      .catch(() => {
        document.getElementById("status").textContent =
          "Correlation profile save failed — restart the companion server.";
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
