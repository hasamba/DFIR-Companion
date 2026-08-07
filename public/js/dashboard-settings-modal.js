// Settings modal: the Essential / All view toggle, and opening the modal on a named tab
// (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS THE MODE KEY. `SETTINGS_MODE_KEY` is the localStorage key the
// Essential/All choice persists under; in a CLASSIC script an unwrapped top-level const is a
// page-wide global, and a storage key named after one panel has no business being one.
//
// openSettingsTab is called from three places across the page — the Velociraptor badge, the tools
// panel and the dashboard-views link — so it publishes, as does closeSettingsModal.
(function () {
  // ── Essential / All view ────────────────────────────────────────────────────────────────
  // Essential shows only the controls a feature is dead without — API keys, service URLs, tool
  // binaries. Everything with a working default shows only under All. Which fields those are is authored
  // in the markup as `data-essential` and enforced by tests/settings/settingsEssentialAll.test.ts;
  // all this code does is set the mode. Stored per browser, like dfir.investigator.
  const SETTINGS_MODE_KEY = "dfir.settingsMode";

  function settingsMode() {
    return localStorage.getItem(SETTINGS_MODE_KEY) === "all"
      ? "all"
      : "essential";
  }

  function applySettingsMode(mode) {
    const modal = document.querySelector(".settings-modal");
    modal.dataset.mode = mode;
    localStorage.setItem(SETTINGS_MODE_KEY, mode);
    document
      .getElementById("settingsModeEssential")
      .classList.toggle("active", mode === "essential");
    document
      .getElementById("settingsModeAll")
      .classList.toggle("active", mode === "all");
    // Switching to Essential can hide the tab you were on — fall back to the first one still shown.
    const active = document.querySelector(".stab.active");
    if (active && stabHidden(active, mode)) {
      const first = [...document.querySelectorAll(".stab")].find(
        (b) => !stabHidden(b, mode),
      );
      if (first) first.click();
    }
  }

  // Open Settings on a named tab. A tab hidden in Essential (Velociraptor, Dashboard Views, …)
  // forces All first, so an in-app deep link can never land on a tab that isn't there.
  function openSettingsTab(name) {
    document.getElementById("settingsBtn").click();
    const tab = document.querySelector(`.stab[data-stab="${name}"]`);
    if (!tab) return;
    if (stabHidden(tab, settingsMode())) applySettingsMode("all");
    tab.click();
  }

  function openSettingsModal() {
    document.getElementById("settingsInvestigator").value =
      localStorage.getItem("dfir.investigator") || "";
    document.getElementById("kbdShortcutsChk").checked = kbdShortcutsEnabled();
    renderSecChecks();
    renderTlChecks();
    syncImportSevDefaultSelect();
    fetchEnvSettings();
    fetchLogLevel();
    // Reset to first tab
    document
      .querySelectorAll(".stab")
      .forEach((b, i) => b.classList.toggle("active", i === 0));
    document
      .querySelectorAll(".stab-pane")
      .forEach((p, i) => p.classList.toggle("active", i === 0));
    document.getElementById("settingsSaveMsg").textContent = "";
    // Refresh the Velociraptor triage panel (bundles + current hunt job + live monitors) so it's current when opened.
    veloClearBuilder();
    loadVeloBundles();
    loadVeloHuntJobs(veloCaseId());
    loadVeloClients();
    loadVeloMonitors(veloCaseId());
    loadPushToken(veloCaseId());
    loadUpdateCheck();
    // After the reset-to-first-tab above, so the fallback in applySettingsMode sees a real
    // active tab; before .open, so Essential mode never flashes the full list.
    window.DfirSettingsSearch?.reset();
    applySettingsMode(settingsMode());
    document.getElementById("settingsOverlay").classList.add("open");
  }

  function closeSettingsModal() {
    document.getElementById("settingsOverlay").classList.remove("open");
  }

  // Live references, not snapshots — the search module calls applyMode() when the box is cleared
  // so a tab Essential hides falls back through the code above rather than a duplicate of it.
  // Set at inline-script top level, read by the module at call time: module scripts run after
  // classic inline ones, so there is no ordering handshake to get wrong in either direction.

  // The statements the inline block ran at module scope, in their original order.
  function initSettingsModal() {
    document.getElementById("settingsBtn").onclick = openSettingsModal;
    document.getElementById("settingsSaveBtn").onclick = saveSettings;
    document.getElementById("settingsCloseBtn").onclick = closeSettingsModal;
    document.getElementById("settingsModeEssential").onclick = () =>
      applySettingsMode("essential");
    document.getElementById("settingsModeAll").onclick = () =>
      applySettingsMode("all");
    window.DfirSettingsSearchConfig = {
      applyMode: applySettingsMode,
      mode: settingsMode,
    };
  }

  window.openSettingsTab = openSettingsTab;
  window.closeSettingsModal = closeSettingsModal;
  window.openSettingsModal = openSettingsModal;
  window.initSettingsModal = initSettingsModal;
})();
