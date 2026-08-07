// The per-case AI on/off toggle (#415 tier 3).
//
// The third feature under the Query Translator's banner. It decides whether the case may call an
// AI provider at all, and reports when no provider is configured.
(function () {
  function renderAiToggle() {
    const b = document.getElementById("aiToggle");
    b.textContent = aiEnabled ? "AI: ON" : "AI: OFF";
    b.classList.remove("na");
    b.classList.toggle("on", aiEnabled);
  }

  function aiToggleUnavailable() {
    const b = document.getElementById("aiToggle");
    b.textContent = "AI: ?";
    b.classList.remove("on");
    b.classList.add("na");
    b.setAttribute("data-tip", "AI control endpoint missing");
    document.getElementById("status").textContent =
      "AI toggle unavailable — restart the companion server (stop it, then `npm run dev`) to load the latest endpoints.";
  }

  function loadAiToggle(caseId) {
    fetch(`/cases/${caseId}/ai-control`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((c) => {
        aiEnabled = !!c.enabled;
        renderAiToggle();
      })
      .catch(() => aiToggleUnavailable());
  }

  function toggleAi() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const next = !aiEnabled;
    fetch(`/cases/${caseId}/ai-control`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: next }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((c) => {
        aiEnabled = !!c.enabled;
        renderAiToggle();
        document.getElementById("status").textContent = aiEnabled
          ? "AI on — catching up on un-analyzed evidence…"
          : "AI off — capturing only";
      })
      .catch(() => aiToggleUnavailable());
  }

  // Threat-intel enrichment (per-case provider toggles) moved to js/dashboard-enrichment.js
  // (#415 tier 3). Its two controls are bound by initEnrichment(), from the modal-wiring block.

  window.loadAiToggle = loadAiToggle;
  window.toggleAi = toggleAi;
})();
