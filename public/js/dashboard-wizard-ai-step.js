// Setup wizard, AI step (#181) — choosing and testing the AI provider during first-run setup
// (#415 tier 3).
//
// ITS WIRING WAS A SELF-CALLING IIFE, the fourth in this PR after wirePushToken, wireVeloTriage and
// wireLifecycleButtons. A `(function(){…})()` at module scope looks deliberate and is the same trap:
// in a <head> script it runs before the wizard's controls exist and binds nothing, silently.
(function () {
  // Moved here from dashboard.html (#415), second pass. These two are read by this module and
  // nothing else, but they sat interleaved with js/dashboard-setup-wizard.js's bindings under one
  // banner, so the two groups had to move separately — a single splice across the interleave is
  // how a neighbour gets taken by mistake.
  //
  // Neither is published: a lookup object and a Set are not callable, and the feature manifest
  // requires published names to be functions (the gate that rejected a bare QA_AUDIT_MARK in
  // extraction 76). Nothing outside needs them, so they stay private rather than growing accessors
  // that no one calls.
  const WIZ_MODEL_HINTS = {
    openai:
      "Try <code>gpt-4o-mini</code> (cheap) or <code>gpt-4o</code> (stronger).",
    openrouter:
      "Try <code>openai/gpt-4o-mini</code> or <code>anthropic/claude-3.5-sonnet</code>.",
    ollama:
      "Try <code>llama3.2-vision</code> or <code>llava</code> (must support vision).",
    litellm:
      "Use your proxy's model name, e.g. <code>gpt-4o-mini</code>. Set the base URL below.",
    gemini:
      "Try <code>gemini-2.0-flash</code> (cheap) or <code>gemini-1.5-pro</code>.",
    anthropic:
      "Try <code>claude-haiku-4-5</code> (cheap) or <code>claude-sonnet-4-6</code>.",
  };
  const LOCAL_PROVIDERS = new Set(["ollama", "litellm"]);

  // ── AI step logic (#181, preserved) ──
  function wizResetAiStep() {
    wizEl("wizProvider").value = "";
    wizEl("wizModel").value = "";
    wizEl("wizKey").value = "";
    wizEl("wizBaseUrl").value = "";
    wizEl("wizResult").textContent = "";
    wizEl("wizModelHint").innerHTML = "";
    wizEl("wizBaseUrlField").style.display = "none";
    wizEl("wizTestSaveBtn").disabled = false;
    wizEl("wizSynthProvider").value = "";
    wizEl("wizSynthModel").value = "";
    wizEl("wizSynthKey").value = "";
    wizEl("wizSynthBaseUrl").value = "";
    wizEl("wizSynthResult").textContent = "";
    wizEl("wizSynthSaveBtn").disabled = false;
    const ccWizCard = wizEl("claude-code-status-wizard");
    if (ccWizCard) ccWizCard.style.display = "none";
  }
  // Claude Code connection-status card mirrored inside the wizard's own AI step (distinct
  // cc-*-wizard ids so it doesn't collide with the Settings → AI instance). No hard "ready" gate
  // exists anywhere in this wizard — Next/Back/Done are never blocked on step completion (every
  // step, including AI, is explicitly optional/skippable) — so this only surfaces status, it does
  // not gate navigation.
  async function wizSaveAndTestAi() {
    const provider = wizEl("wizProvider").value,
      model = wizEl("wizModel").value.trim();
    const key = wizEl("wizKey").value.trim(),
      baseUrl = wizEl("wizBaseUrl").value.trim();
    // claude-code needs no API key (it shells out to the locally-signed-in Claude Code CLI), same
    // as the LOCAL_PROVIDERS (ollama/litellm) exemption below.
    const result = wizEl("wizResult"),
      local = LOCAL_PROVIDERS.has(provider) || provider === "claude-code";
    if (!provider) {
      result.style.color = "#ffb05a";
      result.textContent = "Pick a provider first.";
      return;
    }
    if (!model) {
      result.style.color = "#ffb05a";
      result.textContent = "Enter an extraction model.";
      return;
    }
    if (!key && !local) {
      result.style.color = "#ffb05a";
      result.textContent = "Enter an API key (or pick a local provider).";
      return;
    }
    const btn = wizEl("wizTestSaveBtn");
    btn.disabled = true;
    result.style.color = "#9aa4b2";
    result.textContent = "Saving configuration…";
    const updates = {
      DFIR_VISION_PROVIDER: provider,
      DFIR_VISION_MODEL: model,
    };
    if (key) updates.DFIR_VISION_KEY = key;
    if (baseUrl) updates.DFIR_VISION_BASE_URL = baseUrl;
    try {
      const save = await fetch("/settings/env", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ updates }),
      });
      if (!save.ok) {
        const j = await save.json().catch(() => ({}));
        result.style.color = "#ff9f9f";
        result.textContent =
          "Could not save: " +
          esc(j.error || "HTTP " + save.status) +
          " — restart the companion server if this 404s.";
        btn.disabled = false;
        return;
      }
    } catch (e) {
      result.style.color = "#ff9f9f";
      result.textContent = "Could not reach the server: " + esc(e.message);
      btn.disabled = false;
      return;
    }
    result.textContent = "Applying & testing the connection…";
    await fetch("/settings/ai-reload", { method: "POST" }).catch(() => {});
    try {
      const r = await fetch("/diagnostics/ai-test", { method: "POST" });
      const body = await r.json().catch(() => ({}));
      if (r.status === 501) {
        result.style.color = "#ffb05a";
        result.textContent =
          "Saved, but " +
          esc(body.error || "the provider isn't configured yet") +
          ".";
      } else if (body.ok) {
        result.style.color = "#5ad17a";
        result.innerHTML =
          "✓ <strong>" +
          esc(body.provider) +
          "</strong> responded in " +
          body.latencyMs +
          " ms. Saved to .env — <strong>restart the companion server</strong> to enable AI analysis.";
      } else {
        result.style.color = "#ff9f9f";
        result.innerHTML =
          "✗ Saved, but the test failed — <strong>" +
          esc(body.kind || "error") +
          "</strong>: " +
          esc(body.error || "unknown") +
          ". Fix the value above and test again.";
      }
    } catch (e) {
      result.style.color = "#ff9f9f";
      result.textContent =
        "Saved, but the test request failed: " + esc(e.message);
    } finally {
      btn.disabled = false;
      await wizRefreshStatus();
    }
  }

  // The statements the inline block ran at module scope, in order.
  function initWizardAiStep() {
    (function () {
      var sel = wizEl("wizProvider");
      var card = wizEl("claude-code-status-wizard");
      if (!sel || !card) return;
      var dot = wizEl("cc-status-dot-wizard");
      var msg = wizEl("cc-status-msg-wizard");
      var connectBtn = wizEl("cc-connect-wizard");
      var hint = wizEl("cc-connect-hint-wizard");
      function paint(s) {
        var colors = {
          connected: "#16a34a",
          not_connected: "#d97706",
          not_installed: "#dc2626",
        };
        dot.style.background = colors[s.state] || "#6b7280";
        msg.textContent = s.message || s.state;
        connectBtn.style.display = s.state === "not_connected" ? "" : "none";
      }
      function refresh() {
        msg.textContent = "Checking Claude Code…";
        fetch("/diagnostics/claude-code-status")
          .then((r) => r.json())
          .then(paint)
          .catch(() => {
            msg.textContent = "Status check failed.";
          });
      }
      function toggleCcWizCard() {
        const on = sel.value === "claude-code";
        card.style.display = on ? "" : "none";
        if (on) refresh();
      }
      sel.addEventListener("change", toggleCcWizCard);
      connectBtn.addEventListener("click", () => {
        hint.style.display = "";
        hint.textContent = "Starting sign-in…";
        fetch("/diagnostics/claude-code-login", { method: "POST" })
          .then((r) => r.json())
          .then((r) => {
            if (r.url)
              hint.innerHTML =
                'Open this URL to finish signing in, then click Re-check:<br><a href="' +
                escAttr(r.url) +
                '" target="_blank" rel="noopener">' +
                esc(r.url) +
                "</a>";
            else if (r.started)
              hint.textContent =
                "Sign-in started on the host. Complete it in the browser that opened, then click Re-check.";
            else
              hint.textContent =
                (r.error || "Could not start sign-in") +
                ". Run `claude auth login` in a terminal on the host, then click Re-check.";
          })
          .catch(() => {
            hint.textContent =
              "Run `claude auth login` in a terminal on the host, then click Re-check.";
          });
      });
      wizEl("cc-recheck-wizard").addEventListener("click", refresh);
    })();
    wizEl("wizProvider").addEventListener("change", (e) => {
      const p = e.target.value,
        hint = wizEl("wizModelHint");
      hint.innerHTML = WIZ_MODEL_HINTS[p] || "";
      hint.querySelectorAll("code").forEach((c) => {
        c.title = "Click to use this model";
        c.onclick = () => {
          wizEl("wizModel").value = c.textContent;
        };
      });
      wizEl("wizBaseUrlField").style.display = LOCAL_PROVIDERS.has(p)
        ? ""
        : "none";
    });
    wizEl("wizTestSaveBtn").onclick = wizSaveAndTestAi;
  }

  window.wizResetAiStep = wizResetAiStep;
  window.initWizardAiStep = initWizardAiStep;
})();
