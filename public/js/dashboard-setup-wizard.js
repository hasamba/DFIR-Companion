// Comprehensive setup wizard (#181) — the first-run walkthrough that configures the AI provider,
// the integrations and the notification channels (#415 tier 3).
//
// THE TWO DOM-READING CONSTS ARE IN THE INITIALIZER, the two functions beside them are not.
// `const rerunLink = document.getElementById(…)` is a VariableStatement, so it reads as module body
// and evaluates to null in a <head> script; maybeShowSetupWizard and fetchLogLevel are ordinary
// declarations and belong in the body. Putting the whole tail in the initializer nests them, and
// then `window.fetchLogLevel = fetchLogLevel` cannot see the name — which is how the module suite
// caught the first attempt.
//
// The 419-line banner this came from is mostly NOT this feature: nine guard stanzas from earlier
// extractions and the page's shared Settings wiring sit below it, and all of that stays.
(function () {
  // Moved here from dashboard.html (#415). The wizard module already existed; its STATE did not
  // come with it — the fourth time in this PR an extraction stopped at the code and left the
  // bindings behind, where nothing fails because classic scripts share one global lexical
  // environment. F and WIZARD_STEPS travel together: F builds every entry of it, and both
  // wizardOrder() and WIZARD_BY_ID are derived from it.
  //
  // WIZ_MODEL_HINTS and LOCAL_PROVIDERS stay in the page for now — they belong to
  // js/dashboard-wizard-ai-step.js, and they interleave with these. Separate pass.
  const WIZ_DISMISS_KEY = "dfir.aiWizardDismissed"; // kept for back-compat with #181
  // The step table lives in js/dashboard-wizard-steps.js — it is pure data, and keeping it here
  // put this module over the 800-line budget. Accessors because published names must be callable.
  let wizCurrent = "ai"; // active step id
  let wizStatus = {}; // last /setup/status snapshot (drives ✓/○)

  // ── Synthesis model (optional, sub-section of the AI step) ──
  // No live connectivity test here: /diagnostics/ai-test only probes the main extraction
  // provider, so this mirrors Settings → AI (save + apply, no per-field test).
  async function wizSaveSynth() {
    const result = wizEl("wizSynthResult");
    const updates = {};
    const provider = wizEl("wizSynthProvider").value;
    const model = wizEl("wizSynthModel").value.trim();
    const key = wizEl("wizSynthKey").value.trim();
    const baseUrl = wizEl("wizSynthBaseUrl").value.trim();
    if (provider) updates.DFIR_AI_SYNTH_PROVIDER = provider;
    if (model) updates.DFIR_AI_SYNTH_MODEL = model;
    if (key) updates.DFIR_AI_SYNTH_KEY = key;
    if (baseUrl) updates.DFIR_AI_SYNTH_BASE_URL = baseUrl;
    if (Object.keys(updates).length === 0) {
      result.style.color = "#ffb05a";
      result.textContent =
        "Enter at least one value first — or leave everything blank to keep reusing the extraction model for synthesis.";
      return;
    }
    const btn = wizEl("wizSynthSaveBtn");
    btn.disabled = true;
    result.style.color = "#9aa4b2";
    result.textContent = "Saving…";
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
          "Could not save: " + esc(j.error || "HTTP " + save.status);
        btn.disabled = false;
        return;
      }
    } catch (e) {
      result.style.color = "#ff9f9f";
      result.textContent = "Could not reach the server: " + esc(e.message);
      btn.disabled = false;
      return;
    }
    await fetch("/settings/reload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prefix: "DFIR_AI_SYNTH_" }),
    }).catch(() => {});
    result.style.color = "#5ad17a";
    result.textContent = "✓ Saved. Used on the next synthesis run.";
    btn.disabled = false;
  }

  function wizRenderStep(step) {
    if (step.kind === "notifications") {
      return (
        "<h3>" +
        step.icon +
        " " +
        esc(step.label) +
        "</h3>" +
        '<p class="wiz-sub">' +
        esc(step.blurb) +
        "</p>" +
        (step.note
          ? '<div class="wiz-note">🔔 ' + esc(step.note) + "</div>"
          : "") +
        '<div class="wiz-field"><label>Channel type<span class="wiz-hint">Slack / Teams / Mattermost / Discord — all use an incoming-webhook URL.</span></label>' +
        '<select id="wizNotifType"><option value="slack">Slack</option><option value="teams">MS Teams</option><option value="mattermost">Mattermost</option><option value="discord">Discord</option></select></div>' +
        '<div class="wiz-field"><label>Webhook URL</label><input id="wizNotifUrl" placeholder="https://hooks.slack.com/services/…" autocomplete="off" /></div>' +
        '<div class="wiz-field"><label>Minimum severity<span class="wiz-hint">Only findings at or above this severity notify (milestones always do).</span></label>' +
        '<select id="wizNotifSev"><option value="Critical">Critical</option><option value="High" selected>High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="Info">Info</option></select></div>' +
        '<div class="wiz-actions"><button class="wiz-btn" id="wizNotifSaveBtn">Add &amp; send test</button>' +
        '<span data-safe-style="font-size:11px;color:var(--text-muted)">Adds a channel + posts a test message. Manage all channels in Settings → Notifications.</span></div>' +
        '<div id="wizNotifResult" class="wiz-result"></div>'
      );
    }
    if (step.kind === "providers") {
      const cards = step.providers
        .map((p) => {
          const ok = (wizStatus[step.status] || {})[p.id];
          return (
            '<div class="wiz-prov" data-prov="' +
            p.id +
            '">' +
            '<div class="wiz-prov-head">' +
            esc(p.label) +
            '<span class="wiz-scope ' +
            p.scope +
            '">' +
            p.scope +
            "</span>" +
            '<span class="wiz-ok">' +
            (ok
              ? '<span data-safe-style="color:#5ad17a">✓ configured</span>'
              : '<span data-safe-style="color:#9aa4b2">○ not set</span>') +
            "</span></div>" +
            wizRenderFields(p.fields) +
            '<div class="wiz-actions"><button class="wiz-btn" data-save-prov="' +
            p.id +
            '">Save</button>' +
            '<span class="wiz-result" data-res-prov="' +
            p.id +
            '"></span></div></div>'
          );
        })
        .join("");
      return (
        "<h3>" +
        step.icon +
        " " +
        esc(step.label) +
        "</h3>" +
        '<p class="wiz-sub">' +
        esc(step.blurb) +
        "</p>" +
        (step.note
          ? '<div class="wiz-note">🛡️ ' + esc(step.note) + "</div>"
          : "") +
        '<div class="wiz-prov-list">' +
        cards +
        "</div>"
      );
    }
    return (
      "<h3>" +
      step.icon +
      " " +
      esc(step.label) +
      "</h3>" +
      '<p class="wiz-sub">' +
      esc(step.blurb) +
      "</p>" +
      (step.note
        ? '<div class="wiz-note">🛡️ ' + esc(step.note) + "</div>"
        : "") +
      wizRenderFields(step.fields) +
      '<div class="wiz-actions"><button class="wiz-btn" id="wizStepSaveBtn">Save &amp; test</button>' +
      '<span data-safe-style="font-size:11px;color:var(--text-muted)">Saved to your local .env (gitignored).</span></div>' +
      '<div id="wizStepResult" class="wiz-result"></div>'
    );
  }
  // Collect non-empty field values for a set of fields → { ENVKEY: value }.
  function wizCollect(fields) {
    const updates = {};
    fields.forEach((f) => {
      const el = wizEl(wizFieldId(f.key));
      if (el && el.value.trim()) updates[f.key] = el.value.trim();
    });
    return updates;
  }
  // Save → reload (live) → test. resultEl shows progress/outcome. Returns nothing.
  async function wizSaveAndTestGeneric(
    fields,
    reloadPrefix,
    test,
    resultEl,
    btn,
  ) {
    const updates = wizCollect(fields);
    if (Object.keys(updates).length === 0) {
      resultEl.style.color = "#ffb05a";
      resultEl.textContent = "Enter at least one value first.";
      return;
    }
    if (btn) btn.disabled = true;
    resultEl.style.color = "#9aa4b2";
    resultEl.textContent = "Saving…";
    try {
      const save = await fetch("/settings/env", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ updates }),
      });
      if (!save.ok) {
        const j = await save.json().catch(() => ({}));
        resultEl.style.color = "#ff9f9f";
        resultEl.textContent =
          "Could not save: " + esc(j.error || "HTTP " + save.status);
        if (btn) btn.disabled = false;
        return;
      }
    } catch (e) {
      resultEl.style.color = "#ff9f9f";
      resultEl.textContent = "Could not reach the server: " + esc(e.message);
      if (btn) btn.disabled = false;
      return;
    }
    if (reloadPrefix) {
      resultEl.textContent = "Applying…";
      await fetch("/settings/reload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prefix: reloadPrefix }),
      }).catch(() => {});
    }
    if (test) {
      resultEl.textContent = "Testing the connection…";
      try {
        const r = await fetch(test.url, { method: test.method });
        const body = await r.json().catch(() => ({}));
        // statusKey form: a /setup/status field tells us configured (no reachability probe).
        if (test.statusKey) {
          const ok = !!body[test.statusKey];
          resultEl.style.color = ok ? "#5ad17a" : "#ffb05a";
          resultEl.textContent = ok
            ? "✓ Saved & configured."
            : "Saved, but not detected as configured yet.";
        } else if (body.ok || (body.configured && body.ok !== false)) {
          resultEl.style.color = "#5ad17a";
          resultEl.innerHTML =
            "✓ Saved & connected" +
            (body.baseUrl ? " (" + esc(body.baseUrl) + ")" : "") +
            ".";
        } else if (body.configured === false) {
          resultEl.style.color = "#ffb05a";
          resultEl.textContent =
            "Saved, but " +
            esc(body.error || "still not fully configured") +
            ".";
        } else {
          resultEl.style.color = "#ff9f9f";
          resultEl.innerHTML =
            "✗ Saved, but the test failed: " +
            esc(body.error || "unreachable") +
            ".";
        }
      } catch (e) {
        resultEl.style.color = "#ff9f9f";
        resultEl.textContent = "Saved, but the test failed: " + esc(e.message);
      }
    } else {
      resultEl.style.color = "#5ad17a";
      resultEl.textContent = "✓ Saved.";
    }
    if (btn) btn.disabled = false;
    await wizRefreshStatus();
  }

  // Render the dynamic pane for a step + wire its buttons.
  function wizShowStep(stepId) {
    wizCurrent = stepId;
    const isAi = stepId === "ai";
    wizEl("wizPaneAi").style.display = isAi ? "" : "none";
    wizEl("wizPaneDynamic").style.display = isAi ? "none" : "";
    if (isAi) {
      wizRenderRail();
      wizUpdateNav();
      return;
    }
    const step = wizardStepById(stepId);
    const pane = wizEl("wizPaneDynamic");
    pane.innerHTML = wizRenderStep(step);
    if (step.kind === "providers") {
      step.providers.forEach((p) => {
        const btn = pane.querySelector('[data-save-prov="' + p.id + '"]');
        const res = pane.querySelector('[data-res-prov="' + p.id + '"]');
        if (btn)
          btn.onclick = () =>
            wizSaveAndTestGeneric(p.fields, p.reload, null, res, btn);
      });
    } else if (step.kind === "notifications") {
      const btn = wizEl("wizNotifSaveBtn");
      if (btn) btn.onclick = wizSaveNotification;
    } else {
      const btn = wizEl("wizStepSaveBtn"),
        res = wizEl("wizStepResult");
      if (btn)
        btn.onclick = () =>
          wizSaveAndTestGeneric(step.fields, step.reload, step.test, res, btn);
    }
    wizRenderRail();
    wizUpdateNav();
  }

  // Notifications step: add a webhook channel via the dedicated /notifications API (NOT /settings/env —
  // notifications live in a global config file), then send a test message to it. On 501 the feature is
  // off (no notificationStore); surface that. Refreshes /setup/status so the rail flips ✓.
  async function wizSaveNotification() {
    const type = wizEl("wizNotifType").value;
    const url = wizEl("wizNotifUrl").value.trim();
    const minSeverity = wizEl("wizNotifSev").value;
    const res = wizEl("wizNotifResult"),
      btn = wizEl("wizNotifSaveBtn");
    if (!/^https?:\/\//i.test(url)) {
      res.style.color = "#ffb05a";
      res.textContent = "Enter the incoming-webhook URL (https://…).";
      return;
    }
    btn.disabled = true;
    res.style.color = "#9aa4b2";
    res.textContent = "Adding channel…";
    let channelId;
    try {
      const add = await fetch("/notifications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, webhookUrl: url, minSeverity }),
      });
      const body = await add.json().catch(() => ({}));
      if (add.status === 501) {
        res.style.color = "#ffb05a";
        res.textContent = "Notifications aren't enabled on this server.";
        btn.disabled = false;
        return;
      }
      if (!add.ok) {
        res.style.color = "#ff9f9f";
        res.textContent =
          "Could not add channel: " + esc(body.error || "HTTP " + add.status);
        btn.disabled = false;
        return;
      }
      channelId = body.id;
    } catch (e) {
      res.style.color = "#ff9f9f";
      res.textContent = "Could not reach the server: " + esc(e.message);
      btn.disabled = false;
      return;
    }
    res.textContent = "Sending a test message…";
    try {
      const t = await fetch("/notifications/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channelId }),
      });
      const tb = await t.json().catch(() => ({}));
      const r0 = Array.isArray(tb.results) ? tb.results[0] : null;
      if (t.ok && r0 && r0.ok !== false && !r0.error) {
        res.style.color = "#5ad17a";
        res.innerHTML =
          "✓ Channel added — test message sent to <strong>" +
          esc(type) +
          "</strong>. Check the channel.";
      } else {
        res.style.color = "#ffb05a";
        res.innerHTML =
          "Channel added, but the test failed: " +
          esc((r0 && r0.error) || tb.error || "no response") +
          ". Edit it in Settings → Notifications.";
      }
    } catch (e) {
      res.style.color = "#ffb05a";
      res.textContent =
        "Channel added, but the test request failed: " + esc(e.message);
    }
    btn.disabled = false;
    await wizRefreshStatus();
  }

  // Left rail: one row per step, with a ✓ (configured) / ○ (optional) dot.
  function wizRenderRail() {
    const rail = wizEl("wizRail");
    rail.innerHTML = wizardOrder()
      .map((id) => {
        const label = id === "ai" ? "AI analysis" : wizardStepById(id).label;
        const icon = id === "ai" ? "👋" : wizardStepById(id).icon;
        let done = false;
        if (id === "ai") done = !!wizStatus.ai;
        else {
          const st = wizStatus[wizardStepById(id).status];
          done =
            typeof st === "object"
              ? Object.values(st || {}).some(Boolean)
              : !!st;
        }
        const cls =
          "wiz-rail-item" +
          (id === wizCurrent ? " active" : "") +
          (done ? " done" : "");
        return (
          '<div class="' +
          cls +
          '" data-step="' +
          id +
          '"><span class="wiz-rail-dot">' +
          (done ? "✓" : "○") +
          "</span>" +
          '<span class="wiz-rail-label">' +
          icon +
          " " +
          esc(label) +
          "</span></div>"
        );
      })
      .join("");
    rail.querySelectorAll(".wiz-rail-item").forEach((el) => {
      el.onclick = () => wizShowStep(el.getAttribute("data-step"));
    });
  }
  function wizUpdateNav() {
    const i = wizardOrder().indexOf(wizCurrent);
    wizEl("wizBackBtn").disabled = i <= 0;
    wizEl("wizNextBtn").disabled = i >= wizardOrder().length - 1;
  }
  async function wizRefreshStatus() {
    try {
      wizStatus = await (await fetch("/setup/status")).json();
    } catch {
      wizStatus = {};
    }
    wizRenderRail();
  }

  function openSetupWizard() {
    wizResetAiStep();
    wizCurrent = "ai";
    wizEl("wizPaneAi").style.display = "";
    wizEl("wizPaneDynamic").style.display = "none";
    wizEl("wizOverlay").classList.add("open");
    wizRefreshStatus(); // fills the rail ✓/○, async
    wizRenderRail();
    wizUpdateNav();
  }
  // Mark the wizard as dismissed so it does NOT auto-show again on refresh. Both "Done" and "Skip"
  // mean "I'm finished with this for now" — the ONLY way it reappears afterwards is an explicit
  // launch from Settings (which clears this flag). Escape just closes the overlay without dismissing.
  function wizMarkDismissed() {
    try {
      localStorage.setItem(WIZ_DISMISS_KEY, "1");
    } catch {}
  }
  function closeSetupWizard() {
    wizEl("wizOverlay").classList.remove("open");
  }
  function wizDone() {
    wizMarkDismissed();
    closeSetupWizard();
  }
  function wizDismiss() {
    wizMarkDismissed();
    closeSetupWizard();
  }

  function maybeShowSetupWizard() {
    let dismissed = false;
    try {
      dismissed = localStorage.getItem(WIZ_DISMISS_KEY) === "1";
    } catch {}
    if (dismissed) return;
    fetch("/health")
      .then((r) => r.json())
      .then((h) => {
        if (h && h.aiEnabled === false) openSetupWizard();
      })
      .catch(() => {});
  }
  async function fetchLogLevel() {
    try {
      const r = await fetch("/log-level");
      if (!r.ok) return;
      const j = await r.json();
      const sel = document.getElementById("logLevelSelect");
      if (sel && j.level) sel.value = j.level;
    } catch {
      /* leave the select at its default */
    }
  }

  // Everything the inline block ran at module scope, in its original order.
  function initSetupWizard() {
    wizEl("wizSynthSaveBtn").onclick = wizSaveSynth;
    wizEl("wizDismissBtn").onclick = wizDismiss;
    wizEl("wizDoneBtn").onclick = wizDone;
    wizEl("wizBackBtn").onclick = () => {
      const i = wizardOrder().indexOf(wizCurrent);
      if (i > 0) wizShowStep(wizardOrder()[i - 1]);
    };
    wizEl("wizNextBtn").onclick = () => {
      const i = wizardOrder().indexOf(wizCurrent);
      if (i < wizardOrder().length - 1) wizShowStep(wizardOrder()[i + 1]);
    };
    wizEl("wizOverlay").addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeSetupWizard();
    });

    // Settings → AI "Re-run the setup wizard" link (#181) — now opens the full Setup wizard.
    const rerunLink = document.getElementById("rerunAiWizard");
    if (rerunLink)
      rerunLink.onclick = (e) => {
        e.preventDefault();
        try {
          localStorage.removeItem(WIZ_DISMISS_KEY);
        } catch {}
        closeSettingsModal();
        openSetupWizard();
      };
    // Settings → General "⚙ Open setup wizard" launcher. Clears the dismissal flag (an explicit launch
    // means the user wants the wizard again) so closing with Escape later behaves predictably.
    const setupLauncher = document.getElementById("openSetupWizard");
    if (setupLauncher)
      setupLauncher.onclick = (e) => {
        e.preventDefault();
        try {
          localStorage.removeItem(WIZ_DISMISS_KEY);
        } catch {}
        closeSettingsModal();
        openSetupWizard();
      };

    // First-run: auto-show the wizard ONCE when AI isn't configured and the user hasn't dismissed it.
    // After a Done/Skip the dismissal flag is set and the wizard never auto-shows again (even on refresh
    // or an emptied .env) — it returns ONLY via the Settings launchers, which clear the flag.
    maybeShowSetupWizard();

    // Live log-verbosity control (no restart — server + pipeline share one logger).
    document
      .getElementById("logLevelSelect")
      .addEventListener("change", async (e) => {
        const level = e.target.value;
        try {
          const r = await fetch("/log-level", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ level }),
          });
          const msg = document.getElementById("settingsSaveMsg");
          if (msg) {
            msg.textContent = r.ok
              ? `Log level set to ${level}.`
              : "Could not change log level — restart the server?";
            setTimeout(() => {
              msg.textContent = "";
            }, 3000);
          }
        } catch {
          /* network/404 — server likely stale */
        }
      });
  }

  window.openSetupWizard = openSetupWizard;
  window.closeSetupWizard = closeSetupWizard;
  window.wizRefreshStatus = wizRefreshStatus;
  window.fetchLogLevel = fetchLogLevel;
  window.initSetupWizard = initSetupWizard;
})();
