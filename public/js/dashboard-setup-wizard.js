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
    if (step.kind === "presidio") {
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
        '<div id="wizPresidioWarn" class="wiz-note" data-safe-style="display:none;border-left-color:#e0a458"></div>' +
        '<div class="wiz-actions"><button class="wiz-btn" id="wizPresidioSaveBtn">Save</button>' +
        '<button class="wiz-btn secondary" id="wizPresidioTestBtn">Test connection</button>' +
        '<span data-safe-style="font-size:11px;color:var(--text-muted)">Saved to your local .env (gitignored), and read at startup.</span></div>' +
        '<div id="wizPresidioResult" class="wiz-result"></div>'
      );
    }
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
        '<div class="wiz-field"><label>Channel type<span class="wiz-hint">Slack / Teams / Mattermost / Discord use an incoming-webhook URL. Telegram uses a bot token and a chat ID.</span></label>' +
        '<select id="wizNotifType"><option value="slack">Slack</option><option value="teams">MS Teams</option><option value="mattermost">Mattermost</option><option value="discord">Discord</option><option value="telegram">Telegram bot</option></select></div>' +
        '<div class="wiz-field" id="wizNotifUrlRow"><label>Webhook URL</label><input id="wizNotifUrl" placeholder="https://hooks.slack.com/services/…" autocomplete="off" /></div>' +
        '<div id="wizNotifTgRows" data-safe-style="display:none">' +
        '<div class="wiz-field"><label>Bot token<span class="wiz-hint">From @BotFather. Leave it blank to reuse the war-room bot\'s DFIR_TELEGRAM_BOT_TOKEN — the token then lives in .env only, and rotating it there is enough.</span></label>' +
        '<input id="wizNotifTgToken" type="password" placeholder="Bot token (123456789:AAF…)" autocomplete="new-password" /></div>' +
        '<div class="wiz-field"><label>Chat ID<span class="wiz-hint">A @channel name, or a numeric id like -1001234567890. Check it points where you mean — notifications carry case content.</span></label>' +
        '<input id="wizNotifTgChatId" list="wizNotifTgChats" placeholder="Chat ID" autocomplete="off" /><datalist id="wizNotifTgChats"></datalist></div>' +
        "</div>" +
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
    okText,
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
    // The step's prefix, plus any per-field reload override that was actually saved (a field whose
    // key sits outside the step's family — e.g. the global DFIR_TLS_ALLOW_INSECURE_EXTERNAL on the
    // IRIS step — would otherwise stay in .env until a restart while the test below runs stale).
    const reloadPrefixes = [
      ...new Set(
        [reloadPrefix]
          .concat(fields.filter((f) => f.reload && updates[f.key]).map((f) => f.reload))
          .filter(Boolean),
      ),
    ];
    if (reloadPrefixes.length) {
      resultEl.textContent = "Applying…";
      for (const prefix of reloadPrefixes) {
        await fetch("/settings/reload", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prefix }),
        }).catch(() => {});
      }
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
      resultEl.textContent = okText || "✓ Saved.";
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
      wizEl("wizNotifType").onchange = wizNotifTypeChanged;
      wizNotifTypeChanged();
      wizLoadNotifTelegramHints();
    } else if (step.kind === "presidio") {
      wizEl("wizPresidioSaveBtn").onclick = wizSavePresidio;
      wizEl("wizPresidioTestBtn").onclick = wizTestPresidio;
      wizEl(wizFieldId("DFIR_PRESIDIO_URL")).oninput = wizPresidioLocalWarning;
    } else {
      const btn = wizEl("wizStepSaveBtn"),
        res = wizEl("wizStepResult");
      if (btn)
        btn.onclick = () =>
          wizSaveAndTestGeneric(step.fields, step.reload, step.test, res, btn);
    }
    // Path fields render their own Browse… / Download-latest buttons (wizRenderFields), and this
    // pane is rebuilt on every visit — so they are re-bound here rather than once at load.
    if (typeof wirePathBrowseControls === "function") wirePathBrowseControls(pane);
    wizRenderRail();
    wizUpdateNav();
  }

  // ── Presidio step ──
  // Everything here exists because DFIR_PRESIDIO_ is the one family in the step table that
  // /settings/reload will not apply: the analyzer client is built once at startup, so a save is
  // only half the job and the step has to say so. Hence Save and Test are separate buttons — Test
  // probes the URL as TYPED (nothing is saved), and Save reports "restart" rather than "connected".
  function wizPresidioUrl() {
    const el = wizEl(wizFieldId("DFIR_PRESIDIO_URL"));
    return el ? el.value.trim() : "";
  }
  // The same warning Settings → AI shows, for the same reason: Presidio reads the case text —
  // masked, but still the timeline — so a non-local analyzer sends that text off this machine.
  function wizPresidioLocalWarning() {
    const warn = wizEl("wizPresidioWarn");
    if (!warn) return;
    const url = wizPresidioUrl().toLowerCase();
    const isLocal =
      !url ||
      /(?:\/\/|@)(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::|\/|$)/.test(
        url,
      );
    warn.style.display = isLocal ? "none" : "block";
    warn.textContent =
      "⚠ This Presidio URL is not local. Presidio reads your case text — masked, but still " +
      "your timeline. Pointing it at a remote host sends that text off this machine.";
  }
  // Runs the FIXED synthetic sample (never case data) through the URL currently in the box, so the
  // analyst can confirm the container answers before committing anything to .env.
  async function wizTestPresidio() {
    const res = wizEl("wizPresidioResult");
    const btn = wizEl("wizPresidioTestBtn");
    const url = wizPresidioUrl();
    if (!url) {
      res.style.color = "#ffb05a";
      res.textContent = "Enter the analyzer URL first.";
      return;
    }
    btn.disabled = true;
    res.style.color = "#9aa4b2";
    res.textContent = "Testing…";
    try {
      const r = await fetch("/system/presidio-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const body = await r.json().catch(() => ({}));
      if (body.error) {
        res.style.color = "#ff9f9f";
        // Node's fetch reports a refused or unroutable host as the bare string "fetch failed",
        // which reads as "Failed: fetch failed" — say what actually happened instead.
        res.textContent = /^fetch failed$/i.test(body.error)
          ? "✗ Failed — could not reach that URL"
          : "✗ Failed: " + esc(body.error);
        btn.disabled = false;
        return;
      }
      res.style.color = "#5ad17a";
      res.textContent =
        "✓ Connected — now Save, then restart the server to activate it.";
    } catch (e) {
      res.style.color = "#ff9f9f";
      res.textContent = "Could not reach the server: " + esc(e.message);
    }
    btn.disabled = false;
  }
  async function wizSavePresidio() {
    await wizSaveAndTestGeneric(
      wizardStepById("presidio").fields,
      null, // NOT reloadable — /settings/reload rejects this prefix by design
      null, // and testing the SAVED value would need a restart first, so Test is its own button
      wizEl("wizPresidioResult"),
      wizEl("wizPresidioSaveBtn"),
      "✓ Saved to .env. Restart the server to activate the layer — these three keys are read at startup.",
    );
  }

  // ── Notifications step ──
  // Telegram takes a bot token and a chat ID instead of a webhook URL, so the two field groups
  // swap. Severity, the add, and the test send are shared.
  function wizNotifTypeChanged() {
    const telegram = wizEl("wizNotifType").value === "telegram";
    wizEl("wizNotifUrlRow").style.display = telegram ? "none" : "";
    wizEl("wizNotifTgRows").style.display = telegram ? "" : "none";
  }
  // Ask /notifications/status the two things the Telegram fields cannot answer for themselves:
  // whether .env already carries a bot token (else an operator who configured the war-room bot
  // sees an empty box and pastes the same token twice), and which chats that bot is already bound
  // to. Best-effort: typing both values by hand still works if this never answers.
  async function wizLoadNotifTelegramHints() {
    let status;
    try {
      status = await (await fetch("/notifications/status")).json();
    } catch {
      return;
    }
    // The await above outlives the pane: a click on another rail item replaced this markup, and
    // the ids below would then resolve to nothing or, worse, to a re-rendered pane's fields.
    if (wizCurrent !== "notifications") return;
    const token = wizEl("wizNotifTgToken");
    if (token && status.telegramEnvToken)
      token.placeholder =
        "Bot token — (already set) in .env, leave blank to use it";
    const input = wizEl("wizNotifTgChatId");
    const list = wizEl("wizNotifTgChats");
    if (!input || !list) return;
    const prefill = ntfChatPrefill(status.telegramChats || []);
    list.replaceChildren(
      ...prefill.options.map((o) => {
        const opt = document.createElement("option");
        opt.value = o.value;
        opt.label = o.label;
        return opt;
      }),
    );
    // Pre-filled into a VISIBLE field, never silently defaulted — this is where case content will
    // be sent, so the analyst sees the destination and can change it before Add.
    if (!input.value) input.value = prefill.value;
  }

  // Notifications step: add a webhook channel via the dedicated /notifications API (NOT /settings/env —
  // notifications live in a global config file), then send a test message to it. On 501 the feature is
  // off (no notificationStore); surface that. Refreshes /setup/status so the rail flips ✓.
  async function wizSaveNotification() {
    const type = wizEl("wizNotifType").value;
    const minSeverity = wizEl("wizNotifSev").value;
    const res = wizEl("wizNotifResult"),
      btn = wizEl("wizNotifSaveBtn");
    // `payload`, not `body`: the try below declares its own `const body` for the RESPONSE, in the
    // same block as this send — which puts this name in that block's temporal dead zone and throws
    // "Cannot access 'body' before initialization" on every add.
    const payload = { type, minSeverity };
    if (type === "telegram") {
      const chatId = wizEl("wizNotifTgChatId").value.trim();
      if (!chatId) {
        res.style.color = "#ffb05a";
        res.textContent = "Enter the chat ID the bot should post to.";
        return;
      }
      // A blank token is legitimate — the server falls back to DFIR_TELEGRAM_BOT_TOKEN, and 400s
      // with its own message when there is nothing to fall back to.
      payload.telegram = { botToken: wizEl("wizNotifTgToken").value, chatId };
    } else {
      const url = wizEl("wizNotifUrl").value.trim();
      if (!/^https?:\/\//i.test(url)) {
        res.style.color = "#ffb05a";
        res.textContent = "Enter the incoming-webhook URL (https://…).";
        return;
      }
      payload.webhookUrl = url;
    }
    btn.disabled = true;
    res.style.color = "#9aa4b2";
    res.textContent = "Adding channel…";
    let channelId;
    try {
      const add = await fetch("/notifications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
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
