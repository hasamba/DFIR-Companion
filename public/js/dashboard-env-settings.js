// The .env settings form — reading the current values, testing the Presidio connection, and
// saving only the groups the analyst actually touched (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS loadedEnvValues: what the fields held when the modal was last
// populated. Save submits every field, and this is how the code tells which groups changed — so
// one save does not rebuild every integration client on the server (#178). As a page-wide global
// that snapshot was one stray assignment away from being wrong.
(function () {
  // What the .env fields held when the modal was last populated. Save submits EVERY field, so this
  // is how we tell which groups the analyst actually TOUCHED and therefore which to apply live —
  // without it, one save would rebuild every integration client on the server (#178).
  let loadedEnvValues = {};
  const CUSTOM_MODEL_VALUE = "__custom__";
  const MANUAL_MODEL_LABEL = "Enter model ID manually…";
  const modelRequestVersions = new Map();
  const AI_MODEL_PICKERS = [
    {
      role: "vision",
      providerId: "env-DFIR_VISION_PROVIDER",
      modelId: "env-DFIR_VISION_MODEL",
      keyId: "env-DFIR_VISION_KEY",
      baseUrlId: "env-DFIR_VISION_BASE_URL",
      // Vision IS the fallback every other role borrows from, so it has none of its own.
      fallbackProviderId: "",
      fallbackKeyId: "",
      fallbackBaseUrlId: "",
    },
    {
      role: "synthesis",
      providerId: "env-DFIR_AI_SYNTH_PROVIDER",
      modelId: "env-DFIR_AI_SYNTH_MODEL",
      keyId: "env-DFIR_AI_SYNTH_KEY",
      baseUrlId: "env-DFIR_AI_SYNTH_BASE_URL",
    },
    {
      role: "velociraptor",
      providerId: "env-DFIR_AI_VELO_PROVIDER",
      modelId: "env-DFIR_AI_VELO_MODEL",
      keyId: "env-DFIR_AI_VELO_KEY",
      baseUrlId: "env-DFIR_AI_VELO_BASE_URL",
    },
    {
      role: "second-opinion",
      providerId: "env-DFIR_AI_SECOND_OPINION_PROVIDER",
      modelId: "env-DFIR_AI_SECOND_OPINION_MODEL",
      keyId: "env-DFIR_AI_SECOND_OPINION_KEY",
      baseUrlId: "env-DFIR_AI_SECOND_OPINION_BASE_URL",
    },
  ];

  function fieldValue(id) {
    return (document.getElementById(id)?.value || "").trim();
  }

  // The suffix on this picker's three element ids. Separate from picker.role because role is a
  // fixed server enum and the setup wizard has its OWN vision and synthesis pickers on the same
  // page: two "vision" pickers would otherwise share one <select> and one in-flight request slot.
  function pickerKey(picker) {
    return picker.elementKey || picker.role;
  }

  // Where a role looks when its OWN provider/key/base-URL field is blank. Named per picker rather
  // than hard-coded to the Settings ids, because the setup wizard drives the same code against
  // wizProvider / wizKey / wizBaseUrl. "" means "no fallback — this role IS the fallback".
  function fallbackId(picker, field, settingsDefault) {
    return picker[field] === undefined ? settingsDefault : picker[field];
  }

  function resolvedModelProvider(picker) {
    const selected = fieldValue(picker.providerId);
    if (selected) return selected;
    if (picker.role === "velociraptor") return "openrouter";
    const id = fallbackId(picker, "fallbackProviderId", "env-DFIR_VISION_PROVIDER");
    return id ? fieldValue(id) : "";
  }

  function requestBaseUrl(picker) {
    const value = fieldValue(picker.baseUrlId);
    if (value) return value;
    const key = picker.envBaseUrlKey || picker.baseUrlId.replace(/^env-/, "");
    if (loadedEnvValues[key]) return "";
    const id = fallbackId(picker, "fallbackBaseUrlId", "env-DFIR_VISION_BASE_URL");
    return (id && fieldValue(id)) || undefined;
  }

  function modelOption(value, label, disabled = false) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    option.disabled = disabled;
    return option;
  }

  function showCustomModelInput(picker, visible, focus = false) {
    const input = document.getElementById(picker.modelId);
    if (!input) return;
    const select = document.getElementById("ai-model-picker-" + pickerKey(picker));
    const hasModels = select?.dataset.hasModels === "1";
    input.style.display = visible ? "" : "none";
    input.style.order = hasModels ? "2" : "0";
    input.style.flexBasis = hasModels ? "100%" : "0";
    if (visible && focus) input.focus();
  }

  function replaceModelOptions(picker, models) {
    const select = document.getElementById("ai-model-picker-" + pickerKey(picker));
    if (!select) return;
    const current = fieldValue(picker.modelId);
    select.replaceChildren(
      modelOption("", models.length ? "Choose a model…" : "No listed models", true),
      ...models.map((model) => modelOption(model, model)),
      modelOption(CUSTOM_MODEL_VALUE, MANUAL_MODEL_LABEL),
    );
    select.dataset.hasModels = models.length ? "1" : "0";
    select.style.display = models.length ? "" : "none";
    select.disabled = !models.length;
    if (current && models.includes(current)) {
      select.value = current;
      showCustomModelInput(picker, false);
    } else if (current || !models.length) {
      select.value = CUSTOM_MODEL_VALUE;
      showCustomModelInput(picker, true);
    } else {
      select.value = "";
      showCustomModelInput(picker, false);
    }
  }

  function showModelPickerLoading(picker) {
    const select = document.getElementById("ai-model-picker-" + pickerKey(picker));
    if (!select) return;
    const current = fieldValue(picker.modelId);
    select.replaceChildren(modelOption("", "Loading available models…", true));
    select.dataset.hasModels = "0";
    select.style.display = "";
    select.disabled = true;
    select.value = "";
    showCustomModelInput(picker, false);
  }

  function applySelectedModel(picker) {
    const select = document.getElementById("ai-model-picker-" + pickerKey(picker));
    const input = document.getElementById(picker.modelId);
    if (!select || !input) return;
    if (select.value === CUSTOM_MODEL_VALUE) {
      showCustomModelInput(picker, true, true);
      return;
    }
    if (!select.value) return;
    input.value = select.value;
    showCustomModelInput(picker, false);
  }

  async function refreshAiModels(picker) {
    const provider = resolvedModelProvider(picker);
    const status = document.getElementById("ai-model-status-" + pickerKey(picker));
    if (!provider) {
      replaceModelOptions(picker, []);
      if (status) status.textContent = "Choose a provider first.";
      return;
    }
    const version = (modelRequestVersions.get(pickerKey(picker)) || 0) + 1;
    modelRequestVersions.set(pickerKey(picker), version);
    showModelPickerLoading(picker);
    if (status) status.textContent = "Loading available models…";
    const roleKey = fieldValue(picker.keyId);
    const keyFallback = fallbackId(picker, "fallbackKeyId", "env-DFIR_VISION_KEY");
    const mainKey = keyFallback ? fieldValue(keyFallback) : "";
    const body = { provider, role: picker.role, apiKey: roleKey || mainKey };
    const baseUrl = requestBaseUrl(picker);
    if (baseUrl !== undefined) body.baseUrl = baseUrl;
    try {
      const response = await fetch("/settings/ai-models", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const result = await response.json().catch(() => ({}));
      if (modelRequestVersions.get(pickerKey(picker)) !== version) return;
      if (!response.ok) throw new Error(result.error || "model list request failed");
      const models = Array.isArray(result.models)
        ? result.models.filter((model) => typeof model === "string")
        : [];
      replaceModelOptions(picker, models);
      if (status)
        status.textContent =
          result.note ||
          (models.length
            ? `${models.length} available models — choose one or enter a model ID manually.`
            : "No models were returned; enter a model ID manually.");
    } catch (error) {
      if (modelRequestVersions.get(pickerKey(picker)) !== version) return;
      replaceModelOptions(picker, []);
      if (status)
        status.textContent =
          "Could not load models: " + error.message + " You can still type a custom ID.";
    }
  }

  // One picker. Published, because the setup wizard's AI step has the same combo box over its own
  // wizProvider / wizModel / wizKey fields and reimplementing it there is how the two drift apart.
  function wireAiModelPicker(picker) {
    const button = document.getElementById("load-ai-models-" + pickerKey(picker));
    const select = document.getElementById("ai-model-picker-" + pickerKey(picker));
    if (!button || !select || button.dataset.aiModelsWired) return;
    button.dataset.aiModelsWired = "1";
    button.addEventListener("click", () => refreshAiModels(picker));
    select.addEventListener("change", () => applySelectedModel(picker));
    document
      .getElementById(picker.providerId)
      ?.addEventListener("change", () => refreshAiModels(picker));
    document
      .getElementById(picker.keyId)
      ?.addEventListener("change", () => refreshAiModels(picker));
    document
      .getElementById(picker.baseUrlId)
      ?.addEventListener("change", () => refreshAiModels(picker));
    document.getElementById(picker.modelId)?.addEventListener("input", () => {
      select.value = CUSTOM_MODEL_VALUE;
    });
  }

  function wireAiModelPickers() {
    AI_MODEL_PICKERS.forEach(wireAiModelPicker);
  }

  async function fetchEnvSettings() {
    try {
      const r = await fetch("/settings/env");
      if (!r.ok) return;
      const { env } = await r.json();
      loadedEnvValues = {};
      for (const [key, val] of Object.entries(env)) {
        const el = document.getElementById("env-" + key);
        if (!el) continue;
        if (el.tagName === "SELECT") {
          el.value = val || "";
          el.dispatchEvent(new Event("dfir:envloaded"));
        } else if (el.type === "password") {
          // Secrets come back masked and the input starts empty, so ANY value typed here is a change.
          el.value = "";
          el.placeholder = val === "••••••••" ? "(already set)" : "(not set)";
        } else {
          el.value = val || "";
        }
        loadedEnvValues[key] = el.value;
      }
      renderPresidioLocalWarning();
      await Promise.all(AI_MODEL_PICKERS.map((picker) => refreshAiModels(picker)));
    } catch {}
  }

  // Presidio receives case text — masked, but still the timeline. Warn when the typed URL isn't
  // local (the container the analyst runs isn't necessarily on this machine), mirroring the
  // screenshot-provider local/external warning in openAnonModal.
  function renderPresidioLocalWarning() {
    const url = (document.getElementById("env-DFIR_PRESIDIO_URL")?.value || "")
      .trim()
      .toLowerCase();
    const warn = document.getElementById("presidioLocalWarning");
    if (!warn) return;
    const isLocal =
      !url ||
      /(?:\/\/|@)(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::|\/|$)/.test(
        url,
      );
    warn.style.display = isLocal ? "none" : "block";
    warn.textContent =
      "⚠ This Presidio URL is not local. Presidio receives your case text — masked, but still " +
      "your timeline. Pointing it at a remote host sends that text off this machine.";
  }

  // Test connection: sends the FIXED synthetic sample text (never anything from the case) through
  // whatever URL is currently typed — not necessarily saved yet — so the analyst can tune the
  // confidence floor before committing to Settings.
  function testPresidioConnection() {
    const url = (
      document.getElementById("env-DFIR_PRESIDIO_URL")?.value || ""
    ).trim();
    const result = document.getElementById("presidioTestResult");
    if (!result) return;
    if (!url) {
      result.style.color = "#ffb05a";
      result.textContent = "Enter a URL first.";
      return;
    }
    result.style.color = "#9aa4b2";
    result.textContent = "Testing…";
    fetch("/system/presidio-test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    })
      .then((r) => r.json())
      .then((body) => {
        if (body.error) {
          result.style.color = "#ff9f9f";
          // Node's fetch reports a refused/unroutable host as the bare string "fetch failed",
          // which reads as "Failed: fetch failed". Say what actually happened instead; any
          // other error (HTTP status, non-JSON body) is already descriptive enough to show.
          result.textContent = /^fetch failed$/i.test(body.error)
            ? "✗ Failed — could not reach that URL"
            : "✗ Failed: " + body.error;
          return;
        }
        // Connected or failed, nothing else. The raw finding list this used to print was
        // actively misleading: most of it is entity types the allow-list drops outright
        // (URL, US_BANK_NUMBER, US_DRIVER_LICENSE), so it implied things get masked that
        // never will, and mixed them in with the ones that do.
        //
        // The trailing clause is not padding. This button tests the URL as TYPED — it does
        // not save it, and the server only reads DFIR_PRESIDIO_URL at startup. A bare
        // "Connected" reads as "configured", so it is possible to test successfully, close
        // Settings, and have the layer silently inactive because it was never saved.
        result.style.color = "#5ad17a";
        result.textContent =
          "✓ Connected — now Save, then restart the server to activate it";
      })
      .catch((e) => {
        result.style.color = "#ff9f9f";
        result.textContent = "Could not reach the server: " + e.message;
      });
  }

  // Integration groups POST /settings/reload accepts (the server's own allowlist). A saved key
  // belongs to the group whose prefix it starts with; the LONGEST match wins so a nested family
  // (DFIR_AI_SYNTH_* under DFIR_AI_) reloads the group the server actually knows.
  const RELOADABLE_ENV_PREFIXES = [
    "DFIR_VISION_",
    "DFIR_AI_",
    "DFIR_IRIS_",
    "DFIR_VELOCIRAPTOR_",
    "DFIR_TIMESKETCH_",
    "DFIR_NOTION_",
    "DFIR_CLICKUP_",
    "DFIR_VT_",
    "DFIR_ABUSEIPDB_",
    "DFIR_HUNTINGCH_",
    "DFIR_MB_",
    "DFIR_CROWDSTRIKE_",
    "DFIR_SHODAN_",
    "DFIR_MISP_",
    "DFIR_YETI_",
    "DFIR_OPENCTI_",
    "DFIR_ROCKYRACCOON_",
    "DFIR_GEOIP_",
    "DFIR_LEAKCHECK_",
    "DFIR_HIBP_",
    "DFIR_DEHASHED_",
    "DFIR_PUSH_TOKEN",
    "DFIR_NSRL_",
    // Settings → KEV → "Allow an internal mirror URL" (#760). The route reads process.env per
    // request and Save only writes .env, so without this the toggle looks applied while the old
    // value keeps deciding until a restart. This list is the browser's half of a contract with
    // RELOADABLE_ENV_PREFIXES in settings/envManager.ts — adding a key to one alone does nothing.
    "DFIR_KEV_",
    "DFIR_TOOL_",
    "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
  ];

  // Apply the groups a just-saved set of .env keys belongs to, without a restart (#178).
  //
  // Returns what the server did, in the terms the save message needs:
  //   rebuilt  — components swapped out (a MISP client rebuilt against its new URL).
  //   inEffect — the saved keys that are actually DECIDING BEHAVIOUR NOW.
  //
  // "In effect" is not "applied", and the difference is the whole point (#760). Every reloadable
  // prefix gets loaded into process.env; only some of them thereby take hold. DFIR_KEV_ does — its
  // route reads process.env per request, so the load is the whole job. DFIR_AI_ does not — the
  // running analysis pipeline keeps its boot-time config, and reporting that save as live would
  // tell an analyst a model change had taken hold when it had not. The server decides which is
  // which and says so as `live`; this must not infer it from `applied`.
  async function applySavedEnvGroups(savedKeys) {
    // Keep the keys grouped by the prefix they were reloaded under, so each key can be judged by
    // what the server reported for ITS prefix rather than for the save as a whole.
    const byPrefix = new Map();
    savedKeys.forEach((key) => {
      const prefix = RELOADABLE_ENV_PREFIXES.filter((p) => key.startsWith(p)).sort(
        (a, b) => b.length - a.length,
      )[0];
      if (!prefix) return;
      if (!byPrefix.has(prefix)) byPrefix.set(prefix, []);
      byPrefix.get(prefix).push(key);
    });

    const rebuilt = [];
    const inEffect = [];
    for (const [prefix, keys] of byPrefix) {
      try {
        const r = await fetch("/settings/reload", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prefix }),
        });
        const body = await r.json().catch(() => ({}));
        const names = body.rebuilt || [];
        names.forEach((name) => {
          if (!rebuilt.includes(name)) rebuilt.push(name);
        });
        // Something was swapped out, or the server says loading the env was enough. Either way the
        // change is deciding behaviour now. `applied` is still consulted, because a key the server
        // did not report loading is not in effect whatever the prefix's nature.
        if (names.length === 0 && body.live !== true) continue;
        const applied = body.applied || [];
        keys.forEach((key) => {
          if (applied.includes(key) && !inEffect.includes(key)) inEffect.push(key);
        });
      } catch {}
    }
    return { rebuilt, inEffect };
  }

  async function saveSettings() {
    // 1. Investigator name → localStorage
    localStorage.setItem(
      "dfir.investigator",
      (document.getElementById("settingsInvestigator").value || "").trim(),
    );

    // 2. Section visibility → localStorage + apply
    const vis = {};
    SECTION_DEFS.forEach(({ id }) => {
      const cb = document.getElementById("scb-" + id);
      if (cb) vis[id] = cb.checked;
    });
    localStorage.setItem(SECTIONS_VIS_KEY, JSON.stringify(vis));
    // Saving Settings states every section's visibility outright, so it ends any palette detour
    // still standing (see the reveal set in js/dashboard-section-order.js) — otherwise unticking a
    // panel reached from the palette would leave it on screen.
    if (typeof clearSectionReveals === "function") clearSectionReveals();
    applySectionsVis();

    // 3. Env vars → POST /settings/env
    // ONLY the fields the analyst actually changed. Posting all ~250 of them (the original
    // behaviour) meant one edit dragged every other key into the request, and the server's
    // allowlist rejects a batch atomically — so changing a single Timesketch URL failed with a
    // wall of unrelated key names, and no Settings save could ever succeed. Read-only fields are
    // skipped outright: the server refuses them by design, they're rendered for reference only.
    const updates = {};
    document.querySelectorAll("[id^='env-']").forEach((el) => {
      const key = el.id.replace(/^env-/, "");
      if (el.readOnly || el.disabled) return;
      let val;
      if (el.type === "password") {
        // Secrets load blank behind a "(already set)" placeholder, so only a typed value is a change.
        val = el.value.trim();
        if (!val) return;
      } else if (el.tagName === "SELECT") {
        // A blank select is "leave whatever .env has" — it must not blank an existing key.
        if (!el.value) return;
        val = el.value;
      } else {
        val = el.value.trim();
      }
      if (val !== (loadedEnvValues[key] ?? "")) updates[key] = val;
    });
    const msg = document.getElementById("settingsSaveMsg");
    msg.textContent = "";
    let ok = true;
    if (Object.keys(updates).length > 0) {
      try {
        const r = await fetch("/settings/env", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ updates }),
        });
        if (r.ok) {
          // Saving only WRITES .env, so this used to be a flat "restart to apply" — which is how a
          // corrected MISP URL could sit on disk while the running server kept pushing to the old
          // one (#178). Now every integration group the save touched is applied live: /settings/reload
          // loads it into the environment AND rebuilds the clients it feeds, reporting them back.
          const changed = Object.keys(updates);
          const { rebuilt, inEffect } = await applySavedEnvGroups(changed);
          // The saved values are the new baseline, so saving twice without reopening the modal
          // doesn't rebuild the same clients again.
          changed.forEach((k) => {
            loadedEnvValues[k] = updates[k];
          });
          // Say what actually happened to THESE keys. Two ways to get this wrong, and the code has
          // been both: branching on `rebuilt` alone told the analyst to restart for DFIR_KEV_,
          // which was already live; branching on `applied` told them an AI model change was live
          // when the running pipeline had not moved. `inEffect` is the fact that matters, and the
          // server is the one that knows it.
          const stale = changed.filter((k) => !inEffect.includes(k));
          if (rebuilt.length > 0) {
            msg.textContent =
              "✓ Saved and applied live: " +
              rebuilt.join(", ") +
              (stale.length > 0 ? " — restart the server for the rest" : "");
            msg.style.color = "#5fd470";
          } else if (inEffect.length > 0 && stale.length === 0) {
            // Loaded into the running process, nothing to rebuild — the reload was the whole job.
            msg.textContent = "✓ Saved and applied live — no restart needed";
            msg.style.color = "#5fd470";
          } else if (inEffect.length > 0) {
            msg.textContent =
              "✓ Saved — " +
              inEffect.length +
              " of " +
              changed.length +
              " applied live; restart the server for the rest";
            msg.style.color = "#ffd93b";
          } else {
            // Nothing the server can pick up without a restart (AI models, tool paths), or the
            // reload call failed — the honest answer is still "restart".
            msg.textContent = "✓ Saved — restart the server to apply server-side changes";
            msg.style.color = "#ffd93b";
          }
        } else {
          const j = await r.json().catch(() => ({}));
          msg.textContent = "Error: " + (j.error || r.status);
          msg.style.color = "#ff7a7a";
          ok = false;
        }
      } catch {
        msg.textContent = "Could not reach server";
        msg.style.color = "#ff7a7a";
        ok = false;
      }
    } else {
      msg.textContent = "✓ No .env changes to save";
      msg.style.color = "#5fd470";
    }
    // Only the success note self-clears. An error used to vanish after 5s too, which meant a long
    // rejection message scrolled off before it could be read — errors now stay until the next save.
    if (ok)
      setTimeout(() => {
        if (msg) msg.textContent = "";
      }, 5000);
    return ok;
  }

  // Settings modal (Essential / All view) moved to js/dashboard-settings-modal.js (#415 tier 3).

  // The statements the inline block ran at module scope, in order.
  function initEnvSettings() {
    wireAiModelPickers();
    document
      .getElementById("env-DFIR_PRESIDIO_URL")
      ?.addEventListener("input", renderPresidioLocalWarning);
    document
      .getElementById("presidioTestBtn")
      ?.addEventListener("click", testPresidioConnection);
  }

  window.fetchEnvSettings = fetchEnvSettings;
  window.saveSettings = saveSettings;
  window.wireAiModelPicker = wireAiModelPicker;
  window.initEnvSettings = initEnvSettings;
})();
