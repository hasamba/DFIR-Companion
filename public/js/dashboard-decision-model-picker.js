// Settings → Decision model: the model picker (#2224).
//
// Jev stopped being the only decision model — OpenRouter lists ~30 of them — so on the OpenRouter
// provider the Model field offers that list, and ONLY that list: GET /settings/jev/models is the
// server's cached copy of OpenRouter's decision-model catalog (the page's CSP keeps the browser off
// openrouter.ai). Each entry carries its price, or "free".
//
// The saved value is still the plain text box #env-DFIR_JEV_MODEL, so the generic settings save
// (every `env-*` id) needs nothing new. The list only ever WRITES that box when the analyst picks an
// entry; loading a list never rewrites a saved model. A model the list does not have — a private
// id, an older version, a list that would not load — stays typeable.
//
// TypeSafe serves Jev only, so on that provider there is nothing to pick and the list hides.
//
// Same combo-box look as the other AI model pickers in js/dashboard-env-settings.js, kept separate
// because this list has labels and prices and that one is a list of bare ids.
(function () {
  const CUSTOM = "__custom__";
  const DEFAULT_MODEL = "typesafe/jev-1.14";
  const PROVIDER_ID = "env-DFIR_JEV_PROVIDER";
  const MODEL_ID = "env-DFIR_JEV_MODEL";
  const PICKER_ID = "decision-model-picker";
  // Bumped by every refresh: an answer that comes back to an older request paints nothing.
  let requestVersion = 0;

  const el = (id) => document.getElementById(id);

  function setStatus(text) {
    const status = el("decision-model-status");
    if (status) status.textContent = text;
  }

  function option(value, label) {
    const o = document.createElement("option");
    o.value = value;
    o.textContent = label;
    return o;
  }

  function priceLabel(m) {
    if (m.free) return `${m.name} — free`;
    if (typeof m.inputPerMillionUSD === "number" && isFinite(m.inputPerMillionUSD)) {
      return `${m.name} — $${m.inputPerMillionUSD} per million input tokens`;
    }
    return m.name;
  }

  /** The list hidden, the text box shown: TypeSafe, a failed load, or no page markup to fill. */
  function textBoxOnly() {
    const picker = el(PICKER_ID);
    const input = el(MODEL_ID);
    if (picker) {
      picker.hidden = true;
      picker.disabled = true;
    }
    if (input) input.hidden = false;
  }

  function paintList(models) {
    const picker = el(PICKER_ID);
    const input = el(MODEL_ID);
    if (!picker || !input) return;
    const saved = (input.value || "").trim();
    const ids = models.map((m) => m.id);
    picker.replaceChildren(
      option("", `Default — ${DEFAULT_MODEL}`),
      ...models.map((m) => option(m.id, priceLabel(m))),
      option(CUSTOM, "Enter model ID manually…"),
    );
    picker.hidden = false;
    picker.disabled = false;
    if (!saved) picker.value = "";
    else picker.value = ids.includes(saved) ? saved : CUSTOM;
    input.hidden = picker.value !== CUSTOM;
  }

  function validModels(body) {
    const list = body && Array.isArray(body.models) ? body.models : [];
    return list.filter((m) => m && typeof m.id === "string" && typeof m.name === "string");
  }

  async function refreshDecisionModels() {
    const version = ++requestVersion;
    const provider = (el(PROVIDER_ID)?.value || "").trim();
    if (provider === "typesafe") {
      textBoxOnly();
      setStatus("TypeSafe serves Jev only — leave blank for jev-latest, or type a Jev version.");
      return;
    }
    setStatus("Loading OpenRouter decision models…");
    try {
      const res = await fetch("/settings/jev/models");
      const body = await res.json().catch(() => ({}));
      if (version !== requestVersion) return;
      if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
      const models = validModels(body);
      paintList(models);
      setStatus(
        `${models.length} decision models on OpenRouter — pick one, or enter a model ID manually.` +
          (body.stale ? " Prices may be out of date: OpenRouter could not be reached just now." : ""),
      );
    } catch (err) {
      if (version !== requestVersion) return;
      textBoxOnly();
      setStatus(`Could not load the model list: ${err.message} You can still type a model ID.`);
    }
  }

  function applyPick() {
    const picker = el(PICKER_ID);
    const input = el(MODEL_ID);
    if (!picker || !input) return;
    if (picker.value === CUSTOM) {
      input.hidden = false;
      input.focus?.();
      return;
    }
    // "" is the default entry: a blank saved model is exactly what "use the default" means.
    input.value = picker.value;
    input.hidden = true;
  }

  function initDecisionModelPicker() {
    el(PICKER_ID)?.addEventListener("change", applyPick);
    el("decision-model-refresh")?.addEventListener("click", () => void refreshDecisionModels());
    // The first paint comes from fetchEnvSettings (js/dashboard-env-settings.js) once the saved
    // values are in, so the list is matched against the SAVED model rather than an empty box.
    el(PROVIDER_ID)?.addEventListener("change", () => void refreshDecisionModels());
  }

  window.initDecisionModelPicker = initDecisionModelPicker;
  window.refreshDecisionModels = refreshDecisionModels;
})();
