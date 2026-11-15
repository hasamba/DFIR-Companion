// Two Settings warnings for Watson (phase 5), shown under the field they concern:
//  - "Watson lookups per question": Watson can make several lookups for each question, and no Watson
//    cost or token limit is set.
//  - "Watson provider": the provider is set, but Watson has no model or no key, so it cannot answer.
// Both update as the analyst types. dashboard-env-settings.js calls watsonLimitWarnRefresh() once the
// saved values are loaded. The text is fixed; nothing from the server is put into the page here.
(function () {
  const ID = (k) => "env-DFIR_AI_" + k;
  const LIMIT_TEXT =
    "Watson can make several lookups for each question, and no Watson cost or token limit is set. Set a limit to control cost.";
  const PROVIDER_TEXT =
    "Watson provider is set, but its model or key is missing. Watson will not answer until you set them.";
  const NO_KEY = new Set(["claude-code", "codex"]);
  const LOCAL_HOST = /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)$/i;
  const SAVED = "(already set)";

  const el = (id) => document.getElementById(id);
  const val = (id) => String((el(id) || {}).value || "").trim();
  const isSaved = (id) => String((el(id) || {}).placeholder || "") === SAVED;
  let wired = false;

  function positive(id) {
    const n = Number(val(id));
    return val(id) !== "" && Number.isFinite(n) && n > 0;
  }

  function lookupsOn() {
    const text = val(ID("WATSON_MAX_TOOL_CALLS"));
    const n = Number(text);
    // Same as the server: blank, not a number or negative = the default (on); otherwise the whole part.
    return text === "" || !Number.isFinite(n) || n < 0 || Math.floor(n) > 0;
  }

  const limitMissing = () => lookupsOn() && !positive(ID("WATSON_COST_LIMIT_USD")) && !positive(ID("WATSON_TOKEN_LIMIT"));

  function localBase(provider) {
    const base = val(ID("WATSON_BASE_URL")) || val(ID("BASE_URL_" + provider.toUpperCase()));
    if (!base) return false;
    try {
      return LOCAL_HOST.test(new URL(base).hostname);
    } catch {
      return false;
    }
  }

  function needsKey(provider) {
    if (NO_KEY.has(provider)) return false;
    if ((provider === "ollama" || provider === "litellm") && localBase(provider)) return false;
    return true;
  }

  function keyMissing(provider) {
    if (!needsKey(provider) || val(ID("WATSON_KEY"))) return false;
    const slot = ID("KEY_" + provider.toUpperCase());
    return !(isSaved(ID("WATSON_KEY")) || val(slot) || isSaved(slot) || val("env-DFIR_VISION_KEY") || isSaved("env-DFIR_VISION_KEY"));
  }

  function providerMissing() {
    const provider = val(ID("WATSON_PROVIDER")).toLowerCase();
    if (!provider) return false;
    const synthesis = (val(ID("SYNTH_PROVIDER")) || val("env-DFIR_VISION_PROVIDER")).toLowerCase();
    if (!val(ID("WATSON_MODEL")) && provider !== synthesis) return true;
    return keyMissing(provider);
  }

  // The notice sits at the end of the field's own row. It is made once and only shown or hidden.
  function notice(forId, text) {
    const id = "watsonWarn-" + forId;
    let box = el(id);
    if (box) return box;
    const input = el(forId);
    if (!input || !input.parentElement) return null;
    box = document.createElement("div");
    box.id = id;
    box.className = "sfield-hint";
    box.setAttribute("role", "status");
    box.textContent = "⚠ " + text;
    box.style.display = "none";
    input.parentElement.appendChild(box);
    return box;
  }

  function show(forId, text, on) {
    const box = notice(forId, text);
    if (box) box.style.display = on ? "block" : "none";
  }

  function watsonLimitWarnRefresh() {
    if (!wired) {
      wired = true;
      for (const k of ["WATSON_MAX_TOOL_CALLS", "WATSON_COST_LIMIT_USD", "WATSON_TOKEN_LIMIT", "WATSON_PROVIDER", "WATSON_MODEL", "WATSON_KEY", "WATSON_BASE_URL", "SYNTH_PROVIDER"]) {
        const input = el(ID(k));
        if (!input) continue;
        input.addEventListener("input", watsonLimitWarnRefresh);
        input.addEventListener("change", watsonLimitWarnRefresh);
      }
    }
    show(ID("WATSON_MAX_TOOL_CALLS"), LIMIT_TEXT, limitMissing());
    show(ID("WATSON_PROVIDER"), PROVIDER_TEXT, providerMissing());
  }

  window.watsonLimitWarnRefresh = watsonLimitWarnRefresh;
})();
