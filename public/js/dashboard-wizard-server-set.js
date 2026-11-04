// Setup wizard → the default server set. The IRIS, Timesketch and Velociraptor steps
// (js/dashboard-wizard-steps.js, `serverSet: true`) save their connection fields here instead of in
// .env. The server reads those .env keys only once, to seed the "Testing" set, so a wizard that kept
// writing them there said "saved" for values nothing would ever read.
//
// A field with `set: "<tool>.<field>"` goes into the default set; every other field of the step (the
// global TLS opt-in, the Velociraptor binary) still goes to .env. A secret left blank is not sent:
// the set keeps the stored value. With no default set, the wizard creates "Testing" and makes it the
// default. Holds no state.
(function () {
  "use strict";

  const TOOLS = ["iris", "timesketch", "velociraptor"];
  const FIRST_SET = "Testing";

  function typed(field) {
    const id = typeof wizFieldId === "function" ? wizFieldId(field.key) : "wizf-" + field.key;
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }

  // "true"/"1"/"yes" and "false"/"0"/"no", the wording the .env flags always accepted.
  function asBool(text) {
    return /^(true|1|yes|on)$/i.test(text);
  }

  /** The step's typed values, split into the default-set patch and the .env updates. */
  function splitStep(fields) {
    const env = {};
    const patch = {};
    for (const field of fields) {
      const value = typed(field);
      if (!value) continue;
      if (!field.set) {
        env[field.key] = value;
        continue;
      }
      const [tool, name] = field.set.split(".");
      patch[tool] = { ...(patch[tool] || {}), [name]: field.bool ? asBool(value) : value };
    }
    return { env, patch: Object.keys(patch).length ? patch : null };
  }

  async function send(method, url, body) {
    const res = await fetch(url, {
      method,
      headers: { "content-type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    let json = {};
    try {
      json = await res.json();
    } catch {
      json = {};
    }
    if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
    return json;
  }

  /** Merges `patch` into the default set (or creates "Testing"). Returns the set's name. */
  async function saveToDefaultSet(patch) {
    if (typeof fetchServerSets !== "function") throw new Error("server sets are not available");
    const list = await fetchServerSets();
    // A member gets names only: a merge onto that would wipe every field of the set.
    if (!list.editable) throw new Error("only an administrator can change server sets");
    const current = list.sets.find((s) => s.id === list.defaultId);
    if (!current) {
      const made = await send("POST", "/server-sets", { name: FIRST_SET, ...patch });
      await send("POST", `/server-sets/${encodeURIComponent(made.id)}/default`);
      return made.name || FIRST_SET;
    }
    const body = { name: current.name };
    for (const tool of TOOLS) {
      if (current[tool] || patch[tool]) body[tool] = { ...(current[tool] || {}), ...(patch[tool] || {}) };
    }
    const saved = await send("PUT", `/server-sets/${encodeURIComponent(current.id)}`, body);
    return saved.name || current.name;
  }

  async function saveEnv(step, env) {
    const keys = Object.keys(env);
    if (keys.length === 0) return;
    await send("POST", "/settings/env", { updates: env });
    const prefixes = new Set();
    if (step.reload && keys.some((k) => k.startsWith(step.reload))) prefixes.add(step.reload);
    for (const f of step.fields) if (f.reload && env[f.key]) prefixes.add(f.reload);
    for (const prefix of prefixes) await send("POST", "/settings/reload", { prefix }).catch(() => {});
  }

  async function testLine(test) {
    if (!test) return "";
    try {
      const res = await fetch(test.url, { method: test.method });
      const body = await res.json().catch(() => ({}));
      if (body.ok) return " ✓ Connected.";
      return ` The connection test failed: ${body.error || "unreachable"}.`;
    } catch (e) {
      return ` The connection test failed: ${e.message || "unreachable"}.`;
    }
  }

  /** The wizard's Save & test for a `serverSet` step. */
  async function wizSaveServerSetStep(step, resultEl, btn) {
    const { env, patch } = splitStep(step.fields);
    if (!patch && Object.keys(env).length === 0) {
      resultEl.style.color = "#ffb05a";
      resultEl.textContent = "Enter at least one value first.";
      return;
    }
    if (btn) btn.disabled = true;
    resultEl.style.color = "#9aa4b2";
    resultEl.textContent = "Saving…";
    try {
      const name = patch ? await saveToDefaultSet(patch) : "";
      await saveEnv(step, env);
      const saved = name
        ? `Saved to the default server set (${name}). Edit sets in Settings → Server sets.`
        : "✓ Saved.";
      resultEl.textContent = "Testing the connection…";
      const tested = await testLine(step.test);
      resultEl.style.color = tested.includes("failed") ? "#ffb05a" : "#5ad17a";
      resultEl.textContent = saved + tested; // text only: names and errors come from outside
    } catch (e) {
      resultEl.style.color = "#ff9f9f";
      resultEl.textContent = "Could not save: " + (e.message || "");
    }
    if (btn) btn.disabled = false;
    if (typeof wizRefreshStatus === "function") await wizRefreshStatus();
  }

  window.wizSaveServerSetStep = wizSaveServerSetStep;
})();
