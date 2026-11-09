// Settings → a "Clear" control beside every masked secret that is set (#2465).
//
// Secrets load blank behind an "(already set)" placeholder, so emptying the box is not a change and
// there was no way to remove a leaked key or switch an integration off without editing .env by
// hand. Clear marks the field; js/dashboard-env-settings.js sends a marked field in `unset` (the
// #1785 path, which the server checks against the same allowlist). Typing a value cancels the mark,
// and pressing Clear again undoes it.
//
// The control's id is `secretclear-<KEY>`, deliberately NOT `env-…`: the save loop treats every
// `[id^='env-']` element as a setting.
(function () {
  const SET_HINT = "(already set)";
  const PENDING_HINT = "(will be removed on save)";

  function controlFor(el) {
    return document.getElementById("secretclear-" + el.id.replace(/^env-/, ""));
  }

  function setMark(el, on) {
    const btn = controlFor(el);
    if (on) el.dataset.envClearPending = "1";
    else delete el.dataset.envClearPending;
    el.placeholder = on ? PENDING_HINT : SET_HINT;
    if (btn) {
      btn.textContent = on ? "Undo clear" : "Clear";
      btn.setAttribute?.("aria-pressed", on ? "true" : "false");
    }
  }

  function createControl(el) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.id = "secretclear-" + el.id.replace(/^env-/, "");
    btn.className = "env-secret-clear";
    btn.textContent = "Clear";
    btn.title = "Remove this secret from .env when you save";
    btn.addEventListener("click", () => {
      const on = el.dataset.envClearPending !== "1";
      if (on) el.value = "";
      setMark(el, on);
    });
    if (typeof el.insertAdjacentElement === "function") el.insertAdjacentElement("afterend", btn);
    return btn;
  }

  /** Called for every secret field as Settings load; `isSet` = the server masked a value. */
  function decorateSecretClear(el, isSet) {
    if (!el?.dataset) return;
    let btn = controlFor(el);
    if (!btn && isSet) btn = createControl(el);
    if (el.dataset.secretClearWired !== "1") {
      el.dataset.secretClearWired = "1";
      el.addEventListener("input", () => {
        if (el.value && el.dataset.envClearPending === "1") setMark(el, false);
      });
    }
    delete el.dataset.envClearPending;
    if (btn) {
      btn.hidden = !isSet;
      btn.textContent = "Clear";
    }
  }

  /** True when the analyst pressed Clear on this field and has not typed a value since. */
  function secretClearPending(el) {
    return el?.dataset?.envClearPending === "1";
  }

  /** After a successful save: the removed secrets now read "(not set)" and lose their control. */
  function secretClearSettle(keys) {
    for (const key of keys) {
      const el = document.getElementById("env-" + key);
      if (!secretClearPending(el)) continue;
      delete el.dataset.envClearPending;
      el.placeholder = "(not set)";
      const btn = controlFor(el);
      if (btn) btn.hidden = true;
    }
  }

  window.decorateSecretClear = decorateSecretClear;
  window.secretClearPending = secretClearPending;
  window.secretClearSettle = secretClearSettle;
})();
