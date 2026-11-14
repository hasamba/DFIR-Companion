// Watson's run mode switch: Approve (Watson proposes, the analyst decides) or Auto (Watson acts within
// the limits the server enforces). The mode lives on the case; this file shows it in the panel header
// and on the rail, and asks before Auto. dashboard-watson.js calls watsonModeSync() on every render and
// routes the "setMode" verb here. Actions ride on data-act="watsonAct"; the CSP bans inline handlers.
(function () {
  const AUTO_CONFIRM =
    "Watson will run single-host collections and write to the case without asking. Fleet-wide hunts still ask.";
  const MODES = ["approve", "auto"];
  const LABEL = { approve: "Approve", auto: "Auto" };
  const TIP = {
    approve: "Watson proposes; you approve each action",
    auto: "Watson runs single-host collections and writes to the case without asking; fleet-wide hunts still ask",
  };

  let wMode = "approve";

  const currentCase = () => String((document.getElementById("caseId") || {}).value || "").trim();

  function modeHtml(mode) {
    const btn = (m) =>
      `<button type="button" class="watson-mini watson-mode-btn${m === mode ? " watson-mode-on" : ""}" data-act="watsonAct" data-w-verb="setMode" data-mode="${m}" aria-pressed="${m === mode}" title="${escAttr(TIP[m])}">${LABEL[m]}</button>`;
    return `<span class="watson-mode-label">Mode</span>${btn("approve")}${btn("auto")}`;
  }

  const railHtml = (mode) =>
    mode === "auto" ? `<span class="watson-rail-mode" title="${escAttr(TIP.auto)}">A</span>` : "";

  function paint() {
    document.querySelectorAll('[data-w="mode"]').forEach((el) => { el.innerHTML = modeHtml(wMode); });
    document.querySelectorAll('[data-w="railmode"]').forEach((el) => { el.innerHTML = railHtml(wMode); });
  }

  // The chat the server sent carries runMode on a GET; the replies to a POST do not, so they leave it be.
  function watsonModeSync(chat) {
    if (chat && MODES.includes(chat.runMode)) wMode = chat.runMode;
    paint();
  }

  async function watsonModeSwitch(el) {
    const mode = el.dataset.mode;
    const caseId = currentCase();
    if (!caseId || !MODES.includes(mode) || mode === wMode) return;
    if (mode === "auto" && !confirm(AUTO_CONFIRM)) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/watson/mode`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode }),
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.error ? String(body.error) : "HTTP " + r.status);
      if (caseId === currentCase() && MODES.includes(body.mode)) wMode = body.mode;
    } catch (e) {
      alert("Could not switch Watson's mode: " + (e && e.message ? e.message : "network error"));
      if (typeof loadWatson === "function") loadWatson(caseId); // the GET re-syncs the mode shown (G15)
    }
    paint();
  }

  window.watsonModeSync = watsonModeSync;
  window.watsonModeSwitch = watsonModeSwitch;
})();
