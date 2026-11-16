// Watson's run mode switch: Approve (Watson proposes, the analyst decides) or Auto (Watson acts within
// the limits the server enforces). The mode lives on the case; this file shows it in the panel header
// and on the rail, and asks before Auto. dashboard-watson.js calls watsonModeSync() on every render and
// routes the "setMode" verb here. Actions ride on data-act="watsonAct"; the CSP bans inline handlers.
(function () {
  const AUTO_CONFIRM =
    "Watson will run single-host collections and write to the case. It will not ask you first. A fleet-wide hunt still waits for your approval.";
  const MODES = ["approve", "auto"];
  const LABEL = { approve: "Approve", auto: "Auto" };
  const TIP = {
    approve: "Watson proposes each action. You approve it.",
    auto: "Watson runs single-host collections and writes to the case. It does not ask you first. A fleet-wide hunt still waits for your approval.",
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
    paintChain();
  }

  // The chat the server sent carries runMode on a GET; the replies to a POST do not, so they leave it be.
  function watsonModeSync(chat) {
    if (chat && MODES.includes(chat.runMode)) wMode = chat.runMode;
    if (chat) wChain = chainOf(chat);
    paint();
  }

  // ── The Auto chain (user decision of 2026-11-16) ─────────────────────────────────────────
  // In Auto mode a bar under the header sets the case's chain limit (how many collections Watson may
  // launch in a row from its own rounds; 0 = no limit) and always has Stop chain. Stop chain keeps
  // Auto on; the analyst's next message starts the chain again. The server enforces both.
  const CHAIN_DEFAULT = 3;
  const CHAIN_MAX = 50;
  let wChain = { max: CHAIN_DEFAULT, used: 0, stopped: false };
  const chainOf = (chat) => {
    const max = Number.isInteger(chat.autoChainMax) ? chat.autoChainMax : CHAIN_DEFAULT;
    const used = Number.isInteger(chat.autoChainLaunches) ? chat.autoChainLaunches : 0;
    return { max, used, stopped: chat.autoChainStopped === true };
  };

  function chainHtml(c) {
    const used = c.max === 0 ? `${c.used} launched (no limit)` : `${c.used} of ${c.max} launched`;
    const state = c.stopped
      ? `<span class="watson-chain-state">Stopped until your next message</span>`
      : `<span class="watson-chain-state">${esc(used)}</span>`;
    return (
      `<label class="watson-chain-label" title="How many collections Watson may launch in a row from its own rounds, before it waits for you. 0 = no limit.">` +
      `Auto chain <input type="number" class="watson-chain-max" min="0" max="${CHAIN_MAX}" step="1" value="${escAttr(String(c.max))}" ` +
      `data-act="watsonChainSet" data-act-on="change" aria-label="Auto chain limit (0 = no limit)"></label>` +
      state +
      `<button type="button" class="watson-mini watson-chain-stop" data-act="watsonChainStop"${c.stopped ? " disabled" : ""} ` +
      `title="Watson launches nothing more by itself until your next message. Auto stays on.">Stop chain</button>`
    );
  }

  function paintChain() {
    document.querySelectorAll('[data-w="chain"]').forEach((el) => {
      const on = wMode === "auto";
      el.hidden = !on;
      if (!on) return void (el.innerHTML = "");
      // Do not repaint while the analyst types in the number box (a focused button repaints).
      const box = el.querySelector(".watson-chain-max");
      if (!(box && document.activeElement === box)) el.innerHTML = chainHtml(wChain);
    });
  }

  async function chainPost(path, body, failText) {
    const caseId = currentCase();
    if (!caseId) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/watson/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const reply = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(reply.error ? String(reply.error) : "HTTP " + r.status);
    } catch (e) {
      alert(failText + (e && e.message ? e.message : "network error"));
    }
    // The GET carries the whole panel state (mode, Velociraptor, run); it shows the saved chain either way.
    if (typeof loadWatson === "function") loadWatson(caseId);
  }

  // data-act="watsonChainSet" (change on the number box) and "watsonChainStop" (dashboard-data-act.js).
  function watsonChainSet(el) {
    const n = Number(el.value);
    if (el.value.trim() === "" || !Number.isInteger(n) || n < 0 || n > CHAIN_MAX) {
      alert(`The chain limit must be a whole number from 0 to ${CHAIN_MAX} (0 = no limit).`);
      el.value = String(wChain.max);
      return;
    }
    if (n === wChain.max) return;
    if (el.blur) el.blur();
    return chainPost("auto-chain", { max: n }, "The companion could not change the Auto chain limit: ");
  }

  function watsonChainStop() {
    return chainPost("auto-chain/stop", {}, "The companion could not stop the Auto chain: ");
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
      alert("The companion could not change Watson's mode: " + (e && e.message ? e.message : "network error"));
      if (typeof loadWatson === "function") loadWatson(caseId); // the GET re-syncs the mode shown (G15)
    }
    paint();
  }

  window.watsonModeSync = watsonModeSync;
  window.watsonModeSwitch = watsonModeSwitch;
  window.watsonChainSet = watsonChainSet;
  window.watsonChainStop = watsonChainStop;
})();
