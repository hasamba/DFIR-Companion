// Watson's running state: the working line, the stop icon, the stop call and the per-send idempotency
// key. dashboard-watson.js calls them by name. No initializer.
//
// The server reports a round that runs on the case as chat.running ({ since, kind, actor?, queued },
// null when idle). Every viewer gets it through the watson_changed ping, so the line and the stop icon
// show for a round another tab or another analyst started. A message carries an Idempotency-Key so a
// resend after a lost answer is not run twice. The key is kept per case, and only until the next
// readable answer (any HTTP status): a new send then gets a new key.
(function () {
  const REFETCH_MS = 15000; // while a run shows, re-read the chat: a watson_changed ping may be missed
  const wPendingKey = new Map(); // case id -> { text, key }
  const wStopping = new Set(); // case ids with a stop request in flight
  let wPoll = null; // { caseId, timer } while a run shows

  const selectedCase = () => String((document.getElementById("caseId") || {}).value || "").trim();

  const newKey = () =>
    typeof crypto !== "undefined" && crypto && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : Date.now().toString(36) + Math.random().toString(36).slice(2, 12);

  // With no case open there is no chat: the log shows the hint and, after a send, why nothing went out.
  function watsonNoCaseHtml(notice) {
    const warn = notice ? `<div class="watson-turn watson-warn"><div class="watson-text">${esc(String(notice.text))}</div></div>` : "";
    return `<div class="watson-empty">Open a case to talk to Watson.</div>` + warn;
  }

  function watsonWorkingHtml(chat, localBusy) {
    const run = chat && chat.running ? chat.running : null;
    if (!run && !localBusy) return "";
    let text = "Watson is working on an answer.";
    if (run && run.kind === "reaction") text = "Watson is working on the new case events.";
    else if (run && run.actor) text = `Watson is working on a message from ${esc(String(run.actor))}.`;
    const queued = run ? Number(run.queued) || 0 : 0;
    if (queued > 0) text += queued === 1 ? " 1 more message waits." : ` ${queued} more messages wait.`;
    return `<div class="watson-empty watson-working" role="status">${text}</div>`;
  }

  // The stop icon follows the run. While the server reports a run, the chat is re-read on a timer, so a
  // missed ping cannot leave the icon and the line stuck. The timer ends when the run ends or the case changes.
  const pollSync = (running) => {
    const caseId = selectedCase();
    if (wPoll && (!running || wPoll.caseId !== caseId)) {
      clearInterval(wPoll.timer);
      wPoll = null;
    }
    if (!running || wPoll || !caseId || typeof setInterval !== "function") return;
    const timer = setInterval(() => {
      if (caseId === selectedCase() && typeof loadWatson === "function") loadWatson(caseId);
    }, REFETCH_MS);
    wPoll = { caseId, timer };
  };

  function watsonStopSync(chat, localBusy) {
    const running = !!(chat && chat.running);
    Array.from(document.querySelectorAll('[data-w="stop"]')).forEach((el) => { el.hidden = !(localBusy || running); });
    pollSync(running);
  }

  // POST the stop, then re-read the chat. Returns null on success, else the text to show the analyst.
  // A repeat click while the request is in flight is ignored. An answer that arrives after the analyst
  // selected another case neither re-reads nor reports: it belongs to a case the panel no longer shows.
  async function watsonStop(caseId) {
    if (wStopping.has(caseId)) return null;
    wStopping.add(caseId);
    try {
      const why = await stopRequest(caseId);
      if (caseId !== selectedCase()) return null;
      if (why === null && typeof loadWatson === "function") loadWatson(caseId);
      return why;
    } finally {
      wStopping.delete(caseId);
    }
  }

  async function stopRequest(caseId) {
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/watson/cancel`, { method: "POST" });
      if (r.ok) return null;
      const body = await r.json().catch(() => ({}));
      return body && body.error ? String(body.error) : `Watson could not stop (HTTP ${r.status}).`;
    } catch {
      return "Watson could not stop: network error.";
    }
  }

  function watsonSendKey(caseId, text) {
    const held = wPendingKey.get(caseId);
    if (held && held.text === text) return held.key;
    const key = newKey();
    wPendingKey.set(caseId, { text, key });
    return key;
  }

  // Keep the key only after a lost answer: the resend must be the same request.
  function watsonSendSettled(caseId, networkFailed) {
    if (!networkFailed) wPendingKey.delete(caseId);
  }

  window.watsonWorkingHtml = watsonWorkingHtml;
  window.watsonNoCaseHtml = watsonNoCaseHtml;
  window.watsonStopSync = watsonStopSync;
  window.watsonStop = watsonStop;
  window.watsonSendKey = watsonSendKey;
  window.watsonSendSettled = watsonSendSettled;
})();
