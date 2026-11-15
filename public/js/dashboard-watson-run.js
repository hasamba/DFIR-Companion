// Watson's running state: the working line, the stop icon, the stop call and the per-send idempotency
// key. dashboard-watson.js calls them by name. No initializer.
//
// The server reports a round that runs on the case as chat.running ({ since, kind, actor?, queued },
// null when idle). Every viewer gets it through the watson_changed ping, so the line and the stop icon
// show for a round another tab or another analyst started. A message carries an Idempotency-Key so a
// resend after a lost answer is not run twice. The key is kept per case, and only until the next
// readable answer (any HTTP status): a new send then gets a new key.
(function () {
  const wPendingKey = new Map(); // case id -> { text, key }

  const newKey = () =>
    typeof crypto !== "undefined" && crypto && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : Date.now().toString(36) + Math.random().toString(36).slice(2, 12);

  function watsonWorkingHtml(chat, localBusy) {
    const run = chat && chat.running ? chat.running : null;
    if (!run && !localBusy) return "";
    let text = "Watson is working on an answer.";
    if (run && run.kind === "reaction") text = "Watson is working on the new case events.";
    else if (run && run.actor) text = `Watson is working on a message from ${esc(String(run.actor))}.`;
    const queued = run ? Number(run.queued) || 0 : 0;
    if (queued > 0) text += ` ${queued} more messages wait.`;
    return `<div class="watson-empty watson-working" role="status">${text}</div>`;
  }

  function watsonStopSync(chat, localBusy) {
    const show = !!(localBusy || (chat && chat.running));
    Array.from(document.querySelectorAll('[data-w="stop"]')).forEach((el) => { el.hidden = !show; });
  }

  // POST the stop. Returns null on success, else the text to show the analyst.
  async function watsonStop(caseId) {
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
  window.watsonStopSync = watsonStopSync;
  window.watsonStop = watsonStop;
  window.watsonSendKey = watsonSendKey;
  window.watsonSendSettled = watsonSendSettled;
})();
