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
  const wStopping = new Map(); // case id -> the token of its stop request in flight
  let wPoll = null; // { caseId, timer } while a run shows

  const selectedCase = () => String((document.getElementById("caseId") || {}).value || "").trim();

  // #2640: crypto.randomUUID exists only in secure contexts (https, localhost). Over plain http to a
  // private host the key comes from crypto.getRandomValues (16 bytes, base64url: 22 characters that
  // match the server's [A-Za-z0-9_-]{8,64}). With neither, there is no key and the send goes unkeyed
  // (no duplicate protection after a lost answer) rather than with a weak key.
  const KEY_BYTES = 16;
  function newKey() {
    const c = typeof crypto !== "undefined" ? crypto : null;
    if (c && typeof c.randomUUID === "function") return c.randomUUID();
    if (!c || typeof c.getRandomValues !== "function") return null;
    const bytes = c.getRandomValues(new Uint8Array(KEY_BYTES));
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

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
    pollSync(running || !!(chat && chat.reactionDue)); // a due reaction: re-read until its round shows
    if (typeof watsonStatusSync === "function") watsonStatusSync(chat, localBusy); // dashboard-watson-status.js
  }

  // POST the stop, then re-read the chat. Returns null on success, else the text to show the analyst.
  // A repeat click while the request is in flight is ignored. An answer that arrives after the analyst
  // selected another case neither re-reads nor reports: it belongs to a case the panel no longer shows.
  // #2943: `live` (dashboard-watson.js) also fails once the owner changed; watsonStopReset frees the lock.
  async function watsonStop(caseId, live = () => caseId === selectedCase()) {
    if (wStopping.has(caseId)) return null;
    const token = {};
    wStopping.set(caseId, token);
    try {
      const why = await stopRequest(caseId);
      if (caseId !== selectedCase() || !live()) return null;
      if (why === null && typeof loadWatson === "function") loadWatson(caseId);
      return why;
    } finally {
      if (wStopping.get(caseId) === token) wStopping.delete(caseId); // a newer visit's stop keeps its lock
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
    if (key) wPendingKey.set(caseId, { text, key });
    return key;
  }

  // The send's headers: the Idempotency-Key, or none at all when no key could be made (#2640). An
  // empty or "undefined" header would be one shared key for every send. Each send counts as one
  // attempt on its key until watsonSendSettled.
  function watsonSendHeaders(caseId, text) {
    const key = watsonSendKey(caseId, text);
    const held = wPendingKey.get(caseId);
    if (key && held && held.key === key) held.pending = (held.pending || 0) + 1;
    return key ? { "Idempotency-Key": key } : {};
  }

  // Keep the key after a lost answer: the resend must be the same request. #2943: sends with the same
  // text can overlap across case visits and share one key, so with `key` the key goes only when its
  // last attempt in flight settles and none of its attempts was lost; a send under another key
  // (different text) leaves it alone.
  function watsonSendSettled(caseId, networkFailed, key) {
    const held = wPendingKey.get(caseId);
    if (key === undefined) {
      if (!networkFailed) wPendingKey.delete(caseId);
      return;
    }
    if (!held || held.key !== key) return;
    held.pending = Math.max(0, (held.pending || 1) - 1);
    if (networkFailed) held.lost = true;
    if (held.pending > 0) return;
    if (held.lost) held.lost = false; // the resend reuses it
    else wPendingKey.delete(caseId);
  }

  window.watsonWorkingHtml = watsonWorkingHtml;
  window.watsonNoCaseHtml = watsonNoCaseHtml;
  window.watsonStopSync = watsonStopSync;
  window.watsonStop = watsonStop;
  window.watsonSendKey = watsonSendKey;
  window.watsonSendHeaders = watsonSendHeaders;
  window.watsonSendSettled = watsonSendSettled;
  window.watsonStopReset = () => wStopping.clear(); // the owner changed (dashboard-watson.js)
})();
