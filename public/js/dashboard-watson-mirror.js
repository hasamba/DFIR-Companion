// #2647: the Watson panel's "Mirrored to Telegram" list, under the composer. It shows which Telegram
// chats receive this case's Watson chat, and each has an Off button. There is no On control on
// purpose: turning mirroring on must come from inside the chat (/dfir mirror on).
// dashboard-watson.js calls watsonMirrorRefresh() whenever it loads the chat, and routes the
// "mirrorOff" verb here. Every server string goes through esc()/escAttr(); the CSP bans inline handlers.
(function () {
  let wMirrors = [];
  let wMirrorSeq = 0;

  const currentCase = () => String((document.getElementById("caseId") || {}).value || "").trim();
  const api = (caseId, path) => `/cases/${encodeURIComponent(caseId)}/watson/mirrors${path}`;
  const OFF_TIP = "Stop sending this case's Watson chat to this Telegram chat. To turn it on again, send /dfir mirror on in the chat.";

  function label(m) {
    return `${m.chatType === "private" ? "Private chat" : "Group"} ${String(m.chatId)}`;
  }

  function watsonMirrorListHtml(list) {
    if (!Array.isArray(list) || list.length === 0) return "";
    const rows = list.map((m) =>
      `<li><span class="watson-mirror-chat">${esc(label(m))}</span>` +
      (m.held ? ` <span class="watson-mirror-held" title="Held: anonymization could not mask the next message. Review it in the Anonymization panel.">Held</span>` : "") +
      ` <button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="mirrorOff" data-chat="${escAttr(String(m.chatId))}" title="${escAttr(OFF_TIP)}">Off</button></li>`,
    );
    return `<div class="watson-lbl">Mirrored to Telegram</div><ul class="watson-mirror-list">${rows.join("")}</ul>`;
  }

  function paint() {
    const html = watsonMirrorListHtml(wMirrors);
    document.querySelectorAll('[data-w="mirrors"]').forEach((el) => {
      el.innerHTML = html;
      el.hidden = html === "";
    });
  }

  function watsonMirrorRefresh(caseId) {
    const id = caseId || currentCase();
    const s = ++wMirrorSeq;
    if (!id) {
      wMirrors = [];
      paint();
      return Promise.resolve();
    }
    return fetch(api(id, ""))
      .then((r) => (r.ok ? r.json() : null))
      .then((b) => {
        if (s !== wMirrorSeq || id !== currentCase()) return;
        wMirrors = b && Array.isArray(b.mirrors) ? b.mirrors : [];
        paint();
      })
      .catch(() => {});
  }

  async function watsonMirrorOff(el) {
    const caseId = currentCase();
    const chat = el && el.dataset ? String(el.dataset.chat || "") : "";
    if (!caseId || !chat) return;
    el.disabled = true;
    try {
      await fetch(api(caseId, `/${encodeURIComponent(chat)}/off`), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
    } catch {
      /* the reload below shows what the server kept */
    }
    await watsonMirrorRefresh(caseId);
  }

  window.watsonMirrorListHtml = watsonMirrorListHtml;
  window.watsonMirrorRefresh = watsonMirrorRefresh;
  window.watsonMirrorOff = watsonMirrorOff;
  // #2943: the owner changed (dashboard-watson.js): an older read paints nothing; the list waits for the new GET.
  window.watsonMirrorReset = () => {
    wMirrorSeq++;
    wMirrors = [];
    paint();
  };
})();
