// Watson: the per-case investigation chat agent. A side panel on every section (360px, collapsible
// to a thin rail) plus a full section (sec-watson) with the Key Questions board beside the chat.
//
// Every model, analyst and evidence string goes through esc()/escAttr() (dashboard-escape.js).
// Actions ride on data-act="watsonAct" + data-w-verb; the CSP bans inline handlers. The markup is
// built here, once per surface, so dashboard.html carries only two empty containers.
(function () {
  const COLLAPSE_KEY = "dfir.watsonCollapsed";
  const HIDDEN_KEY = "dfir.watsonHidden";
  const PASTE_LIMIT_BYTES = 50 * 1024 * 1024;
  const TEXT_EXTS = [".csv", ".log", ".txt", ".json", ".xml", ".tsv"];
  const TEXT_TYPES = ["application/json", "application/xml"];
  const QSTATUS = { answered: "Answered", partial: "Partial", unknown: "Unknown", unanswerable: "Not answerable" };

  let wChat = null;
  let wQuestions = [];
  let wCase = null;
  let wSeq = 0;
  let wSeen = 0;
  let wNotice = null; // { text } — a warning shown under the log
  let wBusy = false;

  function readFlag(key) {
    try { return localStorage.getItem(key) === "1"; } catch { return false; }
  }
  function writeFlag(key, on) {
    try { localStorage.setItem(key, on ? "1" : "0"); } catch { /* a blocked store must not break the toggle */ }
  }

  function currentCase() {
    const el = document.getElementById("caseId");
    return el && el.value ? String(el.value).trim() : "";
  }
  const all = (sel) => Array.from(document.querySelectorAll(sel));
  const api = (path) => `/cases/${encodeURIComponent(currentCase())}/watson${path}`;

  // ── Rendering ──────────────────────────────────────────────────────────────────────────
  function pendingCount() {
    return wChat ? wChat.proposals.filter((p) => p.status === "pending").length : 0;
  }

  function requestHtml(r) {
    if (!r) return "";
    if (r.kind === "query") {
      return (
        `<div class="watson-req"><div class="watson-lbl">Run this ${esc(r.language)} query</div>` +
        `<pre class="watson-pre">${esc(r.query)}</pre>` +
        `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="copy">Copy</button>` +
        `<div class="watson-why">${esc(r.why)}</div></div>`
      );
    }
    return (
      `<div class="watson-req"><div class="watson-lbl">Import ${esc(r.what)}</div>` +
      `<div class="watson-why">${esc(r.why)}</div></div>`
    );
  }

  function proposalHtml(p) {
    const a = p.after || {};
    const verbs =
      p.status === "pending"
        ? btn(p.id, "apply", "Apply") + btn(p.id, "reject", "Reject")
        : p.status === "applied"
          ? btn(p.id, "undo", "Undo")
          : "";
    const title = p.kind === "question_new" ? "New question" : "Question update";
    return (
      `<div class="watson-prop" data-pid="${escAttr(p.id)}">` +
      `<div class="watson-lbl">${esc(title)} · ${esc(p.status)}</div>` +
      `<div><strong>${esc(a.question)}</strong></div>` +
      `<div>${statusBadge(a.status)} ${esc(a.answer || "")}</div>` +
      (a.pointer ? `<div class="watson-why">→ ${esc(a.pointer)}</div>` : "") +
      `<div>${verbs}</div></div>`
    );
  }
  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;
  function statusBadge(status) {
    const st = QSTATUS[status] ? status : "unknown";
    return `<span class="q-status q-status-${st}">${esc(QSTATUS[st])}</span>`;
  }

  function turnHtml(t, proposals) {
    const cls = "watson-turn watson-" + (t.error ? "warn" : t.role);
    const who = t.role === "analyst" ? esc(t.actor || "You") : t.role === "system" ? "System" : "Watson";
    const props = (t.proposalIds || [])
      .map((id) => proposals.find((p) => p.id === id))
      .filter(Boolean)
      .map(proposalHtml)
      .join("");
    return (
      `<div class="${cls}"><div class="watson-who">${who}</div>` +
      (t.workingOn ? `<div class="watson-meta"><b>Working on:</b> ${esc(t.workingOn)}</div>` : "") +
      `<div class="watson-text">${esc(t.text)}</div>` +
      (t.learned ? `<div class="watson-meta"><b>Learned:</b> ${esc(t.learned)}</div>` : "") +
      requestHtml(t.request) +
      props +
      `</div>`
    );
  }

  function logHtml() {
    if (!wChat) return `<div class="watson-empty">Open a case to talk to Watson.</div>`;
    const turns = wChat.turns.map((t) => turnHtml(t, wChat.proposals)).join("");
    const hint = wChat.turns.length ? "" : `<div class="watson-empty">Ask Watson about this case, or paste evidence.</div>`;
    const warn = wNotice ? `<div class="watson-turn watson-warn"><div class="watson-text">${esc(wNotice.text)}</div></div>` : "";
    return hint + turns + warn + (wBusy ? `<div class="watson-empty">Watson is thinking…</div>` : "");
  }

  function boardHtml() {
    if (!wQuestions.length) return `<div class="watson-empty">No key questions yet.</div>`;
    return wQuestions
      .map((q) => {
        const dis = q.synthesisDisagrees
          ? `<div class="q-contradicted">Synthesis disagrees: ${esc(q.synthesisDisagrees.status)}` +
            (q.synthesisDisagrees.answer ? ` — ${esc(q.synthesisDisagrees.answer)}` : "") +
            `</div>`
          : "";
        return (
          `<div class="watson-q">${statusBadge(q.status)} <strong>${esc(q.question)}</strong>` +
          `<div>${esc(q.answer || "unknown")}</div>` +
          (q.pointer ? `<div class="watson-why">→ ${esc(q.pointer)}</div>` : "") +
          dis +
          `</div>`
        );
      })
      .join("");
  }

  function footHtml() {
    if (!wChat) return "";
    const calls = Number(wChat.calls) || 0;
    const usd = Number(wChat.costUSD) || 0;
    const tail = usd === 0 && calls > 0 ? `${Number(wChat.tokens) || 0} tokens` : `$${usd.toFixed(2)}`;
    return `This case: ${calls} calls · ${tail}`;
  }

  function setHtml(sel, html) {
    all(sel).forEach((el) => { el.innerHTML = html; });
  }

  function renderWatson(next) {
    if (next) wChat = next;
    const grew = wChat && wChat.turns.length > wSeen;
    setHtml('[data-w="log"]', logHtml());
    setHtml('[data-w="board"]', boardHtml());
    setHtml('[data-w="foot"]', footHtml());
    const n = pendingCount();
    setHtml('[data-w="count"]', n ? esc(String(n)) : "");
    const collapsed = isCollapsed();
    if (wChat && !collapsed) wSeen = wChat.turns.length;
    const unread = wChat && collapsed && wChat.turns.length > wSeen;
    all('[data-w="dot"]').forEach((el) => el.classList.toggle("watson-on", !!unread));
    if (grew) all('[data-w="log"]').forEach((el) => { el.scrollTop = el.scrollHeight; });
  }

  // ── Panel state ────────────────────────────────────────────────────────────────────────
  function isCollapsed() {
    const p = document.getElementById("watsonPanel");
    return !!p && p.classList.contains("watson-collapsed");
  }
  function applyPanel(hidden, collapsed) {
    const panel = document.getElementById("watsonPanel");
    if (!panel) return;
    panel.classList.toggle("watson-collapsed", collapsed);
    panel.classList.toggle("watson-hidden", hidden);
    const b = document.body.classList;
    b.toggle("watson-rail-open", !hidden && collapsed);
    b.toggle("watson-panel-open", !hidden && !collapsed);
    panel.setAttribute("aria-expanded", String(!collapsed));
  }
  function toggleWatsonCollapse() {
    const collapsed = !isCollapsed();
    const hidden = readFlag(HIDDEN_KEY);
    writeFlag(COLLAPSE_KEY, collapsed);
    applyPanel(hidden, collapsed);
    renderWatson();
  }
  function toggleWatsonPanel() {
    const panel = document.getElementById("watsonPanel");
    const hidden = !(panel && panel.classList.contains("watson-hidden"));
    writeFlag(HIDDEN_KEY, hidden);
    applyPanel(hidden, isCollapsed());
  }
  function expandWatson() {
    const sec = document.getElementById("sec-watson");
    if (typeof revealSection === "function") revealSection("sec-watson");
    if (sec && typeof sec.scrollIntoView === "function") sec.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ── Server calls ───────────────────────────────────────────────────────────────────────
  function loadWatson(caseId, onlyIfNew) {
    const id = caseId || currentCase();
    if (!id) return Promise.resolve();
    if (onlyIfNew && wCase === id) return Promise.resolve();
    if (wCase !== id) {
      wCase = id;
      wChat = null;
      wSeen = 0;
      wNotice = null;
    }
    const seq = ++wSeq;
    return fetch(api(""))
      .then((r) => (r.ok ? r.json() : null))
      .then((c) => {
        if (seq !== wSeq || !c) return;
        renderWatson(c);
      })
      .catch(() => {});
  }

  async function failure(r, action) {
    const body = await r.json().catch(() => ({}));
    if (r.status === 409 && body.error === "presidio_approval_required") {
      if (typeof setPresidioPending === "function") setPresidioPending(body.findings);
      return action === "paste"
        ? "The paste was stored as evidence. Presidio found new value(s) awaiting approval; resolve them in Anonymization, and Watson will read it on the next message."
        : "Presidio found new value(s) awaiting approval. Resolve them in Anonymization, then send again.";
    }
    if (r.status === 409 && action === "paste")
      return "The paste was stored as evidence. Watson will read it on the next message.";
    return body.error ? String(body.error) : "Watson request failed (HTTP " + r.status + ")";
  }

  async function post(path, payload, action) {
    if (wBusy) return;
    wBusy = true;
    wNotice = null;
    renderWatson();
    try {
      const r = await fetch(api(path), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (r.ok) {
        wNotice = null;
        return renderWatson(await r.json());
      }
      wNotice = { text: await failure(r, action) };
    } catch (e) {
      wNotice = { text: "Watson request failed: " + (e && e.message ? e.message : "network error") };
    } finally {
      wBusy = false;
      renderWatson();
    }
    // a stored paste or a held round still changed the chat
    if (action) loadWatson(currentCase());
  }

  function composerText(el) {
    const root = el.closest(".watson-root");
    return root ? root.querySelector(".watson-input") : null;
  }
  function send(el) {
    const input = composerText(el);
    const text = input ? input.value.trim() : "";
    if (!text || wBusy) return;
    input.value = "";
    return post("/message", { text }, "message");
  }
  function sendPaste(el) {
    const area = el.closest(".watson-root").querySelector(".watson-paste-text");
    const text = area ? area.value : "";
    if (!text.trim() || wBusy) return;
    area.value = "";
    el.closest(".watson-root").querySelector(".watson-paste-box").classList.remove("watson-on");
    return post("/paste", { text }, "paste");
  }

  function isTextFile(f) {
    const name = String(f.name || "").toLowerCase();
    const type = String(f.type || "");
    return type.startsWith("text/") || TEXT_TYPES.includes(type) || TEXT_EXTS.some((x) => name.endsWith(x));
  }
  async function attach(el) {
    const f = el.files && el.files[0];
    el.value = "";
    if (!f) return;
    if (!isTextFile(f)) {
      wNotice = { text: "Watson reads text files only (text, JSON, XML, CSV, TSV or log). Choose another file." };
      return renderWatson();
    }
    if (f.size > PASTE_LIMIT_BYTES) {
      wNotice = { text: "That file is larger than 50 MB. Watson takes smaller files." };
      return renderWatson();
    }
    const text = await f.text();
    return post("/paste", { text, filename: f.name }, "paste");
  }

  async function proposal(el, verb) {
    const pid = el.dataset.pid;
    wNotice = null;
    try {
      const r = await fetch(api(`/proposals/${encodeURIComponent(pid)}/${verb}`), { method: "POST" });
      if (!r.ok) {
        wNotice = { text: await failure(r, "proposal") };
        return renderWatson();
      }
      const body = await r.json();
      if (body.state && Array.isArray(body.state.keyQuestions)) wQuestions = body.state.keyQuestions;
      renderWatson(body.chat);
    } catch (e) {
      wNotice = { text: "Watson request failed: " + (e && e.message ? e.message : "network error") };
      renderWatson();
    }
  }

  function copyQuery(el) {
    const pre = el.parentElement && el.parentElement.querySelector("pre");
    const text = pre ? pre.textContent : "";
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).catch(() => {});
  }

  const VERBS = {
    send,
    copy: copyQuery,
    collapse: toggleWatsonCollapse,
    expand: expandWatson,
    pasteToggle: (el) => el.closest(".watson-root").querySelector(".watson-paste-box").classList.toggle("watson-on"),
    pasteSend: sendPaste,
    attachPick: (el) => el.closest(".watson-root").querySelector(".watson-file").click(),
    file: attach,
    apply: (el) => proposal(el, "apply"),
    reject: (el) => proposal(el, "reject"),
    undo: (el) => proposal(el, "undo"),
  };
  // data-act="watsonAct": a fixed table, never a lookup of a DOM-supplied name on window.
  function watsonAct(el) {
    const fn = Object.prototype.hasOwnProperty.call(VERBS, el.dataset.wVerb) ? VERBS[el.dataset.wVerb] : null;
    if (fn) return fn(el);
  }

  // ── Shell ──────────────────────────────────────────────────────────────────────────────
  function composerHtml() {
    return (
      `<div class="watson-composer">` +
      `<textarea class="watson-input" rows="2" placeholder="Ask Watson… (Ctrl+Enter to send)" aria-label="Message Watson"></textarea>` +
      `<div class="watson-paste-box"><textarea class="watson-paste-text" rows="5" placeholder="Paste evidence text here" aria-label="Paste evidence"></textarea>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="pasteSend">Send paste</button></div>` +
      `<div class="watson-actions">` +
      `<button type="button" data-act="watsonAct" data-w-verb="send">Send</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="pasteToggle">Paste evidence</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="attachPick">Attach file</button>` +
      `<input type="file" class="watson-file" data-act="watsonAct" data-act-on="change" data-w-verb="file" accept=".txt,.log,.csv,.tsv,.json,.xml,text/*,application/json,application/xml" />` +
      `</div></div>`
    );
  }
  function panelHtml() {
    return (
      `<div class="watson-rail" data-act="watsonAct" data-w-verb="collapse" role="button" tabindex="0" aria-label="Open Watson">` +
      `<span class="watson-rail-icon">W</span><span class="watson-dot" data-w="dot"></span><span class="watson-count" data-w="count"></span></div>` +
      `<div class="watson-root watson-full"><div class="watson-head"><strong>Watson</strong>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="expand">Expand</button>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="collapse" aria-label="Collapse Watson">Collapse</button></div>` +
      `<div class="watson-log" data-w="log"></div>` +
      composerHtml() +
      `<div class="watson-foot" data-w="foot"></div></div>`
    );
  }
  function sectionHtml() {
    return (
      `<div class="watson-root watson-wide"><div class="watson-board" data-w="board"></div>` +
      `<div class="watson-chat"><div class="watson-log" data-w="log"></div>` +
      composerHtml() +
      `<div class="watson-foot" data-w="foot"></div></div></div>`
    );
  }

  function initWatson() {
    const panel = document.getElementById("watsonPanel");
    if (panel) panel.innerHTML = panelHtml();
    const sec = document.getElementById("watsonSection");
    if (sec) sec.innerHTML = sectionHtml();
    applyPanel(readFlag(HIDDEN_KEY), readFlag(COLLAPSE_KEY));
    if (typeof DfirState !== "undefined" && DfirState.onLastStateChange) {
      DfirState.onLastStateChange((st) => {
        wQuestions = st && Array.isArray(st.keyQuestions) ? st.keyQuestions : [];
        renderWatson();
      });
    }
    document.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && e.target.classList && e.target.classList.contains("watson-input")) {
        e.preventDefault();
        send(e.target);
      }
    });
    renderWatson();
  }

  window.initWatson = initWatson;
  window.renderWatson = renderWatson;
  window.toggleWatsonPanel = toggleWatsonPanel;
  window.toggleWatsonCollapse = toggleWatsonCollapse;
  window.expandWatson = expandWatson;
  window.loadWatson = loadWatson;
  window.watsonAct = watsonAct;
})();
