// Watson: the per-case investigation chat agent. One panel pinned to the right of every section and
// view, in three states: rail (a thin strip), open (360px) and full (the whole content area, with the
// Key Questions board beside the chat). It is not a dashboard section: no view profile hides it.
//
// This file owns the state and the server calls; the markup is built by dashboard-watson-view.js
// (watsonTurnHtml, watsonBoardHtml, watsonPanelHtml), which escapes every model, analyst and evidence string. Actions ride on
// data-act="watsonAct" + data-w-verb; the CSP bans inline handlers. dashboard.html carries one
// empty container. Every request is sent to the case it was started on, and its answer is dropped
// when the analyst has since opened another case.
(function () {
  const PANEL_KEY = "dfir.watson.panel";
  const STATES = ["rail", "open", "full"];
  const PASTE_LIMIT_BYTES = 50 * 1024 * 1024;
  const TEXT_EXTS = [".csv", ".log", ".txt", ".json", ".xml", ".tsv"];
  const TEXT_TYPES = ["application/json", "application/xml"];
  const STORED_HEADER = "x-watson-paste-stored";

  let wChat = null;
  let wQuestions = [];
  let wEarlier = []; // older turns paged back from the history file, oldest first, read-only
  let wMore = null; // true/false once a history page said whether older turns remain; null = not asked yet
  let wCase = null;
  let wSeq = 0;
  let wSeen = 0;
  let wNotice = null; // { text } — a warning shown under the log
  const wCardErr = new Map(); // proposal id -> the server's message when its action was refused (shown on the card)
  let wEmpty = false; // the case has no forensic events and no findings (#2468)
  let wNoAi = false; // the server has no Watson provider: the panel is hidden
  let wState = null; // "rail" | "open" | "full", seeded from storage on first use (a blocked store still switches)
  const wBusy = new Set(); // case ids with a request in flight
  const CHAT_CAP = 400; // the server keeps this many turns in the chat file (WATSON_MAX_TURNS)

  const currentCase = () => String((document.getElementById("caseId") || {}).value || "").trim();
  const all = (sel) => Array.from(document.querySelectorAll(sel));
  const api = (caseId, path) => `/cases/${encodeURIComponent(caseId)}/watson${path}`;
  // The answer to a request started on `caseId` may still be shown: that case is still the open one.
  const live = (caseId) => caseId === currentCase() && (!wCase || wCase === caseId);

  // ── Rendering ──────────────────────────────────────────────────────────────────────────
  function pendingCount() {
    return wChat ? wChat.proposals.filter((p) => p.status === "pending" && wChat.turns.some((t) => t.id === p.turnId)).length : 0;
  }

  function logHtml() {
    if (!wChat) return `<div class="watson-empty">Open a case to talk to Watson.</div>`;
    const older = wEarlier.map((t) => watsonTurnHtml(t, [], true)).join("");
    const more = wMore === true || (wMore === null && wChat.turns.length >= CHAT_CAP);
    const props = wCardErr.size ? wChat.proposals.map((p) => (wCardErr.has(p.id) ? { ...p, uiError: wCardErr.get(p.id) } : p)) : wChat.proposals;
    const turns = (more ? watsonEarlierButtonHtml() : "") + older + wChat.turns.map((t) => watsonTurnHtml(t, props)).join("");
    const hint = wChat.turns.length
      ? ""
      : wEmpty
        ? `<div class="watson-empty">No forensic-timeline events or findings yet — import evidence first; until then an answer has nothing to read.</div>`
        : `<div class="watson-empty">Ask Watson about this case, or paste evidence.</div>`;
    const warn = wNotice ? `<div class="watson-turn watson-warn"><div class="watson-text">${esc(wNotice.text)}</div></div>` : "";
    const thinking = wBusy.has(currentCase()) ? `<div class="watson-empty">Watson is thinking…</div>` : "";
    return hint + turns + watsonPausedHtml(wChat.reactionsPaused) + warn + thinking;
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
    watsonMarksSet(wChat ? wChat.proposals : []); // the sections' "Watson" badges follow the applied proposals
    const grew = wChat && wChat.turns.length > wSeen;
    setHtml('[data-w="log"]', logHtml());
    setHtml('[data-w="board"]', watsonBoardHtml(wQuestions));
    setHtml('[data-w="foot"]', footHtml());
    watsonVeloChipSync(wChat);
    watsonModeSync(wChat); // the Approve / Auto switch and the rail's "A" (dashboard-watson-mode.js)
    const n = pendingCount();
    setHtml('[data-w="count"]', n ? esc(String(n)) : "");
    const collapsed = panelState() === "rail";
    if (wChat && !collapsed) wSeen = wChat.turns.length;
    const unread = wChat && collapsed && wChat.turns.length > wSeen;
    all('[data-w="dot"]').forEach((el) => el.classList.toggle("watson-on", !!unread));
    if (grew) all('[data-w="log"]').forEach((el) => { el.scrollTop = el.scrollHeight; });
  }

  // ── Panel state ────────────────────────────────────────────────────────────────────────
  // Never chosen (or a blocked store): the rail. No provider: hidden, whatever the analyst chose.
  function panelState() {
    if (wState === null) {
      let v = null;
      try { v = localStorage.getItem(PANEL_KEY); } catch { /* blocked store: the default */ }
      wState = STATES.includes(v) ? v : "rail";
    }
    return wState;
  }
  // The full panel covers the content below the top toolbar. The header wraps and collapses, so its
  // bottom edge is written to --watson-top whenever it changes (a ResizeObserver, or resize as the fallback).
  function syncTop() {
    const h = typeof document.querySelector === "function" ? document.querySelector("header") : null;
    const root = document.documentElement;
    if (!h || !h.getBoundingClientRect || !root || !root.style || !root.style.setProperty) return;
    root.style.setProperty("--watson-top", Math.max(0, Math.round(h.getBoundingClientRect().bottom)) + "px");
  }
  function watchHeader() {
    const h = typeof document.querySelector === "function" ? document.querySelector("header") : null;
    if (!h) return;
    if (typeof ResizeObserver === "function") new ResizeObserver(syncTop).observe(h);
    else window.addEventListener("resize", syncTop);
    syncTop();
  }
  function applyPanel() {
    const panel = document.getElementById("watsonPanel");
    if (!panel) return;
    const s = panelState();
    panel.classList.toggle("watson-collapsed", s === "rail");
    panel.classList.toggle("watson-fullscreen", s === "full");
    panel.classList.toggle("watson-hidden", wNoAi);
    if (s === "full") syncTop();
    const b = document.body.classList;
    b.toggle("watson-rail-open", !wNoAi && s === "rail");
    b.toggle("watson-panel-open", !wNoAi && s === "open");
    b.toggle("watson-full-open", !wNoAi && s === "full");
  }
  function setWatsonPanelState(next) {
    if (!STATES.includes(next)) return;
    wState = next;
    try { localStorage.setItem(PANEL_KEY, next); } catch { /* a blocked store must not break the switch */ }
    applyPanel();
    renderWatson();
    const panel = document.getElementById("watsonPanel");
    const to = panel && panel.querySelector ? panel.querySelector(next === "rail" ? ".watson-rail" : ".watson-input") : null;
    if (to && to.focus) to.focus();
  }
  const toggleWatsonPanel = () => setWatsonPanelState(panelState() === "rail" ? "open" : "rail");
  function setNoAi(on) {
    if (wNoAi === on) return;
    wNoAi = on;
    applyPanel();
  }

  // ── Server calls ───────────────────────────────────────────────────────────────────────
  function loadWatson(caseId, onlyIfNew) {
    const id = caseId || currentCase();
    if (!id) return Promise.resolve();
    if (onlyIfNew && wCase === id) return Promise.resolve();
    if (wCase !== id) {
      wCase = id;
      wChat = null;
      wEarlier = [];
      wMore = null;
      wSeen = 0;
      wNotice = null;
      wCardErr.clear();
    }
    const seq = ++wSeq;
    return fetch(api(id, ""))
      .then((r) => {
        if (r.status === 501) setNoAi(true);
        return r.ok ? r.json() : null;
      })
      .then((c) => {
        if (seq !== wSeq || !c) return;
        setNoAi(c.providerConfigured === false);
        renderWatson(c);
      })
      .catch(() => {});
  }

  async function failure(r, action, stored) {
    const body = await r.json().catch(() => ({}));
    const why = body.error ? String(body.error) : "Watson request failed (HTTP " + r.status + ")";
    if (r.status === 409 && body.error === "presidio_approval_required") {
      if (typeof setPresidioPending === "function") setPresidioPending(body.findings);
      return stored
        ? "The paste was stored as evidence. Presidio found new value(s) awaiting approval; resolve them in Anonymization, then send a message and Watson will read the paste."
        : "Presidio found new value(s) awaiting approval. Resolve them in Anonymization, then send again.";
    }
    if (action !== "paste") return why;
    return stored
      ? "The paste was stored as evidence, but Watson could not read it yet: " + why + " Watson will read it on your next message."
      : "The paste was not stored: " + why;
  }

  // POST to the case the action started on. { ok, stored }: stored is true once the server kept a paste.
  async function post(caseId, path, payload, action) {
    const out = { ok: false, stored: false };
    if (!caseId || wBusy.has(caseId)) return out;
    wBusy.add(caseId);
    if (live(caseId)) {
      wNotice = null;
      renderWatson();
    }
    try {
      const r = await fetch(api(caseId, path), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      out.stored = action === "paste" && !!r.headers && r.headers.get(STORED_HEADER) === "1";
      if (r.ok) {
        out.ok = true;
        const chat = await r.json();
        if (live(caseId)) {
          wNotice = null;
          renderWatson(chat);
        }
      } else {
        const text = await failure(r, action, out.stored);
        if (live(caseId)) wNotice = { text };
      }
    } catch (e) {
      if (live(caseId)) wNotice = { text: "Watson request failed: " + (e && e.message ? e.message : "network error") };
    } finally {
      wBusy.delete(caseId);
      if (live(caseId)) renderWatson();
    }
    // a stored paste or a held round still changed the chat
    if (!out.ok && action && live(caseId)) loadWatson(caseId);
    return out;
  }

  const composerText = (el) => (el.closest(".watson-root") || document).querySelector(".watson-input");
  function send(el) {
    const input = composerText(el);
    const text = input ? input.value.trim() : "";
    const caseId = currentCase();
    if (!text || wBusy.has(caseId)) return;
    input.value = "";
    return post(caseId, "/message", { text }, "message").then((r) => {
      // a failed send keeps what the analyst typed, in the case they typed it for
      if (!r.ok && !input.value && live(caseId)) input.value = text;
    });
  }
  function sendPaste(el) {
    const area = el.closest(".watson-root").querySelector(".watson-paste-text");
    const text = area ? area.value : "";
    const caseId = currentCase();
    if (!text.trim() || wBusy.has(caseId)) return;
    const box = el.closest(".watson-root").querySelector(".watson-paste-box");
    const bytes = typeof TextEncoder === "function" ? new TextEncoder().encode(text).length : text.length;
    if (bytes > PASTE_LIMIT_BYTES) {
      wNotice = { text: "That text is larger than 50 MB. Watson takes smaller pastes." };
      return renderWatson();
    }
    area.value = "";
    box.classList.remove("watson-on");
    return post(caseId, "/paste", { text }, "paste").then((r) => {
      // A stored paste is evidence already: putting it back would invite a duplicate.
      if (!r.ok && !r.stored && !area.value && live(caseId)) area.value = text;
    });
  }

  function isTextFile(f) {
    const name = String(f.name || "").toLowerCase(), type = String(f.type || "");
    return type.startsWith("text/") || TEXT_TYPES.includes(type) || TEXT_EXTS.some((x) => name.endsWith(x));
  }
  async function attach(el) {
    const f = el.files && el.files[0];
    el.value = "";
    if (!f) return;
    const caseId = currentCase(); // before the file is read: the paste belongs to this case
    const refuse = !isTextFile(f)
      ? "Watson reads text files only (text, JSON, XML, CSV, TSV or log). Choose another file."
      : f.size > PASTE_LIMIT_BYTES ? "That file is larger than 50 MB. Watson takes smaller files." : "";
    if (refuse) {
      wNotice = { text: refuse };
      return renderWatson();
    }
    const text = await f.text();
    return post(caseId, "/paste", { text, filename: f.name }, "paste");
  }

  // A write that answers { chat, state?: { keyQuestions } } (a proposal decision, an added answer).
  async function decide(path, pid, el) {
    const caseId = currentCase();
    wNotice = null;
    try {
      const r = await fetch(api(caseId, path), { method: "POST" });
      if (!live(caseId)) return;
      if (!r.ok) {
        const text = await failure(r, "proposal", false);
        if (!live(caseId)) return;
        if (pid) wCardErr.set(pid, text);
        if (!pid || watsonSectionRefused(el, text)) wNotice = { text }; // a section's Undo: shown where the analyst is
        return renderWatson();
      }
      if (pid) wCardErr.delete(pid);
      const body = await r.json();
      if (!live(caseId)) return;
      if (body.state && Array.isArray(body.state.keyQuestions)) wQuestions = body.state.keyQuestions;
      renderWatson(body.chat);
    } catch (e) {
      if (!live(caseId)) return;
      wNotice = { text: "Watson request failed: " + (e && e.message ? e.message : "network error") };
      renderWatson();
    }
  }

  const proposal = (el, verb) => decide(`/proposals/${encodeURIComponent(el.dataset.pid)}/${verb}`, el.dataset.pid, el);
  const addQuestion = (el) => decide(`/turns/${encodeURIComponent(el.dataset.tid)}/add-question`);
  // Older turns from the full history file, above the oldest one shown. Read-only.
  async function loadEarlier() {
    const caseId = currentCase();
    const oldest = wEarlier[0] || (wChat && wChat.turns[0]);
    if (!caseId || !oldest || wBusy.has(caseId)) return;
    wBusy.add(caseId);
    try {
      const r = await fetch(api(caseId, `/history?before=${encodeURIComponent(oldest.id)}&limit=100`));
      if (!r.ok) throw new Error("HTTP " + r.status);
      const page = await r.json();
      if (!live(caseId)) return;
      wEarlier = [...(Array.isArray(page.turns) ? page.turns : []), ...wEarlier];
      wMore = page.more === true;
    } catch (e) {
      if (live(caseId)) wNotice = { text: "Could not load earlier messages: " + (e && e.message ? e.message : "network error") };
    } finally {
      wBusy.delete(caseId);
      if (live(caseId)) renderWatson();
    }
  }
  const newThread = () => post(currentCase(), "/new-thread", {}, "thread");

  function copyQuery(el) {
    const pre = el.parentElement && el.parentElement.querySelector("pre");
    if (pre && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(pre.textContent).catch(() => {});
  }

  const VERBS = {
    send,
    copy: copyQuery,
    collapse: () => setWatsonPanelState("rail"),
    open: () => setWatsonPanelState("open"),
    fullScreen: () => setWatsonPanelState("full"),
    exitFullScreen: () => setWatsonPanelState("open"),
    pasteToggle: (el) => el.closest(".watson-root").querySelector(".watson-paste-box").classList.toggle("watson-on"),
    pasteSend: sendPaste,
    attachPick: (el) => el.closest(".watson-root").querySelector(".watson-file").click(),
    file: attach,
    apply: (el) => proposal(el, "apply"),
    reject: (el) => proposal(el, "reject"),
    undo: (el) => proposal(el, "undo"),
    // A "Wrote:" link: leave the full view first (it covers the sections), then scroll and flash.
    jump: (el) => {
      if (panelState() === "full") setWatsonPanelState("open");
      watsonJump(el);
    },
    addQuestion,
    loadEarlier,
    newThread,
    setMode: (el) => watsonModeSwitch(el),
    resolveLaunch: (el) => watsonVeloResolve(el),
  };
  // data-act="watsonAct": a fixed table, never a lookup of a DOM-supplied name on window.
  function watsonAct(el) {
    const fn = Object.prototype.hasOwnProperty.call(VERBS, el.dataset.wVerb) ? VERBS[el.dataset.wVerb] : null;
    if (fn) return fn(el);
  }

  // ── Shell ──────────────────────────────────────────────────────────────────────────────
  function initWatson() {
    const panel = document.getElementById("watsonPanel");
    if (panel) panel.innerHTML = watsonPanelHtml();
    applyPanel();
    watchHeader();
    if (typeof DfirState !== "undefined" && DfirState.onLastStateChange) {
      DfirState.onLastStateChange((st) => {
        wQuestions = st && Array.isArray(st.keyQuestions) ? st.keyQuestions : [];
        wEmpty = watsonCaseIsEmpty(st);
        renderWatson();
      });
    }
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !e.defaultPrevented && !wNoAi && wState === "full") setWatsonPanelState("open");
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
  window.setWatsonPanelState = setWatsonPanelState;
  window.loadWatson = loadWatson;
  window.watsonAct = watsonAct;
})();
