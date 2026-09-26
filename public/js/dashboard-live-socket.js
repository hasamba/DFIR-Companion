// The case's live-update WebSocket: open, reconnect, and catch up (#1675).
//
// It used to be opened inline in proceedConnect, and its onclose only wrote "disconnected". After a
// sleep or a network drop the page received no pushes at all until a reload — the AI pill, the jobs
// chip and every push-driven panel froze on whatever they last showed. The analyst in #1675 pressed
// Re-synthesize, the server ran it, and the pill kept reading "conclusions out of date".
//
// What this module guarantees:
//  - A socket that closes is reopened with capped backoff (1 s doubling to 30 s), but ONLY while the
//    same case is still connected and only if the socket that closed is still the current `ws`.
//    proceedConnect (a case switch) and dismissCaseLoading (a cancel) retire the old socket through
//    closeCaseSocket(), which detaches it first, so neither can ever reconnect.
//  - A REconnect catches up on what the gap missed: the pill, the jobs chip, the case state (handed
//    to the same message handler a `state` push uses, so the same panels refresh), the scope, and
//    one bare message per other push-driven panel (CATCH_UP_TYPES, #1681).
//  - A tab that becomes visible re-derives the pill. A closed socket is reopened at once. After a
//    long hide (a sleep) even an OPEN socket is replaced, because a half-open socket reads OPEN and
//    never fires onclose; the server's 30 s ping reaper cleans up its end.
//
// `ws` and `activeCaseId` are page vocabulary (dashboard.html's inline script and
// js/dashboard-case-connect.js), read and written here by bare name like every other module does.
(function () {
  "use strict";

  const RECONNECT_BASE_MS = 1000;
  const RECONNECT_MAX_MS = 30000;
  // A socket must stay up this long before the backoff resets. Resetting on open let a server that
  // accepts and then drops at once be retried every second forever.
  const STABLE_OPEN_MS = 30000;
  // A handshake that has not finished by now is given up on. Across a sleep or a network change a
  // connection attempt can sit in CONNECTING indefinitely, and only onclose schedules a retry.
  const CONNECT_TIMEOUT_MS = 10000;
  // Hidden this long, the tab probably slept: replace the socket even if it still reads OPEN.
  const LONG_HIDE_MS = 60000;

  let liveCaseId = null; // the case the live socket serves; null when none is wanted
  let liveOnMessage = null;
  let sockGen = 0; // bumped on every open/close of the SESSION, so a stale retry timer can tell
  let reconnectDelay = RECONNECT_BASE_MS;
  let reconnectTimer = null;
  let stableTimer = null;
  let connectTimer = null;
  let hiddenAt = 0;
  let visibilityBound = false;
  // Wake detector. Timers do not run while the machine sleeps, so a tick that lands long after the
  // previous one means the page just woke — even in a tab that stayed visible the whole time, which
  // never fires visibilitychange.
  const WAKE_TICK_MS = 5000;
  let wakeTimer = null;
  let lastTick = 0;
  // Counts `state` pushes, so a catch-up snapshot that lands after a newer push is dropped instead
  // of painting older evidence over newer.
  let statePushes = 0;

  // The connection line shares #status with synthesis results, report paths and import warnings. A
  // reconnect can happen at any moment, so it only replaces text that is itself about the
  // connection — never a message the analyst still needs to read.
  function setConnStatus(text, force) {
    const el = document.getElementById("status");
    if (!el) return;
    const conn =
      /^(connected \(live\)|disconnected.*|live updates unavailable.*)?$/;
    if (force || conn.test(el.textContent)) el.textContent = text;
  }

  function clearTimers() {
    clearTimeout(reconnectTimer);
    clearTimeout(stableTimer);
    clearTimeout(connectTimer);
    reconnectTimer = stableTimer = connectTimer = null;
  }

  function detach(sock) {
    try {
      sock.onopen = null;
      sock.onclose = null;
      sock.onmessage = null;
      sock.close();
    } catch {}
  }

  function stillWanted(caseId) {
    return liveCaseId === caseId && activeCaseId === caseId;
  }

  // The push types whose panels the `state` replay does NOT reload (#1681). A push of any of these
  // during the gap was lost, so a reconnect sends each one through the handler once, bare. Every
  // branch in handleCaseMessage for these types reads nothing but msg.type — a test enforces it.
  // Left out on purpose: capture_ingest and import_ingest are one-off events, not state, and a
  // replay would raise a false case-mismatch banner; scope_changed needs msg.start/msg.end, so
  // catchUp fetches the window and sends it with them.
  const CATCH_UP_TYPES = [
    "comments_changed",
    "activity_changed",
    "tags_changed",
    "pins_changed",
    "finding_workflow_changed",
    "finding_outcome_changed",
    "notebook_changed",
    "dwell_window_changed",
    "super_timeline_changed",
    "asset_overrides_changed",
    "import_meta_changed",
    "drop_status_changed",
    "import_undo_changed",
    "velo_hunt_changed",
    "velo_monitor_changed",
    "push_token_changed",
    "importers_changed",
    "false_positive_changed",
    "learned_patterns_changed",
    "source_trust_changed",
    "clock_skew_changed",
  ];

  function stillCurrent(sock, caseId) {
    return sock === ws && stillWanted(caseId) && !!liveOnMessage;
  }

  // What the page missed while the socket was down. AI state and jobs are cheap reads; the case
  // state goes through the `state` handler so its panel fan-out runs exactly as a push would, and
  // every other push-driven panel is re-read the same way (#1681).
  function catchUp(sock, caseId) {
    if (typeof loadJobs === "function") loadJobs(caseId);
    const base = `/cases/${encodeURIComponent(caseId)}`;
    const pushesAtStart = statePushes;
    fetch(`${base}/state`)
      .then((r) => (r.ok ? r.json() : null))
      .then((state) => {
        if (pushesAtStart !== statePushes) return; // a newer state already arrived by push
        if (state && stillCurrent(sock, caseId))
          liveOnMessage({ type: "state", state });
      })
      .catch(() => {});
    for (const type of CATCH_UP_TYPES) {
      if (!stillCurrent(sock, caseId)) return;
      try {
        liveOnMessage({ type });
      } catch (err) {
        console.warn(`live catch-up for ${type} failed:`, err);
      }
    }
    // The scope branch redraws with the window it is given, which loadScope alone would not do.
    fetch(`${base}/scope`)
      .then((r) => (r.ok ? r.json() : null))
      .then((s) => {
        if (s && stillCurrent(sock, caseId))
          liveOnMessage({ type: "scope_changed", start: s.start, end: s.end });
      })
      .catch(() => {});
  }

  function scheduleReconnect() {
    clearTimers();
    const gen = sockGen;
    const caseId = liveCaseId;
    const delay = reconnectDelay;
    reconnectDelay = Math.min(delay * 2, RECONNECT_MAX_MS);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (gen === sockGen && stillWanted(caseId)) openSocket(true);
    }, delay);
  }

  function openSocket(isReconnect) {
    const caseId = liveCaseId;
    let sock;
    try {
      sock = new WebSocket(
        `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws?caseId=${encodeURIComponent(caseId)}`,
      );
    } catch (wsErr) {
      ws = null;
      if (isReconnect) return scheduleReconnect();
      setConnStatus(
        "live updates unavailable (WebSocket blocked — HTTPS/ws mismatch?)",
        true,
      );
      console.warn("WebSocket connection failed:", wsErr);
      liveCaseId = null;
      return;
    }
    ws = sock;
    connectTimer = setTimeout(() => {
      if (sock !== ws || sock.readyState !== WebSocket.CONNECTING) return;
      detach(sock);
      scheduleReconnect();
    }, CONNECT_TIMEOUT_MS);
    sock.onopen = () => {
      if (sock !== ws) return;
      clearTimeout(connectTimer);
      stableTimer = setTimeout(() => {
        reconnectDelay = RECONNECT_BASE_MS;
      }, STABLE_OPEN_MS);
      setConnStatus("connected (live)", !isReconnect);
      // Anything that happened while the socket was down was never delivered, so the pill may be
      // holding a state the case left behind. Re-derive rather than assume the gap was quiet.
      refreshAiState(caseId);
      if (isReconnect) catchUp(sock, caseId);
    };
    sock.onclose = () => {
      if (sock !== ws || !stillWanted(caseId)) return;
      setConnStatus("disconnected — reconnecting…");
      scheduleReconnect();
    };
    sock.onmessage = (ev) => {
      if (sock !== ws || !liveOnMessage) return;
      const msg = JSON.parse(ev.data);
      if (msg && msg.type === "state") statePushes++;
      liveOnMessage(msg);
    };
  }

  function onVisibilityChange() {
    if (document.visibilityState !== "visible") {
      hiddenAt = Date.now();
      return;
    }
    const slept = hiddenAt && Date.now() - hiddenAt >= LONG_HIDE_MS;
    hiddenAt = 0;
    recheck(slept);
  }

  // Re-derive the pill, and reopen the socket if it is closed — or, after a sleep, even if it reads
  // OPEN. Shared by the tab-visible and the wake paths.
  function recheck(slept) {
    const caseId = liveCaseId;
    if (!caseId || !stillWanted(caseId)) return;
    refreshAiState(caseId);
    const state = ws ? ws.readyState : WebSocket.CLOSED;
    const alive =
      state === WebSocket.CONNECTING || (state === WebSocket.OPEN && !slept);
    if (alive) return;
    if (ws) detach(ws);
    clearTimers();
    reconnectDelay = RECONNECT_BASE_MS;
    openSocket(true);
  }

  function onWakeTick() {
    const now = Date.now();
    const slept = now - lastTick >= LONG_HIDE_MS;
    lastTick = now;
    if (slept) recheck(true);
  }

  /** Retire the case socket: no reconnect, no pending retry, no late event. */
  function closeCaseSocket() {
    sockGen++;
    liveCaseId = null;
    liveOnMessage = null;
    clearTimers();
    clearInterval(wakeTimer);
    wakeTimer = null;
    if (ws) detach(ws);
    ws = null;
  }

  /** Open the live socket for `caseId`; every push is parsed and handed to `onMessage`. */
  function openCaseSocket(caseId, onMessage) {
    closeCaseSocket();
    liveCaseId = caseId;
    liveOnMessage = onMessage;
    reconnectDelay = RECONNECT_BASE_MS;
    if (!visibilityBound) {
      visibilityBound = true;
      document.addEventListener("visibilitychange", onVisibilityChange);
    }
    lastTick = Date.now();
    wakeTimer = setInterval(onWakeTick, WAKE_TICK_MS);
    openSocket(false);
  }

  window.openCaseSocket = openCaseSocket;
  window.closeCaseSocket = closeCaseSocket;
})();
