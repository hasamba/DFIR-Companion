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
//  - That catch-up is ~30 requests, so it runs ONCE per outage, not once per open (#1709). It waits
//    until a reopened socket has stayed up, which collapses a flapping server into one run — but
//    never longer than CATCH_UP_MAX_DEFER_MS, so a flap cannot put it off forever. It is never
//    skipped: the server keeps no replay buffer, so any gap, however short, can lose a push.
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
  // A reopened socket must stay up this long before its catch-up runs (#1709) …
  const CATCH_UP_SETTLE_MS = 2000;
  // … unless a catch-up has been owed this long already: then the next open runs it at once.
  const CATCH_UP_MAX_DEFER_MS = 10000;
  // The catch-up's requests share the case load's cap: four of the browser's six HTTP/1.1 lanes,
  // leaving two for whatever the analyst clicks meanwhile (PANEL_LOAD_CONCURRENCY in
  // js/dashboard-case-connect.js explains the number).
  const CATCH_UP_CONCURRENCY = 4;

  let liveCaseId = null; // the case the live socket serves; null when none is wanted
  let liveOnMessage = null;
  let sockGen = 0; // bumped on every open/close of the SESSION, so a stale retry timer can tell
  let reconnectDelay = RECONNECT_BASE_MS;
  let reconnectTimer = null;
  let stableTimer = null;
  let connectTimer = null;
  let catchUpTimer = null;
  // Aborts the running catch-up's requests that are still queued for a lane.
  let catchUpAbort = null;
  // When the first reopened socket that owed a catch-up opened; 0 when none is owed.
  let catchUpOwedSince = 0;
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

  // State-changed notices (#2615). The server no longer pushes the whole case; it pushes a small
  // `{type:"state_changed", caseId, version}` and the page reads the paged GET /cases/:id/state it
  // already uses for a load. A burst of notices (an import settling) must not become a burst of
  // reads: they are debounced, one read is in flight at a time, and notices that arrive during it
  // are folded into ONE more read afterwards.
  const STATE_NOTICE_DEBOUNCE_MS = 250;
  // A read that has not answered by now counts as failed, so one stalled request cannot block the
  // notices behind it. A failed read is retried with backoff (the notice stays owed until a read
  // lands); after this many failures in a row the analyst is told, and the next notice tries again.
  const STATE_READ_TIMEOUT_MS = 20000;
  const STATE_READ_MAX_ATTEMPTS = 5;
  let noticeTimer = null;
  // Refresh bookkeeping belongs to ONE socket session: closing or replacing the socket retires it
  // (retireRefresh), so a request left over from an old session can never block or alter the next.
  function newRefresh() {
    return {
      dead: false,
      inFlight: false,
      pending: false,
      attempts: 0,
      abort: null,
      timeoutTimer: null,
      retryTimer: null,
    };
  }
  let refresh = newRefresh();
  let noticeSeen = 0; // highest notice version heard on this socket
  let noticeApplied = 0; // highest notice version a state read has already covered

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
    clearTimeout(catchUpTimer);
    reconnectTimer = stableTimer = connectTimer = catchUpTimer = null;
    clearTimeout(noticeTimer);
    noticeTimer = null;
    retireRefresh();
    // A drop, a wake, a case switch and a cancel all come through here. A catch-up already running
    // is abandoned too: its queued requests would otherwise reach the wire after a case switch and
    // paint the old case into panels that do not check which case is on screen, and the next
    // reconnect's catch-up would run beside it, two lane caps at once. The next open owes a fresh one.
    if (catchUpAbort) catchUpAbort.abort();
    catchUpAbort = null;
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
    "confidence_control_changed",
    "report_template_changed",
    "case_lifecycle_changed",
    "watson_changed",
  ];

  function stillCurrent(sock, caseId) {
    return sock === ws && stillWanted(caseId) && !!liveOnMessage;
  }

  // The one place the page reads the case state for the live socket: catch-up and every state-changed
  // notice go through it. Null when the read failed or the server answered with an error.
  function fetchCaseState(caseId, signal) {
    return fetch(`/cases/${encodeURIComponent(caseId)}/state`, signal ? { signal } : undefined)
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null);
  }

  function noticeVersionOf(msg) {
    return typeof msg.version === "number" && Number.isFinite(msg.version) ? msg.version : null;
  }

  // A notice for the case on screen. Duplicate or reordered notices (a version already covered by a
  // read) are ignored; the rest wait out the debounce and then share one read.
  function onStateNotice(sock, caseId, msg) {
    if (msg.caseId !== undefined && msg.caseId !== caseId) return;
    const r = refresh;
    const version = noticeVersionOf(msg);
    if (version !== null) {
      if (version <= noticeApplied) return;
      if (version > noticeSeen) noticeSeen = version;
    }
    if (noticeTimer) return;
    noticeTimer = setTimeout(() => {
      noticeTimer = null;
      readStateForNotice(sock, caseId, r);
    }, STATE_NOTICE_DEBOUNCE_MS);
  }

  function retireRefresh() {
    const r = refresh;
    r.dead = true;
    clearTimeout(r.timeoutTimer);
    clearTimeout(r.retryTimer);
    if (r.abort) {
      try {
        r.abort.abort();
      } catch {}
    }
    refresh = newRefresh();
  }

  function readStateForNotice(sock, caseId, r) {
    if (r.dead || !stillCurrent(sock, caseId)) return;
    clearTimeout(r.retryTimer); // a fresh notice supersedes a waiting retry
    r.retryTimer = null;
    if (r.inFlight) {
      r.pending = true; // one more read once this one ends, however many notices arrive
      return;
    }
    r.inFlight = true;
    const covers = noticeSeen;
    const pushesAtStart = statePushes;
    const ctl = typeof AbortController === "function" ? new AbortController() : null;
    r.abort = ctl;
    let settled = false;
    const settle = (state, failed) => {
      if (settled) return;
      settled = true;
      clearTimeout(r.timeoutTimer);
      r.timeoutTimer = null;
      r.abort = null;
      if (r.dead) return; // the session this read belonged to is gone; it changes nothing now
      r.inFlight = false;
      if (failed) return onStateReadFailed(sock, caseId, r);
      r.attempts = 0;
      if (state && stillCurrent(sock, caseId) && !(state.caseId !== undefined && state.caseId !== caseId) &&
          pushesAtStart === statePushes) {
        if (covers > noticeApplied) noticeApplied = covers;
        statePushes++;
        liveOnMessage({ type: "state", state });
      }
      if (r.pending) {
        r.pending = false;
        readStateForNotice(ws, liveCaseId, r);
      }
    };
    r.timeoutTimer = setTimeout(() => {
      if (ctl) ctl.abort();
      settle(null, true);
    }, STATE_READ_TIMEOUT_MS);
    fetchCaseState(caseId, ctl ? ctl.signal : undefined)
      .then((state) => settle(state, state === null))
      .catch(() => settle(null, true));
  }

  // The notice stays owed until a read covers it: retry with backoff while this session lasts.
  function onStateReadFailed(sock, caseId, r) {
    r.attempts++;
    if (r.attempts >= STATE_READ_MAX_ATTEMPTS) {
      setConnStatus("live updates unavailable — the case state could not be refreshed");
      r.pending = false;
      return; // the next notice (or a reconnect's catch-up) tries again
    }
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** (r.attempts - 1), RECONNECT_MAX_MS);
    r.retryTimer = setTimeout(() => {
      r.retryTimer = null;
      r.pending = false;
      readStateForNotice(sock, caseId, r);
    }, delay);
  }

  // What the page missed while the socket was down. AI state and jobs are cheap reads; the case
  // state goes through the `state` handler so its panel fan-out runs exactly as a push would, and
  // every other push-driven panel is re-read the same way (#1681).
  //
  // Every message carries one shared catch-up context (#1709). Several types reload the same panel
  // — /cockpit alone was fetched five times — and the handler uses `ctx.ran` to run each of those
  // loaders once per catch-up. A real push carries no context, so it always reloads.
  function catchUp(sock, caseId) {
    const base = `/cases/${encodeURIComponent(caseId)}`;
    const pushesAtStart = statePushes;
    const ctx = { source: "catch-up", ran: new Set() };
    const send = (msg) => {
      if (stillCurrent(sock, caseId)) liveOnMessage(msg, ctx);
    };
    const entries = [
      ["jobs", () => typeof loadJobs === "function" && loadJobs(caseId)],
      [
        "state",
        () =>
          fetchCaseState(caseId)
            .then((state) => {
              if (pushesAtStart !== statePushes) return; // a newer state already arrived by push
              if (state) send({ type: "state", state });
            })
            .catch(() => {}),
      ],
      // The scope branch redraws with the window it is given, which loadScope alone would not do.
      [
        "scope",
        () =>
          fetch(`${base}/scope`)
            .then((r) => (r.ok ? r.json() : null))
            .then((s) => {
              if (s) send({ type: "scope_changed", start: s.start, end: s.end });
            })
            .catch(() => {}),
      ],
      ...CATCH_UP_TYPES.map((type) => [
        type,
        () => {
          try {
            send({ type });
          } catch (err) {
            console.warn(`live catch-up for ${type} failed:`, err);
          }
        },
      ]),
    ];
    // The signal is the case load's own contract: an abandoned request hands its loader a promise
    // that never settles, so it draws nothing. Every loader here already runs under it on a case
    // switch. Two of them — jobs, and tags via the tags_changed replay — do hold a lock until their
    // request settles; runPanelLoaders announces the abort and both drop it there (#2400).
    const runner =
      window.DfirCaseLoadProgress && window.DfirCaseLoadProgress.runPanelLoaders;
    if (typeof runner === "function" && typeof AbortController === "function") {
      catchUpAbort = new AbortController();
      runner(entries, null, {
        // The page-wide pool (#1713), shared with the case load and the debounced panel reloads.
        lanes: window.DfirCaseLoadProgress.panelLanes,
        concurrency: CATCH_UP_CONCURRENCY,
        signal: catchUpAbort.signal,
      });
    } else
      for (const [, run] of entries) {
        if (!stillCurrent(sock, caseId)) return;
        try {
          run();
        } catch {}
      }
  }

  // Run the catch-up once the reopened socket has stayed up — or at once, if one has been owed for
  // CATCH_UP_MAX_DEFER_MS. A close before then cancels it (clearTimers), and the next open owes it.
  function scheduleCatchUp(sock, caseId) {
    const now = Date.now();
    if (!catchUpOwedSince) catchUpOwedSince = now;
    const wait = Math.max(
      0,
      Math.min(CATCH_UP_SETTLE_MS, catchUpOwedSince + CATCH_UP_MAX_DEFER_MS - now),
    );
    catchUpTimer = setTimeout(() => {
      catchUpTimer = null;
      if (!stillCurrent(sock, caseId)) return;
      catchUpOwedSince = 0;
      catchUp(sock, caseId);
    }, wait);
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

  // The message a frame carries, or null when it is not one. The hub accepts any value, so the shape
  // is checked here: a string `type`, and for `state` an object to render.
  function parseLiveMessage(data) {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      return null;
    }
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) return null;
    if (typeof msg.type !== "string") return null;
    const s = msg.state;
    if (msg.type === "state" && (!s || typeof s !== "object" || Array.isArray(s))) return null;
    return msg;
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
    // Notice numbers count per server process, so a new socket (maybe a restarted server) starts over.
    noticeSeen = noticeApplied = 0;
    retireRefresh();
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
      if (isReconnect) scheduleCatchUp(sock, caseId);
    };
    sock.onclose = () => {
      if (sock !== ws || !stillWanted(caseId)) return;
      setConnStatus("disconnected — reconnecting…");
      scheduleReconnect();
    };
    let warnedBadFrame = false;
    sock.onmessage = (ev) => {
      if (sock !== ws || !liveOnMessage) return;
      // A frame that is not a live message is skipped before it can count as a state push (#1707).
      // One fixed warning per socket, never echoing the frame: a broken producer must not flood
      // DevTools, and the frame's content is not ours to log.
      const msg = parseLiveMessage(ev.data);
      if (!msg) {
        if (!warnedBadFrame) console.warn("live update skipped: a frame was not a live message");
        warnedBadFrame = true;
        return;
      }
      if (msg.type === "state_changed") return onStateNotice(sock, caseId, msg);
      if (msg.type === "state") statePushes++; // a legacy full frame: still rendered as before
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
    catchUpOwedSince = 0;
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
