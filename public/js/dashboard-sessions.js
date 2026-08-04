// Attacker Sessions story view (#341 / #229) (#415 tier 3).
//
// `sessionsCollapsed` deliberately did NOT come along: the collapse-all control in the timeline
// header reads it, so it is shared state and stays in the page. The rest — the segmentation, its
// debounce timer and the ephemeral per-session summaries — is this feature's alone.
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // ── Attacker Sessions story view (#341 / #229) ────────────────────────────────────────
  // The timeline re-threaded as per-host chapters. Derived server-side (GET /cases/:id/sessions)
  // from the raw forensic timeline; re-derived (debounced) on each state change like the panels
  // above. Clicking a card filters the Forensic Timeline below to exactly that session's events.
  let sessionsData = [];
  let sessionsTimer = null;
  const sessionSummaries = new Map();   // sessionId → markdown, for the current segmentation only

  function loadSessions(caseId) {
    fetch(`/cases/${caseId}/sessions`).then(r => r.ok ? r.json() : { sessions: [] }).then(d => {
      const next = Array.isArray(d && d.sessions) ? d.sessions : [];
      // Session ids are POSITIONAL within a segmentation run, so a re-derive can silently reassign
      // "session-3" to a different sitting. Drop cached summaries whose session no longer has the
      // same identity, or a card would show another session's account under its own heading.
      for (const [id, cached] of [...sessionSummaries]) {
        const still = next.find(s => s.id === id);
        if (!still || still.label !== cached.label) sessionSummaries.delete(id);
      }
      sessionsData = next;
      renderSessions();
    }).catch(() => {});
  }
  function scheduleSessionsReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(sessionsTimer);
    sessionsTimer = setTimeout(() => loadSessions(caseId), 800);
  }

  function renderSessions() {
    const el = document.getElementById("sessions");
    if (!el) return;
    const countEl = document.getElementById("sessionsCount");
    if (!sessionsData.length) {
      el.innerHTML = "<span data-safe-style='color:var(--text-muted)'>No attacker sessions — sessions are derived from dated timeline events.</span>";
      if (countEl) countEl.textContent = "";
      return;
    }
    const hosts = new Set(sessionsData.map(s => s.host));
    if (countEl) countEl.textContent = `(${sessionsData.length} session${sessionsData.length !== 1 ? "s" : ""} across ${hosts.size} host${hosts.size !== 1 ? "s" : ""})`;

    el.innerHTML = sessionsData.map((s, i) => {
      const worst = (s.severityRange && s.severityRange[0]) || "Info";
      // The server's unknown-host bucket is events whose asset was never recorded — possibly from
      // several machines. Render it as a stated absence, never as a hostname.
      const unknown = s.host === "(unknown host)";
      const hostCell = unknown
        ? `<span class="ses-host ses-unknown" title="These events' source tool did not report an affected asset. They are grouped by time alone and may span more than one machine.">host not recorded</span>`
        : `<span class="ses-host">${esc(s.host)}</span>`;
      const acct = s.account ? `<span class="ses-acct" title="Account established by a successful logon inside this session">${esc(s.account)}</span>` : "";
      const tactic = s.dominantTactic ? `<span class="ses-tactic" title="Most common ATT&amp;CK tactic across this session's events">${esc(s.dominantTactic)}</span>` : "";
      const sum = sessionSummaries.get(s.id);
      const summaryBlock = sum ? `<div class="ses-summary">${esc(sum.markdown)}</div>` : "";
      const rows = (s.eventIds || []).length;
      return `<div class="ses-card sevr-${esc(worst)}" data-sesid="${escAttr(s.id)}" data-evids="${escAttr((s.eventIds || []).join(","))}" data-label="${escAttr(s.label || "")}" title="Click to filter the Forensic Timeline to this session's events">`
        + `<div class="ses-head"><span class="ses-num">#${i + 1}</span>${hostCell}${acct}${tactic}`
        + `<span class="ses-when">${esc(s.startTime)} → ${esc(s.endTime)}</span></div>`
        // Rows vs occurrences: eventCount sums aggregated `count`, so a single collapsed row can
        // report 14 events. Clicking the card filters the timeline to ROWS, so the card states the
        // row count and mentions occurrences only when the two actually differ — otherwise the
        // card promises 14 and the timeline below shows 1.
        + `<div class="ses-body"><span data-safe-style="color:var(--text-muted)">${esc(String(rows))} row${rows !== 1 ? "s" : ""}`
        + (s.eventCount > rows ? ` · ${esc(String(s.eventCount))} occurrences` : "")
        + ` · ${esc((s.severityRange || []).join(", "))}</span>`
        + `<div class="ses-actions">`
        + `<button type="button" class="ses-btn ses-filter">⧉ Show these events</button>`
        + `<button type="button" class="ses-btn ses-summarize" title="One focused AI call over just this session's events">✨ Summarize session</button>`
        + `<span class="ses-msg"></span></div>${summaryBlock}</div></div>`;
    }).join("");
  }

  // One focused AI call over a single session (#342). Ephemeral — the answer is held in memory for
  // this segmentation only and is deliberately not persisted.
  function summarizeSession(card) {
    const caseId = document.getElementById("caseId").value.trim();
    const sid = card.getAttribute("data-sesid");
    if (!caseId || !sid) return;
    const msg = card.querySelector(".ses-msg");
    const btn = card.querySelector(".ses-summarize");
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = "summarizing…";
    fetch(`/cases/${caseId}/sessions/${encodeURIComponent(sid)}/summary`, {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}",
    }).then(r => r.json().then(b => ({ ok: r.ok, b }))).then(({ ok, b }) => {
      if (!ok) { if (msg) msg.textContent = (b && b.error) || "summary failed"; if (btn) btn.disabled = false; return; }
      sessionSummaries.set(sid, { markdown: b.markdown || "", label: b.label || "" });
      if (msg) msg.textContent = b.truncated ? `(${b.usedEvents} of ${b.eventCount} events used)` : "";
      renderSessions();
    }).catch(() => {
      if (msg) msg.textContent = "summary failed";
      if (btn) btn.disabled = false;
    });
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.loadSessions = loadSessions;
  window.scheduleSessionsReload = scheduleSessionsReload;
  window.summarizeSession = summarizeSession;
})();
