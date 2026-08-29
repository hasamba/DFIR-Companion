// The AI status banner — what the provider is doing right now, and clearing it when it stops
// (#415 tier 3).
//
// The singleton cluster under the import-progress heading. Nothing in it touches the progress bar
// and nothing there touches this.
(function () {
  function applyAiStatus(evt) {
    if (evt.status === "analyzing") {
      // Drive the progress bar from server-side "kind import — N/M" updates (40 → 95%).
      const m =
        evt.detail && evt.detail.match(/import\s*[—\-]\s*(\d+)\/(\d+)/i);
      if (m) {
        const d = +m[1],
          t = +m[2];
        if (t > 0) showImportProgress(40 + (d / t) * 55);
      }
      // Deterministic evidence import/ingest is NOT AI work: it runs even with AI switched off
      // (resynthesizeInBackground gates the LLM on the per-case toggle server-side). The import
      // routes only reuse this AI-status channel to drive the progress bar, so relabel their
      // updates honestly instead of claiming "AI: processing…" while the AI is off. Import
      // updates are recognisable by the detail text ("importing …" / "<kind> import — N/M");
      // screenshot extraction + synthesis (genuine AI) keep the AI label.
      // NOTE: the `!aiEnabled` fallback below is belt-and-suspenders for the AUTO live-analysis loop
      // ONLY — aiEnabled is the per-case "live analysis paused/resumed" toggle, not "is AI configured".
      // Manual on-demand AI (Re-synthesize, Second opinion, Ask …) can run while that toggle is OFF,
      // so every server route emitting one of those MUST set `phase: "synthesizing"` (checked first,
      // below) rather than relying on this fallback — otherwise a genuine AI call gets mislabeled
      // "deterministic import — not AI" whenever the analyst has paused live analysis (found live: the
      // second-opinion badge showed that exact false label with the toggle off — see aiSynthesis.ts).
      const isIngest =
        !!m || (evt.detail && /^importing\b/i.test(evt.detail)) || !aiEnabled;
      // Deep pass (#204) carries its own phase because its detail already reads as a full sentence
      // ("deep pass (Medium+) — reading batch 2 of 5") and it is the longest AI run in the product:
      // it must never fall through to the isIngest branch, which would label it a deterministic
      // import whenever live analysis is paused — a deep pass runs regardless of that toggle.
      if (evt.phase === "deep-pass")
        setAi("analyzing", evt.detail || "deep pass running…");
      else if (evt.phase === "synthesizing")
        setAi("analyzing", "synthesizing findings… " + (evt.detail || ""));
      else if (evt.detail && /^enriching IOC/.test(evt.detail)) {
        const el = document.getElementById("aiStatus");
        el.className = "ai-analyzing";
        el.textContent = evt.detail;
        el.title = evt.detail;
      } else if (isIngest) {
        const el = document.getElementById("aiStatus");
        el.className = "ai-analyzing";
        const label = evt.detail || "importing evidence…";
        el.textContent = label; // no "AI:" prefix — this is deterministic ingest
        el.title = label + " (deterministic import — not AI)";
      } else setAi("analyzing", "processing evidence… " + (evt.detail || ""));
    } else if (evt.status === "idle") {
      hideImportProgress();
      setAi("idle", "idle — up to date (" + fmtTime(evt.at) + ")");
      clearTransientStatus(); // re-synthesis finished → drop the "…re-synthesizing" line
      // "Idle" is the event most likely to be WRONG about a case, because it is emitted by whichever
      // run just finished and that run knows nothing about a gate still holding the next one. Verify
      // it against the case rather than let a stale "up to date" sit over an unresolved decision.
      refreshAiState(activeCaseId);
      // Every import path answers 202 before its background job lands the new events in the
      // timeline (see js/dashboard-unified-import.js), so this "run just finished" event — not the
      // fetch resolving — is the earliest safe point to re-check for a near-duplicate host (e.g.
      // "HOST" vs "HOST.domain") the import just introduced. Runs on every idle, not only imports,
      // but loadHostDuplicates is a cheap GET and this is the only reliable "import settled" signal
      // available client-side, including when AI is off.
      loadHostDuplicates(activeCaseId);
      // Same signal, same reason (#679): an import that lands a C2 domain already sitting in
      // another case is exactly when the analyst should be told, and the Related Cases panel is
      // otherwise only loaded on case connect — so the link would stay invisible until the next
      // page load.
      loadRelatedCases(activeCaseId);
    } else if (evt.status === "blocked") {
      // A GATE, not a failure: the pipeline stopped on purpose and is waiting for a decision (a
      // Presidio approval, a duplicate-host merge). Both used to arrive as "error", which painted
      // a red "AI: error" over a question — analysts read it as a broken provider and never went
      // looking for the buttons that would release the run. Amber, and it says "on hold".
      hideImportProgress();
      setAi(
        "blocked",
        "on hold — " + (evt.detail || "waiting on your decision"),
      );
      clearTransientStatus();
      // Refresh BOTH pending lists rather than parse the detail text: the two gates share this
      // status, each list is a cheap request, and whichever one is empty simply hides its chip.
      loadPresidioPending(activeCaseId);
      loadHostDuplicates(activeCaseId);
    } else if (evt.status === "error") {
      hideImportProgress();
      setAi("error", "error — " + (evt.detail || "see server log"));
      clearTransientStatus();
      // Imports are fire-and-forget (202 immediately, pipeline runs in the background) — when the
      // Presidio approval gate stops one, there is no synchronous response to carry a 409, so this
      // is how that case surfaces at all. Re-check the persisted pending list rather than assume
      // the error text; it's cheap and this is the ONLY path a stopped import gets noticed on.
      //
      // STILL CHECKED HERE even though the gates now report "blocked": a gate that fires on a path
      // which reports its own generic error (rather than routing through sendPipelineError) would
      // otherwise leave the chip down, and this check is what caught that case before.
      loadPresidioPending(activeCaseId);
      // Same reason as the Presidio line above: an import is fire-and-forget, so a gate that fires
      // mid-import has no response to carry its 409. This is the only path it surfaces on.
      loadHostDuplicates(activeCaseId);
    }
  }

  // Reset the #status line to the normal connected state, but only when it is
  // showing a transient background-work message (so we don't clobber e.g. a
  // "report written: …" notice).
  function clearTransientStatus() {
    const el = document.getElementById("status");
    // "catching up" is the optimistic message toggleAi() writes when AI is switched on; it must
    // be cleared once the backfill reports idle, or it stays stuck (it's not a live indicator).
    if (
      /synthesiz|applying scope|marking false positive|import|catching up/i.test(
        el.textContent,
      )
    ) {
      el.textContent =
        ws && ws.readyState === 1 ? "connected (live)" : "disconnected";
    }
  }

  // ── The correction ───────────────────────────────────────────────────────────────────────────
  //
  // Everything above reacts to a PUSHED event. That was the pill's only source of state, and it is
  // why three bugs were possible: a wrong event (it announced a synthesis the merge gate would
  // refuse), an absent event (it stayed "on hold" after the last Presidio approval cleared), and no
  // event at all (a page reload set it from /health — which is server-wide and cannot know anything
  // about a case — so a reload on a held case read "ready (waiting for activity)").
  //
  // GET /cases/:id/ai-state derives the answer from the case instead. Pushed events stay the fast
  // path for live progress; this is what the pill falls back to whenever it needs the truth rather
  // than the latest rumour.

  /** Render a derived AiState (see companion/src/analysis/aiState.ts) onto the pill. */
  function paintAiState(s) {
    // A hold rides ALONGSIDE the state: a running import is real work even while synthesis is held,
    // so the pill names the work and appends the hold rather than hiding either one.
    const heldNote = s.holds && s.holds.length ? " (analysis on hold)" : "";
    if (s.state === "off") setAi("off", s.detail || "off");
    else if (s.state === "blocked")
      setAi("blocked", "on hold — " + (s.detail || "waiting on your decision"));
    else if (s.state === "error")
      setAi("error", "error — " + (s.detail || "see server log"));
    else if (s.state === "analyzing")
      setAi("analyzing", (s.detail || "working…") + heldNote);
    else setAi("idle", s.detail || "up to date");
  }

  async function refreshAiState(caseId) {
    if (!caseId) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/ai-state`);
      if (!r.ok) return; // leave the pill as it is; a failed correction must not invent a state
      paintAiState(await r.json());
    } catch {
      // Never let the corrector be the thing that breaks the page it exists to fix.
    }
  }

  window.applyAiStatus = applyAiStatus;
  window.clearTransientStatus = clearTransientStatus;
  window.refreshAiState = refreshAiState;
})();
