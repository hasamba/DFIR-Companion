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
    } else if (evt.status === "error") {
      hideImportProgress();
      setAi("error", "error — " + (evt.detail || "see server log"));
      clearTransientStatus();
      // Imports are fire-and-forget (202 immediately, pipeline runs in the background) — when the
      // Presidio approval gate stops one, there is no synchronous response to carry a 409, so this
      // is how that case surfaces at all. Re-check the persisted pending list rather than assume
      // the error text; it's cheap and this is the ONLY path a stopped import gets noticed on.
      loadPresidioPending(activeCaseId);
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

  window.applyAiStatus = applyAiStatus;
  window.clearTransientStatus = clearTransientStatus;
})();
