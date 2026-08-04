// Chain of custody (#231) (#415 tier 3).
//
// The button wiring comes with it. `initCustodyButtons` is a named IIFE rather than a function
// declaration, so a walk over top-level declarations does not see it — and it writes two of this
// feature's three cells, which is exactly why it had to travel with them.
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // ── Chain of Custody (#231) ───────────────────────────────────────────────────────────
  // Every artifact this case has stored, grouped with the full sequence of events that touched
  // it. Grouped by artifact rather than shown as a flat log because the question an analyst has
  // is "what happened to THIS piece of evidence" — the same reasoning as the report appendix.
  // Verification state is filled in by "Verify now" (a re-hash of every artifact, which is far
  // too heavy to run just because a panel rendered).
  let custodyRecords = [];
  let custodyFailedPaths = new Set();
  let custodyVerifiedAt = null;

  function renderCustody() {
    const el = document.getElementById("custodyPanel");
    if (!el) return;
    if (!custodyRecords.length) {
      el.innerHTML = "<div data-safe-style='color:var(--text-muted);font-size:12px'>No custody records for this case yet. Artifacts are recorded automatically as screenshots and imports are stored.</div>";
      return;
    }
    const byPath = custodyGroupByArtifact(custodyRecords);
    const rows = [];
    byPath.forEach((chain, path) => {
      const name = path.split(/[\\/]/).pop() || path;
      const last = chain[chain.length - 1];
      const failed = custodyFailedPaths.has(path);
      const state = failed
        ? "<span data-safe-style='color:#e5484d;font-weight:600' title='This artifact no longer matches its recorded hash, or is missing'>&#9888; FAILED</span>"
        : (custodyVerifiedAt ? "<span data-safe-style='color:#46a758' title='Re-hashed and matching'>&#10003; verified</span>" : "<span data-safe-style='color:var(--text-muted)'>&mdash;</span>");
      const events = chain.map(r => `<tr data-safe-style="border-bottom:1px solid var(--border-color)">
          <td data-safe-style="padding:3px 8px;white-space:nowrap;color:var(--text-muted)">${esc(String(r.seq ?? ""))}</td>
          <td data-safe-style="padding:3px 8px;white-space:nowrap">${esc(r.event || "collected")}</td>
          <td data-safe-style="padding:3px 8px;white-space:nowrap;color:var(--text-muted)" title="${escAttr(r.collectedAt)}">${activityTimeAgo(r.collectedAt)}</td>
          <td data-safe-style="padding:3px 8px;white-space:nowrap">${esc(r.collectedBy)}</td>
          <td data-safe-style="padding:3px 8px">${esc(r.source)}</td>
          <td data-safe-style="padding:3px 8px;white-space:nowrap;color:var(--text-muted)">${esc(r.trigger)}</td>
        </tr>`).join("");
      rows.push(`<details data-safe-style="border-bottom:1px solid var(--border-color)">
        <summary data-safe-style="padding:5px 8px;cursor:pointer;display:grid;grid-template-columns:1fr auto auto auto;gap:10px;align-items:center;font-size:12px">
          <span title="${escAttr(path)}">${esc(name)}</span>
          <span data-safe-style="color:var(--text-muted)">${chain.length} event(s)</span>
          <code data-safe-style="color:var(--text-muted);font-size:11px" title="${escAttr(last.sha256)}">${esc(String(last.sha256).slice(0, 12))}&hellip;</code>
          <span>${state}</span>
        </summary>
        <div data-safe-style="padding:4px 8px 10px">
          <div data-safe-style="font-size:11px;color:var(--text-muted);margin-bottom:4px">${esc(path)}</div>
          <table data-safe-style="width:100%;font-size:12px;border-collapse:collapse">
            <tr data-safe-style="color:var(--text-muted)"><td data-safe-style="padding:3px 8px">#</td><td data-safe-style="padding:3px 8px">Event</td><td data-safe-style="padding:3px 8px">When</td><td data-safe-style="padding:3px 8px">By</td><td data-safe-style="padding:3px 8px">Source</td><td data-safe-style="padding:3px 8px">Trigger</td></tr>
            ${events}
          </table>
        </div>
      </details>`);
    });
    el.innerHTML = `<div data-safe-style="font-size:12px;color:var(--text-muted);margin-bottom:6px">${byPath.size} artifact(s), ${custodyRecords.length} recorded event(s).</div>` + rows.join("");
  }

  function loadCustody(caseId) {
    fetch(`/cases/${caseId}/custody`)
      .then(r => r.ok ? r.json() : { records: [] })
      .then(d => { custodyRecords = d.records || []; renderCustody(); })
      .catch(() => {});
    const link = document.getElementById("custodyManifestLink");
    if (link) link.href = `/cases/${caseId}/custody/manifest`;
  }

  // NOT an IIFE any more. It ran at its old position in the inline script — AFTER the custody
  // markup — but this is a <head> module, so running it here would call getElementById() before the
  // buttons exist and silently wire nothing. The page calls it where the IIFE used to run.
  function initCustodyButtons() {
    const verifyBtn = document.getElementById("custodyVerifyBtn");
    const refreshBtn = document.getElementById("custodyRefreshBtn");
    const msg = document.getElementById("custodyVerifyMsg");
    if (refreshBtn) refreshBtn.addEventListener("click", () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (caseId) loadCustody(caseId);
    });
    if (!verifyBtn) return;
    verifyBtn.addEventListener("click", () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      verifyBtn.disabled = true;
      if (msg) msg.textContent = "Re-hashing evidence…";
      // The synchronous verify endpoint: it re-reads every artifact, so it can take a while on a
      // case holding disk images. The button stays disabled until it answers.
      fetch(`/cases/${caseId}/custody/verify`)
        .then(r => r.ok ? r.json() : null)
        .then(d => {
          if (!d) { if (msg) msg.textContent = "Verification unavailable."; return; }
          custodyFailedPaths = new Set((d.mismatches || []).map(m => m.artifactPath));
          custodyVerifiedAt = new Date().toISOString();
          const breaks = (d.chainBreaks || []).length;
          if (msg) {
            msg.textContent = d.ok
              ? "All artifacts verified, custody log intact."
              : `${custodyFailedPaths.size} artifact(s) failed${breaks ? `, ${breaks} custody-log chain break(s)` : ""}.`;
            msg.style.color = d.ok ? "#46a758" : "#e5484d";
          }
          renderCustody();
        })
        .catch(() => { if (msg) msg.textContent = "Verification failed to run."; })
        .finally(() => { verifyBtn.disabled = false; });
    });
  }

  // Ask the server to re-verify THIS case's stored evidence now that an analyst is looking at it
  // (#231). Fire-and-forget: the server returns 202 immediately and hashes in the background, and
  // throttles internally so flipping between cases re-hashes nothing. A 501 (no monitor wired) or
  // any transport error is ignored — verification is assurance, never a blocker on opening a case.
  function verifyCustodyOnOpen(caseId) {
    fetch(`/cases/${caseId}/custody/verify`, { method: "POST" }).catch(() => {});
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.initCustodyButtons = initCustodyButtons;
  window.loadCustody = loadCustody;
  window.verifyCustodyOnOpen = verifyCustodyOnOpen;
})();
