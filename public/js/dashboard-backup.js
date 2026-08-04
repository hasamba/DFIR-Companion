// Case backup restore (#180) (#415 tier 3).
//
// Holds no state at all; it is here because it is a self-contained feature rather than a helper.
// Reads its table renderers from window.DfirDiagnostics at CALL time, so load order is free.
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // Case backup restore (#180) ---------------------------------------------------------------
  function loadCaseBackups() {
    const { diagRow, diagCard, diagFmtBytes, diagFmtAge } = window.DfirDiagnostics; // see renderDiagnostics
    const caseId = document.getElementById("caseId").value.trim();
    const list = document.getElementById("diagBackupsList");
    const msg = document.getElementById("diagBackupMsg");
    const btn = document.getElementById("diagLoadBackupsBtn");
    if (!caseId) { if (msg) { msg.style.color = "#ffb05a"; msg.textContent = "select a case first"; } return; }
    if (msg) { msg.style.color = "#9aa4b2"; msg.textContent = "loading…"; }
    if (btn) btn.disabled = true;
    if (list) list.innerHTML = "";
    fetch(`/cases/${encodeURIComponent(caseId)}/backups`)
      .then(async r => { if (!r.ok) throw new Error(await r.text().catch(() => String(r.status))); return r.json(); })
      .then(j => {
        if (msg) { msg.style.color = ""; msg.textContent = ""; }
        const backups = j.backups || [];
        if (!backups.length) {
          list.innerHTML = `<div data-safe-style="color:#9aa4b2;padding:4px 0">No backups found for case <code>${esc(caseId)}</code>.</div>`;
          return;
        }
        const TRIGGER_COLOR = { "pre-synthesis": "#7ec8e3", scheduled: "#9aa4b2", "pre-import": "#b8ccff", shutdown: "#ffce8a" };
        list.innerHTML = `<div data-safe-style="color:#9aa4b2;font-size:11px;margin-bottom:6px">${backups.length} backup${backups.length !== 1 ? "s" : ""} for case <code>${esc(caseId)}</code> · newest first</div>` +
          backups.map((b, i) => {
            const col = TRIGGER_COLOR[b.trigger] || "#9aa4b2";
            const ts = (b.createdAt || "").replace("T", " ").slice(0, 19);
            return `<div data-safe-style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding:5px 8px;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;margin-bottom:5px;flex-wrap:wrap">
              <span data-safe-style="display:flex;gap:8px;align-items:center;min-width:0">
                <span data-safe-style="color:${col};font-size:11px;white-space:nowrap">${esc(b.trigger)}</span>
                <span data-safe-style="color:#cbd3df;font-family:monospace;font-size:11.5px">${esc(ts)}</span>
                <span data-safe-style="color:#7e8aa0;font-size:11px">${diagFmtBytes(b.sizeBytes)}</span>
              </span>
              <button type="button" class="bk-restore-btn" data-filename="${esc(b.filename)}" data-safe-style="padding:2px 10px;font-size:11px;background:#2a1a1a;border:1px solid #5a2a2a;border-radius:4px;color:#ffb05a;cursor:pointer;white-space:nowrap">↩ Restore</button>
            </div>`;
          }).join("");
      })
      .catch(e => {
        if (msg) { msg.style.color = "#ff9f9f"; msg.textContent = e.message + " — restart the companion server if this 404s"; }
      })
      .finally(() => { if (btn) btn.disabled = false; });
  }
  function restoreCaseBackup(filename) {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("diagBackupMsg");
    if (!caseId || !filename) return;
    const ts = filename.replace(/_[a-z-]+\.json$/, "").replace(/T/, " ").replace(/-/g, (m, o) => o > 10 ? ":" : m).slice(0, 19);
    if (!confirm(`Restore backup from ${ts} for case "${caseId}"?\n\nThis overwrites the live investigation state (findings, timeline, IOCs, tags, comments, …) with the snapshot. The current live state is NOT auto-saved.\n\nProceed?`)) return;
    if (msg) { msg.style.color = "#9aa4b2"; msg.textContent = "restoring…"; }
    fetch(`/cases/${encodeURIComponent(caseId)}/restore-backup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename }),
    })
      .then(async r => {
        if (!r.ok) {
          // Surface the server's `error` string rather than the raw JSON body: a restore blocked
          // by an in-flight job (409) is a routine outcome the analyst needs to be able to read.
          const body = await r.text().catch(() => String(r.status));
          let detail = body;
          try { const parsed = JSON.parse(body); if (parsed && parsed.error) detail = parsed.error; } catch {}
          throw new Error(detail);
        }
        return r.json();
      })
      .then(j => {
        if (msg) { msg.style.color = "#5ad17a"; msg.textContent = `✓ Restored ${(j.restored || []).length} file(s) — reload the page to reflect changes`; }
      })
      .catch(e => {
        if (msg) { msg.style.color = "#ff9f9f"; msg.textContent = "Restore failed: " + e.message; }
      });
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.loadCaseBackups = loadCaseBackups;
  window.restoreCaseBackup = restoreCaseBackup;
})();
