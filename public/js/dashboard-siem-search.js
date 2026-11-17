// Run a CQL hunt on CrowdStrike Next-Gen SIEM (#2666).
//
// A CQL hunt card (dashboard-main-source.js) gets a "Run in Falcon" button when the server has the
// SIEM API client set up (GET /cases/:id/crowdstrike/siem). Run opens a confirm step INSIDE the card:
// the exact query that will run, the time range (prefilled from the server's default range), the caps
// and the repository. Confirm posts it (POST …/crowdstrike/siem/search), which starts a job; the card
// then follows that job (GET /api/jobs/:id) until it ends and shows its outcome sentence. The rows are
// imported as evidence by the server — nothing here touches the timeline.
// Everything the server or the model sent is rendered through esc()/escAttr().
(function () {
  "use strict";

  const POLL_MS = 3000;
  let siem = null; // the last GET answer for siemCase
  let siemCase = "";

  const caseIdOf = () => {
    const el = document.getElementById("caseId");
    return el ? el.value.trim() : "";
  };

  /** Load the case's SIEM search settings; re-render the fleet language cards when it changes. */
  function loadSiemSearch() {
    const caseId = caseIdOf();
    if (caseId !== siemCase) {
      siem = null;
      siemCase = caseId;
    }
    if (!caseId) return Promise.resolve();
    return fetch(`/cases/${encodeURIComponent(caseId)}/crowdstrike/siem`)
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null)
      .then((j) => {
        if (caseIdOf() !== caseId) return;
        const was = !!(siem && siem.configured);
        siem = j;
        const now = !!(siem && siem.configured);
        const el = document.getElementById("veloHuntSuggest");
        if (was !== now && el && typeof renderLanguageHunts === "function") renderLanguageHunts(el);
      });
  }

  const runnable = (hunt) => !!(siem && siem.configured && hunt && hunt.language === "cql");

  /** The Run button for a CQL card, or "" (not CQL, or the search is not set up). */
  function siemRunButtonHtml(hunt) {
    if (!runnable(hunt)) return "";
    return (
      `<button type="button" class="msh-siem-run" title="Run this query on CrowdStrike Next-Gen SIEM and import the rows as evidence">` +
      `Run in Falcon</button>`
    );
  }

  /** The badge text a CQL card shows: runnable here when the search is set up. */
  const siemBadge = (hunt) => (runnable(hunt) ? "runnable" : "");

  const toLocal = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 16);
  };
  const fromLocal = (v) => (v ? new Date(`${v}:00.000Z`).toISOString() : "");
  const minutes = (ms) => Math.round((Number(ms) || 0) / 60000);

  function confirmHtml(query) {
    const r = siem.defaultRange || {};
    return (
      `<div class="siem-confirm" role="group" aria-label="Confirm the CrowdStrike Next-Gen SIEM search">` +
      `<div class="siem-confirm-head">Run this query on CrowdStrike Next-Gen SIEM</div>` +
      `<pre class="siem-query">${esc(query)}</pre>` +
      `<div class="siem-range">` +
      `<label>From (UTC) <input type="datetime-local" class="siem-start" value="${escAttr(toLocal(r.start))}" /></label> ` +
      `<label>To (UTC) <input type="datetime-local" class="siem-end" value="${escAttr(toLocal(r.end))}" /></label>` +
      `</div>` +
      `<div class="siem-caps">Repository ${esc(siem.repository)} · at most ${esc(String(siem.maxWindowDays))} days, ` +
      `${esc(Number(siem.maxRows).toLocaleString())} rows and ${esc(String(minutes(siem.timeoutMs)))} minutes per search. ` +
      `The search runs in your Next-Gen SIEM and counts against its query use. A <code>table()</code> returns at most 200 rows unless the query sets <code>limit=</code>.</div>` +
      `<div class="vhs-actions"><button type="button" class="siem-go">Run search</button>` +
      `<button type="button" class="siem-cancel">Cancel</button></div>` +
      `<div class="siem-status" role="status" aria-live="polite"></div>` +
      `</div>`
    );
  }

  function follow(jobId, statusEl, btn) {
    const tick = () =>
      fetch(`/api/jobs/${encodeURIComponent(jobId)}`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null)
        .then((job) => {
          if (!statusEl.isConnected) return; // the card was re-rendered: the Jobs panel still has it
          if (!job) {
            statusEl.textContent = "Search started — follow it in the Jobs panel.";
            return;
          }
          if (job.status === "succeeded") {
            statusEl.textContent = job.detail || "Search finished.";
            btn.disabled = false;
            return;
          }
          if (job.status === "failed" || job.status === "cancelled" || job.status === "interrupted") {
            statusEl.textContent = (job.failure && job.failure.message) || `Search ${job.status}.`;
            btn.disabled = false;
            return;
          }
          statusEl.textContent = job.status === "queued" ? "Waiting for the case…" : job.detail || "Searching…";
          setTimeout(tick, POLL_MS);
        });
    tick();
  }

  function openConfirm(card, btn) {
    const old = card.querySelector(".siem-confirm");
    if (old) return old.querySelector(".siem-go").focus();
    const q = card.querySelector(".msh-query");
    const query = q ? q.value : "";
    if (!query.trim()) return;
    card.insertAdjacentHTML("beforeend", confirmHtml(query));
    const box = card.querySelector(".siem-confirm");
    const status = box.querySelector(".siem-status");
    box.querySelector(".siem-cancel").onclick = () => box.remove();
    const go = box.querySelector(".siem-go");
    go.onclick = () => {
      const caseId = caseIdOf();
      if (!caseId) return;
      go.disabled = true;
      btn.disabled = true;
      status.textContent = "Starting…";
      const title = (card.querySelector(".vhs-title") || {}).textContent || "CQL hunt";
      fetch(`/cases/${encodeURIComponent(caseId)}/crowdstrike/siem/search`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          query, // exactly what the confirm step shows
          start: fromLocal(box.querySelector(".siem-start").value),
          end: fromLocal(box.querySelector(".siem-end").value),
          title,
        }),
      })
        .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
        .catch(() => ({ ok: false, j: { error: "could not reach the server" } }))
        .then(({ ok, j }) => {
          if (!ok) {
            status.textContent = (j && j.error) || "the search was refused";
            go.disabled = false;
            btn.disabled = false;
            return;
          }
          follow(j.jobId, status, btn);
        });
    };
    go.focus();
  }

  /** Wire every Run button inside `root` (called wherever the language cards are wired). */
  function wireSiemRun(root) {
    root.querySelectorAll(".msh-siem-run").forEach((b) => {
      b.onclick = (e) => {
        e.stopPropagation();
        const card = b.closest(".msh-card");
        if (card) openConfirm(card, b);
      };
    });
  }

  window.loadSiemSearch = loadSiemSearch;
  window.siemRunButtonHtml = siemRunButtonHtml;
  window.siemBadge = siemBadge;
  window.wireSiemRun = wireSiemRun;
})();
