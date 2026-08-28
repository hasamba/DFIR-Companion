// Background jobs (#225) — the jobs badge, its menu, and the live event/IOC counters —
// extracted from dashboard.html (issue #415, tier 3). The last banner holding feature code.
//
// It took three commits to get here, and none of them were about this feature:
//   - esc() and escAttr() were declared under this banner with 125 and 66 call sites. Page
//     vocabulary; moved to sit with SEV.
//   - the deep-pass panel's five controls were wired here, so the initializer range was two
//     features' load-time work interleaved.
//   - three guard stanzas from earlier extractions sit inside the line range and stay put.
//
// What is left has one escape: _jobsCache, read by js/dashboard-deep-pass.js to answer 'is a
// deep pass running'. It asks runningJob(kind) now — a question, not the array, so nothing
// outside can mutate the cache the badge renders from.
(function () {
  "use strict";

  // clicking it opens a popover to view recent jobs and cancel a long/stuck one. Fed by GET
  // /api/jobs and refreshed on the job_changed WS event.
  let _jobsCache = [];
  // WHICH CASE _jobsCache DESCRIBES. A job id only means anything inside its own case, and every
  // Cancel button in the popover POSTs one — so a cache drawn under the wrong case offers to kill
  // work in a case the analyst has already left. Nothing needed this while a failed read emptied
  // the cache; now that a failed read KEEPS it (see loadJobs), the cache outlives a case switch and
  // has to say whose it is.
  let _jobsCacheCaseId = "";
  let _jobsMenuShape = "";
  let _jobsLoadPromise = null;
  let _jobsLoadCaseId = "";
  const JOB_UI_REFRESH_MS = 1000;
  const JOBS_MENU_ROWS = 12; // rows the popover renders; active jobs are never crowded out of them
  let _jobUiRefreshTimer = null;
  let _jobUiRefreshRunning = false;
  let _jobUiRefreshQueued = false;
  let _jobUiRefreshCaseId = "";
  // Resolve the connected case id from the input element. NOTE: a bare `caseId` at this outer
  // script scope resolves to the #caseId DOM ELEMENT (browsers expose id'd elements as window
  // globals), NOT the string — so we must read `.value` here rather than trust any argument.
  function jobsCaseId() {
    const el = document.getElementById("caseId");
    return el && typeof el.value === "string" ? el.value.trim() : "";
  }
  // The cache, but only when it belongs to the case on screen. THE ONE READ EVERY CONSUMER USES —
  // the badge, the popover, the deep-pass lock and runningJob() — because a stale-case answer is
  // wrong for all four in the same way, and one of them can cancel the wrong job.
  function jobsForCurrentCase() {
    return _jobsCacheCaseId && _jobsCacheCaseId === jobsCaseId() ? _jobsCache : [];
  }
  function loadJobs() {
    const cid = jobsCaseId();
    if (!cid) return Promise.resolve();
    if (_jobsLoadPromise && _jobsLoadCaseId === cid) return _jobsLoadPromise;
    _jobsLoadCaseId = cid;
    // THROW, don't substitute an empty list. A non-ok answer — an expired session's 401, a 500, a
    // request the server dropped while it was overloaded — used to be mapped to `{ jobs: [] }`,
    // which emptied the cache and hid the badge: the case was drawn as idle at the exact moment the
    // analyst needed to see (and cancel) the run the header pill was claiming. Reported as "the AI
    // chip still shows running, no jobs chip at all". A failed read means we learned nothing, so
    // fall through to the catch and keep the last known answer — the same rule refreshAiState
    // follows in js/dashboard-ai-status.js. Only a real answer may empty the badge.
    //
    // "The last known answer" is scoped to the case it was read for. jobsForCurrentCase() enforces
    // that on every read; the render in the catch is what repaints a badge still showing the case
    // the analyst just left.
    const request = fetch(`/api/jobs?caseId=${encodeURIComponent(cid)}`)
      .then((r) => {
        if (!r.ok) throw new Error("jobs HTTP " + r.status);
        return r.json();
      })
      .then((d) => {
        if (cid !== jobsCaseId()) return;
        _jobsCache = Array.isArray(d.jobs) ? d.jobs : [];
        _jobsCacheCaseId = cid;
        renderJobs();
      })
      .catch(() => renderJobs())
      .finally(() => {
        if (_jobsLoadPromise === request) {
          _jobsLoadPromise = null;
          _jobsLoadCaseId = "";
        }
      });
    _jobsLoadPromise = request;
    return request;
  }
  function scheduleJobUiRefresh(caseId) {
    const cid = caseId || jobsCaseId();
    if (!cid) return;
    _jobUiRefreshCaseId = cid;
    _jobUiRefreshQueued = true;
    if (_jobUiRefreshTimer || _jobUiRefreshRunning) return;
    _jobUiRefreshTimer = setTimeout(runJobUiRefresh, JOB_UI_REFRESH_MS);
  }
  async function runJobUiRefresh() {
    _jobUiRefreshTimer = null;
    const cid = _jobUiRefreshCaseId;
    if (!cid || cid !== jobsCaseId()) {
      _jobUiRefreshQueued = false;
      return;
    }
    _jobUiRefreshQueued = false;
    _jobUiRefreshRunning = true;
    try {
      await Promise.all([loadJobs(), loadCockpit(cid)]);
    } finally {
      _jobUiRefreshRunning = false;
      if (_jobUiRefreshQueued && _jobUiRefreshCaseId === jobsCaseId()) {
        _jobUiRefreshTimer = setTimeout(runJobUiRefresh, JOB_UI_REFRESH_MS);
      }
    }
  }
  function rebuildJobsMenu(menu, views) {
    menu.innerHTML =
      `<h3>Background jobs</h3>` +
      (views.length
        ? views.map(jobRowHtml).join("")
        : `<div class="jobs-empty">No jobs yet.</div>`);
    menu
      .querySelectorAll(".job-cancel")
      .forEach((b) =>
        b.addEventListener("click", () => cancelJob(b.dataset.job, b)),
      );
    menu
      .querySelectorAll(".job-resume")
      .forEach((b) =>
        b.addEventListener("click", () => resumeJob(b.dataset.job, b)),
      );
  }
  function renderJobs() {
    const badge = document.getElementById("jobsBadge");
    const menu = document.getElementById("jobsMenu");
    if (!badge || !menu) return;
    const cached = jobsForCurrentCase();
    const running = cached.filter(
      (j) => j.status === "running" || j.status === "queued",
    );
    const attention = cached.filter(
      (j) =>
        j.resumable &&
        (j.status === "interrupted" ||
          (j.status === "failed" && j.failure && j.failure.retryable)),
    );
    const menuOpen = menu.style.display !== "none";
    let badgeText = "";
    if (running.length) {
      badge.style.display = "";
      badgeText = `⚙ ${running.length} job${running.length > 1 ? "s" : ""}`;
    } else if (attention.length) {
      badge.style.display = "";
      badgeText = `⚠ ${attention.length} job${attention.length > 1 ? "s" : ""} need attention`;
    } else if (menuOpen && cached.length) {
      badge.style.display = "";
      badgeText = "⚙ jobs";
    } // keep it clickable while the popover is open so it can't vanish under the cursor
    else {
      badge.style.display = "none";
      if (menuOpen && !cached.length) menu.style.display = "none";
    }
    if (badgeText && badge.textContent !== badgeText)
      badge.textContent = badgeText;
    // EVERY job the badge counts, then the newest finished rows to fill the remaining budget.
    // Taking the newest 12 rows outright let a burst of finished rows fill all 12 and push the
    // work the badge was counting off the end — "⚙ 3 jobs" over a list with no queued row in it.
    // Order is preserved (newest first): this only chooses WHICH rows fit, never reorders them.
    const shown = new Set(running.concat(attention).map((j) => j.id));
    for (const j of cached) {
      if (shown.size >= JOBS_MENU_ROWS) break;
      shown.add(j.id);
    }
    const views = cached.filter((j) => shown.has(j.id)).map(jobMenuView);
    const shape = JSON.stringify(
      views.map((v) => [v.job.id, v.cancel, v.resume]),
    );
    if (shape !== _jobsMenuShape) rebuildJobsMenu(menu, views);
    else
      menu
        .querySelectorAll(".job-row")
        .forEach((row, i) => updateJobRow(row, views[i]));
    _jobsMenuShape = shape;
    applyHeavyAiJobLock(); // deep pass ↔ synthesis mutual lock + the deep-pass progress line (#204)
  }
  function cancelJob(id, btn) {
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Cancelling…";
    }
    fetch(`/api/jobs/${encodeURIComponent(id)}/cancel`, { method: "POST" })
      .then((r) => {
        if (!r.ok && r.status === 404)
          document.getElementById("status").textContent =
            "Job endpoint missing — restart the companion server.";
      })
      .catch(() => {})
      .finally(() => loadJobs());
  }
  function resumeJob(id, btn) {
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Resuming…";
    }
    fetch(`/api/jobs/${encodeURIComponent(id)}/resume`, { method: "POST" })
      .then(async (r) => {
        const body = await r.json().catch(() => ({}));
        if (!r.ok)
          document.getElementById("status").textContent =
            body.error || "Job could not resume.";
      })
      .catch(() => {})
      .finally(() => loadJobs());
  }

  // Deep pass (#282) moved to js/dashboard-deep-pass.js (#415 tier 3). Its guarded wiring
  // block below is what reports it missing.

  // The job registry's `exclusive` flag only supersedes jobs of the SAME kind, and the deep pass's
  // own closing synthesize() is not registered as a "synthesis" job — so a Re-synthesize started
  // mid-run would race the deep pass's write and one of the two results would be silently lost.
  // Nothing server-side prevents that, so the buttons lock each other out here.
  function applyHeavyAiJobLock() {
    const dp = deepPassBusy();
    const synth = jobsForCurrentCase().some(
      (j) =>
        j.kind === "synthesis" &&
        (j.status === "running" || j.status === "queued"),
    );
    const synthBtn = document.getElementById("synthesize");
    const soBtn = document.getElementById("secondOpinion");
    for (const btn of [synthBtn, soBtn]) {
      if (!btn) continue;
      btn.disabled = dp;
      if (dp)
        btn.title =
          "A deep pass is running — it ends in a synthesis of its own, so this would overwrite it.";
      else btn.removeAttribute("title");
    }
    const cancel = document.getElementById("deepPassCancel");
    if (cancel) cancel.style.display = deepPassJob() ? "" : "none";
    const prog = document.getElementById("deepPassProgress");
    const job = deepPassJob();
    if (prog && job) {
      const p = job.progress
        ? ` (${job.progress.done}/${job.progress.total})`
        : "";
      prog.textContent = (job.detail || "running") + p;
    }
    if (synth && !dp) {
      const run = document.getElementById("deepPassRun");
      if (run) {
        run.disabled = true;
        run.title = "A synthesis is running — wait for it to finish.";
        return;
      }
    }
    applyDeepPassGate();
  }

  // GUARDED AS A BLOCK, and these two names are the sentinel. Both are passed as REFERENCES, so a
  // ReferenceError fires while the argument is evaluated — before addEventListener is entered —
  // and takes the rest of this script with it. Same shape as the KEV block (#475).
  //
  // Deliberately NOT stubbed by js/dashboard-facade.js: a stub would make this test pass, wire a
  // no-op to the button, and silence the chip. A name that a guard tests is evidence, and the
  // facade may only ever replace work.
  // The deep-pass panel's own controls moved with the feature to js/dashboard-deep-pass.js

  // Poll the capture count (new screenshots arrive via the extension, not the WS) every 5s while
  // the tab is VISIBLE; pause entirely when it's hidden — background tabs were just emitting an
  // idle GET/min (browser-throttled) for no benefit. Resumes (and refreshes once) on re-focus.
  function startCount() {
    if (!countTimer && countUpdate && !document.hidden)
      countTimer = setInterval(countUpdate, 5000);
  }
  function stopCount() {
    if (countTimer) {
      clearInterval(countTimer);
      countTimer = null;
    }
  }
  // Retire the poller for good, as opposed to stopCount()'s "pause while hidden".
  //
  // CLEARING countUpdate IS THE WHOLE POINT. stopCount() only drops the timer, and countUpdate
  // still closes over the case id it was built for — so the visibilitychange handler below, which
  // calls countUpdate() and startCount() on every return to the tab, would resurrect a 5-second
  // poll against a case the analyst has cancelled. Used by the case-load cancel path, which has no
  // replacement case to re-point the poller at.
  function retireCount() {
    stopCount();
    countUpdate = null;
  }

  function pollCount(caseId) {
    stopCount();
    countUpdate = () =>
      fetch(`/cases/${caseId}/captures/count`)
        .then((r) => r.json())
        .then(
          (d) =>
            (document.getElementById("captureCountNum").textContent = d.count),
        )
        .catch(() => {});
    countUpdate();
    startCount();
  }

  // Inline IOC quick-actions (#221) live in public/js/dashboard-ioc-quick-actions.js.

  // What dashboard-deep-pass.js asks: the running/queued job of a kind, if any.
  function runningJob(kind) {
    return jobsForCurrentCase().find(
      (j) =>
        j.kind === kind && (j.status === "running" || j.status === "queued"),
    );
  }

  // The badge and the outside-click close. Both bind to markup.
  function initJobs() {
    // The visibility pause. It ran at MODULE scope in the inline script, where that was harmless;
    // here it is load-time work like any other listener. Third time in #415 I have split the main
    // range and not the tail I appended to it — the lifecycle gate caught all three.
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stopCount();
      else {
        if (countUpdate) countUpdate();
        startCount();
      }
    });

    document.getElementById("jobsBadge").addEventListener("click", () => {
      const menu = document.getElementById("jobsMenu");
      const show = menu.style.display === "none";
      menu.style.display = show ? "" : "none";
      if (show) loadJobs();
    });
    document.addEventListener("click", (e) => {
      const menu = document.getElementById("jobsMenu");
      if (!menu || menu.style.display === "none") return;
      if (!menu.contains(e.target) && e.target.id !== "jobsBadge")
        menu.style.display = "none";
    });
  }

  window.initJobs = initJobs;
  window.runningJob = runningJob;
  window.applyHeavyAiJobLock = applyHeavyAiJobLock;
  window.cancelJob = cancelJob;
  window.loadJobs = loadJobs;
  window.pollCount = pollCount;
  window.retireCount = retireCount;
  window.scheduleJobUiRefresh = scheduleJobUiRefresh;
})();
