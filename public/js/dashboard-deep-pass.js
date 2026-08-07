// Deep pass (#282) — the re-analysis sweep that re-reads evidence at a lower confidence floor.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE. Four mutable bindings: the synthesis gate read from /health,
// the lazily-fetched preview flag, a sequence guard that lets a superseded preview retire itself,
// and the in-flight POST flag.
//
// TWO OF THOSE USED TO ESCAPE, and both were closed rather than published:
//   - deepPassPreviewLoaded was read by two collapse/expand handlers deciding whether to call
//     loadDeepPassPreview(). That guard is this feature's business, so loadDeepPassPreview() is
//     idempotent now and the callers just call it. A FAILED measure still leaves the flag false,
//     so a reopen retries exactly as before.
//   - deepPassSynthesisEnabled was written from the /health response. It has a setter now, so the
//     page tells the feature rather than reaching into it.
//
// IT CALLS BACK INTO THE PAGE — loadJobs, cancelJob, applyHeavyAiJobLock, loadSynthMeta — because a
// deep pass runs as a background job and the job registry lives in the inline script. That is the
// established shape here, not a new one: js/dashboard-swimlane.js calls seven page functions and
// js/dashboard-timeline-view.js nine. All of them are called from handlers, never at load, so this
// file still loads cleanly on its own.
(function () {

  // ── Deep pass (#204) ────────────────────────────────────────────────────────
  // The batched deep pass reads EVERY graded event at or above a floor, in as many batches as it
  // takes, then folds the observations into one final synthesis that REPLACES the conclusions.
  //
  // Three things shape this surface:
  //  1. Prompt rows scale with HOSTS and the right floor is case-dependent, so there is no correct
  //     default — the analyst picks from the pre-flight table (AI-free) instead of guessing.
  //  2. A 13-batch run is roughly 650k input tokens and many minutes, so progress and cancel are
  //     load-bearing, not decoration. Both ride the existing job registry (#225) rather than a
  //     private mechanism — the run already registers a cancellable job server-side.
  //  3. batchesFailed MUST be visible. A run that lost batches read less of the case than its
  //     event count implies, and presenting that as complete coverage is the worst outcome here.
  let deepPassSynthesisEnabled = false;   // /health.synthesisEnabled — the TEXT gate, not aiEnabled
  let deepPassPreviewLoaded = false;      // the preview is fetched lazily; this is the "already have it" flag
  let deepPassPreviewSeq = 0;             // guards against an out-of-order preview from a rapid case switch
  let deepPassPosting = false;            // the POST is in flight (the job may not exist yet)

  function deepPassCaseId() { const el = document.getElementById("caseId"); return el && typeof el.value === "string" ? el.value.trim() : ""; }
  function deepPassGuidance(msg) {
    const el = document.getElementById("deepPassGuidance");
    if (!el) return;
    el.innerHTML = msg ? esc(msg) : "";
    el.style.display = msg ? "" : "none";
  }

  // Called on connect: the previous case's measurements and result must not bleed into this one.
  function resetDeepPass() {
    deepPassPreviewLoaded = false;
    deepPassPreviewSeq++;
    deepPassGuidance("");
    document.getElementById("deepPassFloors").innerHTML = "Open this section to measure the case.";
    document.getElementById("deepPassProgress").textContent = "";
    const run = document.getElementById("deepPassRun");
    if (run) run.disabled = true;
    renderDeepPassResult(loadStoredDeepPassResult(deepPassCaseId()));
    // Re-measure straight away when the analyst left the section open on the previous case.
    const sec = document.getElementById("sec-deep-pass");
    if (sec && !sec.classList.contains("collapsed")) loadDeepPassPreview();
  }

  function loadStoredDeepPassResult(cid) {
    if (!cid) return null;
    try { return JSON.parse(localStorage.getItem(deepPassResultKey(cid)) || "null"); } catch { return null; }
  }

  // AI-free and free of spend, but NOT free of CPU — it groups the whole graded timeline once per
  // floor — so it is fetched on demand (section expand / Refresh), never on every state broadcast.
  function loadDeepPassPreview(force) {
    // IDEMPOTENT, so the flag stays private. Both callers used to read deepPassPreviewLoaded to
    // decide whether to call — the one piece of this feature's state that escaped. The guard is
    // the feature's business, so it lives here. A FAILED measure leaves the flag false, so a
    // reopen still retries, exactly as before.
    // `force` is the Refresh button. Before this feature moved out, the "already loaded" test sat
    // at the two expand callers and Refresh called straight through — folding the guard in here
    // silently made the button a no-op after the first measurement, which is the one thing it
    // exists to do.
    if (deepPassPreviewLoaded && !force) return;
    const cid = deepPassCaseId();
    if (!cid) return;
    const mySeq = ++deepPassPreviewSeq;
    const host = document.getElementById("deepPassFloors");
    host.innerHTML = "measuring…";
    fetch(`/cases/${encodeURIComponent(cid)}/deep-pass/preview`)
      .then(r => r.json().then(j => ({ ok: r.ok, status: r.status, j })))
      .then(({ ok, status, j }) => {
        if (mySeq !== deepPassPreviewSeq) return;   // a newer case/refresh already superseded this
        if (!ok) {
          host.innerHTML = "";
          deepPassGuidance(status === 501
            ? "The analysis pipeline isn't configured on this server, so a deep pass can't be measured or run."
            : `Couldn't measure this case: ${j && j.error ? j.error : "unknown error"}`);
          return;
        }
        deepPassPreviewLoaded = true;
        renderDeepPassFloors(j.cap, Array.isArray(j.floors) ? j.floors : []);
      })
      .catch(e => { if (mySeq === deepPassPreviewSeq) { host.innerHTML = ""; deepPassGuidance("Couldn't measure this case: " + e.message); } });
  }

  // One row per floor. Batches is the number the analyst is really choosing on — it is what the
  // run costs in calls, wall-clock and the server-side ceiling that may refuse it.
  function renderDeepPassFloors(cap, floors) {
    const host = document.getElementById("deepPassFloors");
    if (!host) return;
    if (!floors.length) { host.innerHTML = "No graded events in scope — nothing for a deep pass to read."; return; }
    const rows = floors.map(f => {
      const empty = !f.events;
      return `<tr data-dp-row="${esc(f.floor)}">`
        + `<td><label><input type="radio" name="dpFloor" value="${esc(f.floor)}"${empty ? " disabled" : ""}>`
        + `<span class="sev-${esc(f.floor)}">${esc(f.floor)}+</span></label></td>`
        + `<td>${Number(f.events).toLocaleString()}</td>`
        + `<td>${Number(f.rows).toLocaleString()}</td>`
        + `<td>${Number(f.batches).toLocaleString()}</td>`
        + `<td>~${Number(f.estimatedInputTokens).toLocaleString()}</td></tr>`;
    }).join("");
    host.innerHTML = `<table class="dp-table"><thead><tr>`
      + `<th title="Read this severity and everything above it">Floor</th>`
      + `<th title="Graded events at or above this floor (Info is never read)">Events</th>`
      + `<th title="Prompt rows after detection-burst grouping — what the model actually sees">Rows</th>`
      + `<th title="AI calls the run would make, at ${Number(cap).toLocaleString()} rows per batch">Batches</th>`
      + `<th title="Estimated input tokens across all batches — the run's rough cost">Est. input</th>`
      + `</tr></thead><tbody>${rows}</tbody></table>`
      + `<div class="dp-note">Info events are never read: they are excluded from AI prompts entirely.</div>`;
    host.querySelectorAll('input[name="dpFloor"]').forEach(el => el.addEventListener("change", () => {
      host.querySelectorAll("tr[data-dp-row]").forEach(tr => tr.classList.toggle("dp-picked", tr.dataset.dpRow === el.value));
      applyDeepPassGate();
    }));
    applyDeepPassGate();
  }

  function selectedDeepPassFloor() {
    const el = document.querySelector('input[name="dpFloor"]:checked');
    return el ? el.value : "";
  }

  // The Run button is only live when a floor is picked AND a synthesis provider exists AND no
  // heavy AI job is already running for this case (see applyHeavyAiJobLock).
  function applyDeepPassGate() {
    const run = document.getElementById("deepPassRun");
    if (!run) return;
    const floor = selectedDeepPassFloor();
    if (!deepPassSynthesisEnabled) {
      run.disabled = true;
      run.title = "No synthesis provider configured — set an AI provider in Settings before running a deep pass.";
      return;
    }
    if (deepPassBusy()) { run.disabled = true; run.title = "A heavy AI job is already running for this case."; return; }
    run.disabled = !floor;
    run.title = floor ? `Run the deep pass at ${floor}+` : "Pick a severity floor above first.";
  }

  // True while THIS case has a running deep pass — either the POST is still in flight (before the
  // job shows up) or the registry lists one.
  function deepPassJob() {
    // Asked of the jobs feature rather than reaching into its cache (#415).
    return typeof runningJob === "function" ? runningJob("deep-pass") : undefined;
  }
  function deepPassBusy() { return deepPassPosting || !!deepPassJob(); }

  function runDeepPass() {
    const cid = deepPassCaseId();
    const floor = selectedDeepPassFloor();
    // No floor → no request. The server refuses an unrecognised floor rather than reading
    // everything, and the UI must not paper over that with a default of its own.
    if (!cid || !floor) { deepPassGuidance("Pick a severity floor from the table first — no floor is right for every case."); return; }
    deepPassGuidance("");
    deepPassPosting = true;
    applyHeavyAiJobLock();
    document.getElementById("deepPassProgress").textContent = `starting deep pass (${floor}+)…`;
    document.getElementById("deepPassResult").innerHTML = "";
    fetch(`/cases/${encodeURIComponent(cid)}/deep-pass`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ minSeverity: floor }),
    })
      .then(r => r.json().then(j => ({ r, j })))
      .then(({ r, j }) => {
        if (r.ok) {
          storeDeepPassResult(cid, j);
          renderDeepPassResult(j);
          // The final synthesis rewrote the conclusions — pull them in case the WS push was missed.
          fetch(`/cases/${encodeURIComponent(cid)}/state`).then(x => x.json()).then(render).catch(() => {});
          loadSynthMeta(cid);
          return;
        }
        // 400 = over the batch ceiling (its message already names a floor that would fit);
        // 423 = the case is closed or archived. Both are analyst-correctable, so they are
        // guidance, not a failure — the run never started and nothing is wrong with the case.
        if (r.status === 400 || r.status === 423) { deepPassGuidance(j.error || "That run was refused."); return; }
        if (r.status === 501) { deepPassGuidance("No synthesis provider is configured — a deep pass needs one."); return; }
        document.getElementById("deepPassResult").innerHTML =
          `<div class="dp-result dp-partial"><span class="dp-partial-hd">Deep pass failed</span> — ${esc(j && j.error ? j.error : "unknown error")}. Nothing was written to the case.</div>`;
      })
      .catch(e => deepPassGuidance("Deep pass request failed: " + e.message))
      .finally(() => {
        deepPassPosting = false;
        document.getElementById("deepPassProgress").textContent = "";
        loadJobs();          // settle the badge + re-enable the controls
        applyHeavyAiJobLock();
      });
  }

  function storeDeepPassResult(cid, r) {
    // The summary lives only in the HTTP response body; persisting it per case is what keeps
    // batchesFailed readable after a reload instead of dying with the request.
    try { localStorage.setItem(deepPassResultKey(cid), JSON.stringify({ ...r, at: new Date().toISOString() })); } catch {}
  }

  function cancelDeepPass() {
    const job = deepPassJob();
    if (!job) return;
    document.getElementById("deepPassProgress").textContent = "cancelling…";
    cancelJob(job.id, document.getElementById("deepPassCancel"));
  }

  function renderDeepPassResult(r) {
    const host = document.getElementById("deepPassResult");
    if (!host) return;
    if (!r || typeof r !== "object") { host.innerHTML = ""; return; }
    const when = r.at ? ` <span data-safe-style="color:var(--text-dim)">(${esc(r.at)})</span>` : "";
    // A cancelled run persisted NOTHING — the case is exactly as it was. Saying "read N events"
    // without that would imply conclusions changed.
    if (r.aborted) {
      host.innerHTML = `<div class="dp-result">Last deep pass (${esc(r.floor)}+) was <b>cancelled</b> after ${Number(r.batches || 0).toLocaleString()} planned batch(es) — nothing was written to the case.${when}</div>`;
      return;
    }
    const partial = Number(r.batchesFailed) > 0;
    const head = partial
      ? `<span class="dp-partial-hd">⚠ Partial coverage — ${Number(r.batchesFailed).toLocaleString()} of ${Number(r.batches).toLocaleString()} batch(es) failed</span><br>`
        + `This run read LESS of the case than the numbers below suggest; the failed batches contributed no observations. Re-run to cover them.<br>`
      : "";
    host.innerHTML = `<div class="dp-result${partial ? " dp-partial" : ""}">${head}`
      + `Floor <b>${esc(r.floor)}+</b> · read <b>${Number(r.events || 0).toLocaleString()}</b> event(s) `
      + `as <b>${Number(r.rows || 0).toLocaleString()}</b> prompt row(s) in <b>${Number(r.batches || 0).toLocaleString()}</b> batch(es) · `
      + `<b>${Number(r.observations || 0).toLocaleString()}</b> observation(s) folded into the synthesis.${when}</div>`;
  }

  window.runDeepPass = runDeepPass;
  window.cancelDeepPass = cancelDeepPass;
  window.resetDeepPass = resetDeepPass;
  // Its own five controls, which had been left under the "Background jobs (#225)" banner — the
  // run/cancel pair, refresh, the section-expand measure and the toolbar entry point. They read
  // their handlers at LOAD, so with this module extracted a 404 threw there before the facade could
  // report anything. The run/cancel guard is kept as it was: a dead pair says so out loud.
  function initDeepPass() {
    if (typeof runDeepPass === "function" && typeof cancelDeepPass === "function") {
      document.getElementById("deepPassRun").addEventListener("click", runDeepPass);
      document.getElementById("deepPassCancel").addEventListener("click", cancelDeepPass);
    } else dfirFeatureUnavailable("Deep pass");
    document.getElementById("deepPassRefresh").addEventListener("click", (e) => { e.stopPropagation(); loadDeepPassPreview(true); });
    // Measure on expand (the h2 click toggles `collapsed` in its own handler — read it after).
    document.querySelector("#sec-deep-pass h2").addEventListener("click", () => {
      setTimeout(() => {
        const sec = document.getElementById("sec-deep-pass");
        if (sec && !sec.classList.contains("collapsed")) loadDeepPassPreview();
      }, 0);
    });
    // Toolbar entry point: reveal the section (it may be hidden by the active view), open it, and
    // scroll to it — the analyst's route in when the panel isn't already on screen.
    document.getElementById("deepPassBtn").addEventListener("click", () => {
      const sec = document.getElementById("sec-deep-pass");
      if (!sec) return;
      sec.style.display = "";
      sec.classList.remove("collapsed");
      loadDeepPassPreview();
      sec.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  window.initDeepPass = initDeepPass;
  window.applyDeepPassGate = applyDeepPassGate;
  window.loadDeepPassPreview = loadDeepPassPreview;
  window.deepPassGuidance = deepPassGuidance;
  window.deepPassBusy = deepPassBusy;
  window.deepPassJob = deepPassJob;
  // The page owns /health, so it pushes the gate in rather than this file polling for it.
  window.setDeepPassSynthesisEnabled = (on) => { deepPassSynthesisEnabled = !!on; };
})();
