// Missed evidence review (#1540).
//
// The analyst presses one button; the server re-grades the Info-graded super-timeline rows with a
// fast decision model (Jev) and hands back a ranked reading. NOTHING IS PROMOTED AND NO CASE STATE
// CHANGES — the panel says that in its own first line rather than leaving an analyst to infer it
// from the absence of a save control, because a ranked list of "missed evidence" reads like a
// verdict unless it is told otherwise.
//
// Two things this panel owes the analyst, both of which it would be easy to get wrong:
//
//   1. THE NUMBERS ARE ALWAYS THE TRUE ONES, AND EACH REASON IS ITS OWN FACT. `matched` is how
//      many rows matched, `read` how many were actually read, `alreadyAnalyzed` how many were
//      skipped as already visible to the AI, `graded` how many were judged, `capped` says the
//      cap — and only the cap — held rows back, and `readAll` says the run ignored the cap
//      entirely. A caption that showed only the rows on screen would imply full coverage of a case
//      the model never finished reading. Truncation is stated to the ANALYST, in the panel, not
//      only to the model.
//
//   2. THE BUSY FLAG IS CLEARED IN A `finally`. A cancelled or errored panel load that leaves an
//      in-flight flag on wedges the button for the rest of the session — a bug class this codebase
//      has shipped before. The flag is cleared on every exit path AND reset when a case loads, so
//      neither a rejected fetch nor a case switch mid-run can leave the control dead. A full read
//      can be in flight for minutes, which is long enough for that bug to cost a whole session, so
//      the run is generation-stamped too: a resolution that no longer owns the flag lets go of it
//      rather than clearing a newer run's.
//
// An IIFE for the same reason as js/dashboard-sensitive-access.js: this feature owns state.
// NOT AN ES MODULE: the page and its siblings call the published names below by bare name.
(function () {
  // The model's own probability that a row is about the investigator's OWN collection tooling
  // rather than the host's activity. Detection-rule files on disk carry names like
  // `proc_access_win_pypykatz_cred_dump_lsass_access.yml`, which read as attacker tooling and are
  // not. Hidden above this by default; the analyst can show them.
  const TOOLING_CUTOFF = 0.5;
  // The grades the server may send. A class name is built from this value, so it is matched
  // against the list rather than interpolated — model output is never trusted into markup.
  const GRADES = ["Critical", "High", "Medium", "Low", "Info"];
  // Ceiling on rendered rows. The server's own cap can be thousands; painting all of them costs
  // more than it tells anyone. Whatever is held back is stated, never silently dropped.
  const MAX_SHOWN = 300;
  // HOW MANY UNREAD ROWS MAKE A FULL READ WORTH A SECOND CLICK.
  //
  // 2,000 is the server's own default cap — one press-worth of work, the amount the analyst
  // already consented to with a single click on "Review missed evidence". Below that, a full read
  // is no longer and no dearer than the run they just ran, so a confirmation would be friction
  // carrying no information. At or above it the run is more than double, can take minutes and
  // spends real money, which is exactly when starting it unprompted is the wrong behaviour.
  //
  // A run whose size is UNKNOWN — no earlier run on this case to measure — is not "small". It is
  // unknown, and it asks too; see askFullRead().
  const FULL_READ_CONFIRM_ROWS = 2000;
  // How often the elapsed-time line is repainted while a run is in flight.
  const TICK_MS = 1000;

  let currentCaseId = "";
  let loadGen = 0;
  let status = null; // { configured, reason, model } once the status probe answers
  let statusState = "idle"; // "idle" | "loading" | "ready" | "error"
  let statusError = "";
  let result = null; // the last review response for this case
  let reviewError = "";
  let busy = false;
  let hideTooling = true;
  let wired = false;
  let confirming = false; // the inline "read every row?" confirmation is on screen
  let runningAll = false; // the run in flight ignores the cap
  let runGen = 0; // whose resolution owns the busy flag
  let runStartedAt = 0;
  let tickTimer = null;

  const gradeRank = (g) => {
    const i = GRADES.indexOf(g);
    return i < 0 ? GRADES.length : i;
  };

  const gradeClass = (g) => (GRADES.indexOf(g) < 0 ? "sev-Info" : `sev-${g}`);

  const pct = (v) => (typeof v === "number" && isFinite(v) ? `${Math.round(v * 100)}%` : "—");

  const when = (ts) => (ts ? String(ts).slice(0, 19).replace("T", " ") : "—");

  function money(v) {
    if (typeof v !== "number" || !isFinite(v) || v < 0) return "";
    // Sub-cent runs are the normal case for a decision model, so a 2-decimal format would print
    // "$0.00" for every run and say nothing.
    return v >= 0.01 ? `$${v.toFixed(2)}` : `$${v.toFixed(6)}`;
  }

  const num = (v) => (typeof v === "number" && isFinite(v) ? v.toLocaleString() : "0");

  function isTooling(row) {
    return typeof row.tooling === "number" && isFinite(row.tooling) && row.tooling > TOOLING_CUTOFF;
  }

  function visibleRows() {
    const rows = result && Array.isArray(result.rows) ? result.rows : [];
    return hideTooling ? rows.filter((r) => !isTooling(r)) : rows;
  }

  /** Rows the last run matched but never reached. Zero when there is no run to compare against. */
  function unreadRows(r) {
    if (!r) return 0;
    return Math.max(0, (r.matched || 0) - (r.read || 0));
  }

  // WHAT A FULL READ WOULD COVER, FROM THE LAST RUN'S OWN NUMBERS — never from a guess.
  //
  // `matched` is how many rows a full read reads. The cost is the last run's real cost scaled by
  // rows read (cost x matched / read), because the spend is per row read, not per row matched.
  // When there is no last run, `known` is false and the panel says it does not know rather than
  // printing a number it invented. Same when the run reported no cost: `cost` stays null.
  function fullReadPlan() {
    if (!result) return { known: false, matched: 0, unread: 0, cost: null };
    const matched = result.matched || 0;
    const read = result.read || 0;
    const usage = result.usage || {};
    const spent = typeof usage.costUSD === "number" && isFinite(usage.costUSD) ? usage.costUSD : null;
    return {
      known: true,
      matched,
      unread: unreadRows(result),
      cost: spent !== null && read > 0 ? (spent * matched) / read : null,
    };
  }

  /** A real elapsed count. The server sends no progress, so no percentage is invented here. */
  function elapsedText() {
    if (!runStartedAt) return "";
    const s = Math.max(0, Math.round((Date.now() - runStartedAt) / 1000));
    return s < 60 ? `${s}s so far.` : `${Math.floor(s / 60)}m ${s % 60}s so far.`;
  }

  function startTick() {
    stopTick();
    runStartedAt = Date.now();
    if (typeof setInterval !== "function") return;
    tickTimer = setInterval(() => {
      if (busy) renderJevReview();
      else stopTick();
    }, TICK_MS);
  }

  function stopTick() {
    if (tickTimer !== null && typeof clearInterval === "function") clearInterval(tickTimer);
    tickTimer = null;
    runStartedAt = 0;
  }

  function rowHtml(row) {
    const grade = GRADES.indexOf(row.grade) < 0 ? "Info" : row.grade;
    const sub = [row.asset, row.path].filter(Boolean).map(esc).join(" — ");
    const tool = isTooling(row)
      ? `<div class="jev-tool-score">reads as our own collection tooling (${pct(row.tooling)})</div>`
      : "";
    return `<tr>
      <td><span class="jev-grade ${gradeClass(grade)}"><span class="sev-dot"></span>${esc(grade)}</span></td>
      <td class="jev-conf">${esc(pct(row.confidence))}</td>
      <td>${esc(when(row.timestamp))}</td>
      <td>${esc(row.artifactName || "—")}${tool}</td>
      <td class="jev-desc">${esc(row.description || "—")}${sub ? `<div class="jev-tool-score">${sub}</div>` : ""}</td>
    </tr>`;
  }

  function captionHtml() {
    // STATE FACTS, NAME NO CAUSE YOU CANNOT KNOW. This caption once read "the row cap stopped the
    // read" on a case where 1,344 rows matched a 2,000 cap: the shortfall was 366 rows already in
    // the forensic timeline, not the cap. The server now sends the reasons apart — `capped` is true
    // only when the cap really held rows back — and each fact gets its own clause.
    //
    // `readAll` is a third fact, not a fourth guess: the server says the run ignored the cap, and
    // the shortfall is still checked against the numbers before the panel calls it full coverage.
    const matched = result.matched || 0;
    const analyzed = result.alreadyAnalyzed || 0;
    const graded = result.graded || 0;
    const unread = unreadRows(result);
    const shown = visibleRows();
    const total = Array.isArray(result.rows) ? result.rows.length : 0;
    const hidden = total - shown.length;

    let line = `${num(graded)} of ${num(matched)} matching super-timeline row(s) were graded.`;
    if (analyzed > 0) {
      line += ` ${num(analyzed)} were already in the forensic timeline, where the AI can already see them.`;
    }
    if (result.readAll === true && result.capped !== true && unread === 0) {
      line += " This was a full read: every matching row was read, with no cap in force.";
    } else if (result.readAll === true && result.capped !== true && unread > 0) {
      // The cap was not in force and rows are still missing. The panel does not know why, so it
      // reports the shortfall and stops there.
      line +=
        ` <span class="jev-truncated">${num(unread)} matching row(s) were not read, ` +
        `so this is not full coverage of the case.</span>`;
    }
    if (result.capped === true && unread > 0) {
      line +=
        ` <span class="jev-truncated">The ${num(result.cap || 0)}-row cap stopped the read — ` +
        `${num(unread)} matching row(s) were never read, so this is not full coverage of the case.</span>`;
    }
    if (graded === 0 && analyzed > 0 && result.capped !== true) {
      line += " Nothing was left for this review to grade.";
    }

    let second = `Showing ${num(Math.min(shown.length, MAX_SHOWN))} of ${num(total)} graded row(s).`;
    if (hidden > 0) second += ` ${num(hidden)} hidden as our own collection tooling.`;
    if (shown.length > MAX_SHOWN) second += ` ${num(shown.length - MAX_SHOWN)} more are not drawn.`;
    return `<p class="jev-caption">${line}</p><p class="jev-caption">${esc(second)}</p>`;
  }

  // OFFER THE FULL READ ONLY WHEN IT WOULD ADD SOMETHING. The cap really held rows back, so there
  // are rows a full read would reach and this one did not. When nothing was capped this returns
  // nothing at all — a panel that offers the expensive action after every run is a panel whose
  // offer stops meaning anything.
  function offerHtml() {
    if (!result || result.capped !== true) return "";
    const unread = unreadRows(result);
    if (unread <= 0) return "";
    return `<p class="jev-offer"><strong>${num(unread)} matching row(s) went unread.</strong>
      Reading every row covers them. <button type="button" id="jevOfferAll">Read every row</button></p>`;
  }

  // THE CONFIRMATION, IN THE PANEL — never confirm(), alert() or any other browser modal: they
  // block the automation harness, and a native dialog cannot show the numbers this one has to.
  function confirmHtml() {
    const plan = fullReadPlan();
    let body;
    if (!plan.known) {
      body =
        "No review has run on this case yet, so this panel cannot say how many rows a full read " +
        "covers or what it would cost. That is not an estimate of zero — the figures are simply " +
        "not known until a first run reports them.";
    } else {
      const est = money(plan.cost);
      body =
        `This reads all ${num(plan.matched)} matching super-timeline row(s), ` +
        `${num(plan.unread)} of which the last run never reached. ` +
        (est
          ? `Estimated cost ${est}, worked out from the last run's own cost per row — an estimate, not a quote.`
          : "The last run reported no cost, so there is no figure to estimate from.");
    }
    return `<div class="jev-confirm" role="group" aria-label="Confirm reading every row">
      <p class="jev-confirm-head">Read every row, ignoring the cap?</p>
      <p class="jev-caption">${esc(body)}</p>
      <p class="jev-caption">It reads only. Nothing is promoted and no case data changes, however long it runs.</p>
      <p class="jev-confirm-actions">
        <button type="button" id="jevConfirmRun">Yes — read every row</button>
        <button type="button" id="jevConfirmCancel">Cancel</button>
      </p>
    </div>`;
  }

  function metaHtml() {
    const bits = [];
    if (result.model) bits.push(esc(String(result.model)));
    const usage = result.usage || {};
    const cost = money(usage.costUSD);
    if (cost) bits.push(cost);
    if (typeof usage.inputTokens === "number" || typeof usage.outputTokens === "number") {
      bits.push(`${num(usage.inputTokens)} in / ${num(usage.outputTokens)} out tokens`);
    }
    return bits.length ? `<p class="jev-meta">${bits.join(" &middot; ")}</p>` : "";
  }

  function resultHtml() {
    const shown = visibleRows().slice().sort((a, b) => gradeRank(a.grade) - gradeRank(b.grade));
    const body = shown.slice(0, MAX_SHOWN).map(rowHtml).join("");
    const table = body
      ? `<table class="jev-table"><thead><tr><th scope="col">Grade</th><th scope="col">Confidence</th><th scope="col">Time (UTC)</th><th scope="col">Artifact</th><th scope="col">What the row says</th></tr></thead><tbody>${body}</tbody></table>`
      : `<p class="jev-status">No row is left to show. ${hideTooling ? "Untick the tooling filter to see the rows the model read as our own collection tooling." : "The model graded nothing here."}</p>`;
    return captionHtml() + offerHtml() + metaHtml() + table;
  }

  function progressHtml() {
    const what = runningAll
      ? "Reading every matching super-timeline row and grading it. On a large case this takes minutes."
      : "Reading the super-timeline rows up to the cap and grading them.";
    // No percentage: the server reports no progress, and a made-up bar is the one number an
    // analyst would trust most.
    return `<p class="jev-progress">${esc(`${what} ${elapsedText()}`.trim())}</p>
      <p class="jev-progress">Nothing is written back while this runs.</p>`;
  }

  function notConfiguredHtml() {
    const reason = status && status.reason ? String(status.reason) : "Jev is not configured on this server.";
    return `<p class="jev-status">${esc(reason)}</p>
      <p class="jev-status">Set it up in <strong>Settings &rarr; AI &rarr; Missed evidence review (Jev)</strong>: turn <code>DFIR_JEV_ENABLED</code> on and choose a provider and model.</p>
      <p><button type="button" id="jevOpenSettings">Open Settings</button></p>`;
  }

  function renderJevReview() {
    const el = document.getElementById("jevReviewPanel");
    const statusEl = document.getElementById("jevReviewStatus");
    const btn = document.getElementById("jevRunBtn");
    const allBtn = document.getElementById("jevRunAllBtn");
    const chk = document.getElementById("jevHideTooling");
    if (!el) return;
    if (chk) chk.checked = hideTooling;

    const configured = statusState === "ready" && status && status.configured === true;
    // Both actions are locked while a run is in flight or a confirmation is waiting. The flag in
    // runJevReview() is the real gate; this is what the analyst can see of it.
    const locked = busy || confirming || !currentCaseId || !configured;
    if (btn) {
      btn.disabled = locked;
      btn.textContent = busy && !runningAll ? "Reviewing…" : "Review missed evidence";
      btn.title = configured
        ? "Grade the Info-graded super-timeline rows the AI never sees, up to the server's row cap. Reads only; promotes nothing."
        : "Jev is not configured — see the note below.";
    }
    if (allBtn) {
      allBtn.disabled = locked;
      allBtn.textContent = busy && runningAll ? "Reading every row…" : "Read every row";
      allBtn.title = configured
        ? "Ignore the row cap and read every matching super-timeline row. Slower and dearer — it asks first, with the numbers. Reads only; promotes nothing."
        : "Jev is not configured — see the note below.";
    }

    if (statusEl) {
      let msg = "";
      if (!currentCaseId) msg = "Connect to a case to run a review.";
      else if (statusState === "loading") msg = "Checking whether the review model is configured…";
      else if (statusState === "error") msg = `Could not check the review model (${statusError}). Nothing here says the case holds no missed evidence.`;
      else if (busy)
        msg = runningAll
          ? `Reading every matching super-timeline row and grading it. ${elapsedText()}`
          : `Reading the super-timeline rows and grading them. ${elapsedText()}`;
      else if (confirming) msg = "Waiting for you to confirm a full read.";
      else if (configured && status.model) msg = `Ready — ${status.model}.`;
      statusEl.textContent = msg;
    }

    let html = "";
    if (statusState === "loading" || !currentCaseId) html = "";
    else if (statusState === "ready" && !configured) html = notConfiguredHtml();
    else if (busy) html = progressHtml();
    else if (confirming) html = confirmHtml() + (result ? resultHtml() : "");
    else if (reviewError) html = `<p class="jev-error">${esc(reviewError)}</p>`;
    else if (result) html = resultHtml();
    else html = `<p class="jev-status">Nothing reviewed yet for this case. The review reads the Info-graded rows the forensic timeline leaves out, grades them, and ranks them — it writes nothing back.</p>`;
    el.innerHTML = html;

    const open = el.querySelector("#jevOpenSettings");
    if (open) {
      open.addEventListener("click", () => {
        if (typeof openSettingsTab === "function") openSettingsTab("ai");
        else if (typeof openSettingsModal === "function") openSettingsModal();
      });
    }
    const offer = el.querySelector("#jevOfferAll");
    if (offer) offer.addEventListener("click", askFullRead);
    const go = el.querySelector("#jevConfirmRun");
    if (go) go.addEventListener("click", () => runJevReview(true));
    const stop = el.querySelector("#jevConfirmCancel");
    if (stop) {
      stop.addEventListener("click", () => {
        confirming = false;
        renderJevReview();
      });
    }
  }

  // THE FULL READ ASKS FIRST UNLESS IT CAN SHOW THE RUN IS SMALL.
  //
  // Small is measured, never assumed: only a previous run's numbers can say how many rows are
  // still unread. With no previous run the size is unknown, which is a reason to ask, not a reason
  // to skip asking — so the confirmation goes up and says plainly that it has no figures.
  function askFullRead() {
    if (busy || !currentCaseId) return;
    const plan = fullReadPlan();
    if (plan.known && plan.unread < FULL_READ_CONFIRM_ROWS) {
      runJevReview(true);
      return;
    }
    confirming = true;
    renderJevReview();
  }

  function runJevReview(all) {
    // ONE RUN AT A TIME. Both buttons, the offer and the confirmation all land here, and an
    // uncapped read can be in flight for minutes — long enough for a second click to look like the
    // first did nothing. The flag is the lock; `disabled` is only what the analyst sees of it.
    if (busy || !currentCaseId) return;
    const caseId = currentCaseId;
    const readAll = all === true;
    const gen = ++runGen;
    busy = true;
    runningAll = readAll;
    confirming = false;
    reviewError = "";
    result = null;
    startTick();
    renderJevReview();
    fetch(`/cases/${encodeURIComponent(caseId)}/jev/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(readAll ? { all: true } : {}),
    })
      .then((r) => r.json().then((body) => ({ ok: r.ok, status: r.status, body })))
      .then((r) => {
        if (currentCaseId !== caseId || runGen !== gen) return;
        if (!r.ok) {
          reviewError = `The review did not run: ${r.body && r.body.error ? r.body.error : `HTTP ${r.status}`}`;
          return;
        }
        result = r.body && Array.isArray(r.body.rows) ? r.body : null;
        if (!result) reviewError = "The review returned nothing this panel can read.";
      })
      .catch((err) => {
        if (currentCaseId !== caseId || runGen !== gen) return;
        reviewError = `The review did not run: ${String((err && err.message) || err)}`;
      })
      .finally(() => {
        // EVERY exit path clears the flag — a rejected fetch, a 501, an abandoned case. A busy flag
        // that survives one failure wedges the button for the rest of the session.
        //
        // The generation check is not an escape from that rule, it is what keeps it true across a
        // case switch: loadJevReview() has already cleared the flag and stopped the ticker for the
        // run this resolution belongs to, and a later run may now own both. Clearing them here
        // would unlock a run that is still in flight — the same wedge, one case along.
        if (runGen !== gen) return;
        stopTick();
        busy = false;
        runningAll = false;
        renderJevReview();
      });
  }

  function loadJevReview(caseId) {
    currentCaseId = caseId;
    // A case switch is also an exit path for a run started under the previous case: the flag goes
    // off, the ticker stops and the generation moves on, so the old run's `finally` cannot touch
    // any of the three again.
    busy = false;
    runningAll = false;
    confirming = false;
    runGen++;
    stopTick();
    status = null;
    statusState = "loading";
    statusError = "";
    result = null;
    reviewError = "";
    renderJevReview();
    const gen = ++loadGen;
    return fetch(`/cases/${encodeURIComponent(caseId)}/jev/status`)
      .then((r) => r.json().then((body) => ({ ok: r.ok, code: r.status, body })))
      .then((r) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        if (!r.ok) {
          // A 501 IS an answer — "not configured" — and it belongs in the panel as the reason plus
          // the way to fix it, not as a request failure the analyst can do nothing with.
          if (r.code === 501 && r.body && r.body.error) {
            status = { configured: false, reason: String(r.body.error) };
            statusState = "ready";
            return;
          }
          throw new Error(`HTTP ${r.code}`);
        }
        status = r.body && typeof r.body === "object" ? r.body : { configured: false };
        statusState = "ready";
      })
      .catch((err) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        statusError = String((err && err.message) || err);
        statusState = "error";
      })
      .finally(() => {
        if (currentCaseId === caseId && loadGen === gen) renderJevReview();
      });
  }

  // The toolbar's way in. It OPENS the panel and never starts a review: a toolbar click that
  // silently spends money is the wrong behaviour, and the press that costs something stays inside
  // the panel where the numbers are. When Jev is unconfigured this still opens the panel, which
  // already carries the reason and the route to Settings — one explanation, in one place.
  //
  // The reveal is the page's own idiom: a view profile may have hidden the section outright, and
  // scrollIntoView() on a display:none element is a silent no-op.
  function revealJevReview() {
    const sec = document.getElementById("sec-jev-review");
    if (!sec) return;
    if (typeof markSectionRevealed === "function") markSectionRevealed("sec-jev-review");
    sec.classList.remove("collapsed");
    sec.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function initJevReview() {
    if (wired) return;
    const btn = document.getElementById("jevRunBtn");
    const chk = document.getElementById("jevHideTooling");
    if (!btn || !chk) return;
    wired = true;
    btn.addEventListener("click", () => runJevReview(false));
    const allBtn = document.getElementById("jevRunAllBtn");
    if (allBtn) allBtn.addEventListener("click", askFullRead);
    const toolbarBtn = document.getElementById("jevReviewBtn");
    if (toolbarBtn) toolbarBtn.addEventListener("click", revealJevReview);
    chk.addEventListener("change", () => {
      hideTooling = chk.checked;
      renderJevReview();
    });
    renderJevReview();
  }

  // Only the two the page and its siblings actually call: initJevReview from the inline script at
  // load, loadJevReview from the case-panel loaders. The run, the render and every piece of state
  // stay inside the closure.
  window.loadJevReview = loadJevReview;
  window.initJevReview = initJevReview;
})();
