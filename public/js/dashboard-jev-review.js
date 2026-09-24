// Missed evidence review (#1540), and promoting what it finds (#1568).
//
// The analyst presses one button; the server re-grades the Info-graded super-timeline rows with a
// fast decision model (Jev) and hands back a ranked reading. THE REVIEW ITSELF STILL WRITES
// NOTHING; promoting does. Ticking rows and pressing "Promote selected" writes them into the
// FORENSIC timeline carrying THE MODEL'S GRADE AS THEIR SEVERITY — and severity is what decides
// whether the analysis AI ever reads a row. A model's judgement entering the evidence record, not
// a bookmark, so it asks first, in the panel, with the count.
//
// SELECT-ALL IS SCOPED TO WHAT IS DRAWN, never to everything graded. The tooling filter, the grade
// floor, the confidence floor and the MAX_SHOWN draw cap each narrow the table, and a row any of
// them held back is one nobody saw — so the post body is rebuilt from the drawn rows at press time.
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
  // HOW LONG THE CAPPED REVIEW IS WAITED FOR BEFORE THE PANEL GIVES UP (#1552).
  //
  // A request that never settles — a laptop that slept, a proxy that dropped the socket — would
  // otherwise hold the panel on "Reviewing…" until a case switch. One cap-worth of rows finishes
  // far inside this, so 15 minutes is generous. The FULL READ gets no limit: a large case can
  // legitimately run longer, and giving up in the browser does not stop the run on the server.
  // For that one, and for the analyst who will not wait, there is the "Stop waiting" button.
  const CAPPED_TIMEOUT_MS = 15 * 60 * 1000;
  // What happens on the server after the browser stops waiting. The server refuses a second review
  // of a case while one is still running (#1551), so a press that comes too soon gets a refusal —
  // this says why before it happens.
  const STILL_RUNNING = "may still be running on the server; a new review of this case is refused until it ends.";
  const STOP_MESSAGES = {
    cancel: `You stopped waiting for this review. It ${STILL_RUNNING}`,
    timeout: `No answer after ${Math.round(CAPPED_TIMEOUT_MS / 60000)} minutes. The review ${STILL_RUNNING}`,
  };

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
  let activeRun = null; // { controller, timer } for the review in flight; null when none is
  let reviewNote = ""; // why the panel stopped waiting — the analyst's own press, or the time limit
  let minGrade = ""; // the write half (#1568). "" = any grade; else the LOWEST grade the table draws
  let minConfidence = 0; // 0..1, the model's own confidence floor
  let picked = new Set(); // row ids the analyst has ticked
  let sentIds = new Set(); // row ids this panel has already posted to promote
  let promoting = false; // a promote is in flight — the lock, not the `disabled` attribute
  let promoteGen = 0; // whose resolution owns the promoting flag
  let confirmingPromote = false; // the inline "promote these rows?" confirmation is on screen
  let promoteError = "";
  let promoteResult = null; // { promoted, skipped, reasons } from the last promote

  // Pure formatting lives in js/dashboard-jev-review-format.js (#1552 split). Resolved at CALL
  // time, never at load: this module must still load, and report itself, if that one did not.
  const grades = () => jevGrades();
  const gradeRank = (g) => jevGradeRank(g);
  const gradeClass = (g) => jevGradeClass(g);
  const pct = (v) => jevPct(v);
  const when = (ts) => jevWhen(ts);
  const money = (v) => jevMoney(v);
  const num = (v) => jevNum(v);
  const unreadRows = (r) => jevUnreadRows(r);
  const fullReadPlan = () => jevFullReadPlan(result);

  function isTooling(row) {
    return typeof row.tooling === "number" && isFinite(row.tooling) && row.tooling > TOOLING_CUTOFF;
  }

  function visibleRows() {
    const rows = result && Array.isArray(result.rows) ? result.rows : [];
    return hideTooling ? rows.filter((r) => !isTooling(r)) : rows;
  }

  /** Rows left after the grade floor and the confidence floor, on top of the tooling filter. */
  function filteredRows() {
    const floor = minGrade && grades().indexOf(minGrade) >= 0 ? gradeRank(minGrade) : grades().length;
    return visibleRows().filter((r) => {
      if (gradeRank(r.grade) > floor) return false;
      const c = typeof r.confidence === "number" && isFinite(r.confidence) ? r.confidence : 0;
      return c >= minConfidence;
    });
  }

  // EXACTLY THE ROWS ON SCREEN. Every count, the select-all and the POST body derive from it.
  function drawnRows() {
    return filteredRows()
      .slice()
      .sort((a, b) => gradeRank(a.grade) - gradeRank(b.grade))
      .slice(0, MAX_SHOWN);
  }

  /** Drawn rows this panel has not already sent. Sent rows are in the timeline; they are done. */
  function selectableRows() {
    return drawnRows().filter((r) => !sentIds.has(r.id));
  }

  // What a press would write. The intersection is taken HERE, at press time, not kept tidy in
  // `picked`: a pruned-on-every-change tick set is one forgotten prune from posting a row nobody saw.
  function selectedRows() {
    return selectableRows().filter((r) => picked.has(r.id));
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

  // The tick, or the badge that replaces it. A native checkbox with a screen-reader label, and
  // `escAttr` on the id and label — attacker-influenced text going into attribute position.
  function pickHtml(row, grade) {
    if (sentIds.has(row.id)) {
      return `<span class="jev-sent" title="This panel sent this row to the forensic timeline. It is not promotable again from here.">Sent</span>`;
    }
    const label = `Promote the ${grade} row: ${String(row.description || "").slice(0, 80)}`;
    return `<input type="checkbox" class="jev-pick" data-id="${escAttr(row.id)}"${picked.has(row.id) ? " checked" : ""} aria-label="${escAttr(label)}" />`;
  }

  function rowHtml(row) {
    const grade = grades().indexOf(row.grade) < 0 ? "Info" : row.grade;
    const sub = [row.asset, row.path].filter(Boolean).map(esc).join(" — ");
    const tool = isTooling(row)
      ? `<div class="jev-tool-score">reads as our own collection tooling (${pct(row.tooling)})</div>`
      : "";
    return `<tr${sentIds.has(row.id) ? ' class="jev-row-sent"' : ""}>
      <td class="jev-pick-cell">${pickHtml(row, grade)}</td>
      <td><span class="jev-grade ${gradeClass(grade)}"><span class="sev-dot"></span>${esc(grade)}</span></td>
      <td class="jev-conf">${esc(pct(row.confidence))}</td>
      <td>${esc(when(row.timestamp))}</td>
      <td>${esc(row.artifactName || "—")}${tool}</td>
      <td class="jev-desc">${esc(row.description || "—")}${sub ? `<div class="jev-tool-score">${sub}</div>` : ""}</td>
    </tr>`;
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

  // The selection bar. THE COUNT IN THE SELECT-ALL LABEL IS THE SCOPE: a bare "Select all" reads as
  // "everything graded", which it must never mean, so the number counts rows DRAWN BELOW it.
  function selectionHtml() {
    const selectable = selectableRows().length;
    const chosen = selectedRows().length;
    const off = (cond) => (cond || promoting ? " disabled" : "");
    const allTip = `Ticks only the rows drawn in the table below. The tooling filter, the grade filter, the confidence filter and the ${MAX_SHOWN}-row draw cap all narrow it — a row you cannot see is never ticked.`;
    const goTip = "Writes the ticked rows into the forensic timeline with the model's grade as their severity. It asks first.";
    const note =
      (chosen === 0
        ? "Tick a row to promote it. Promoting writes to the case."
        : `${num(chosen)} of the ${num(selectable)} row(s) shown are ticked.`) +
      (sentIds.size > 0 ? ` ${num(sentIds.size)} already sent from this panel.` : "");
    return `<div class="jev-select" role="group" aria-label="Promote reviewed rows">
      <button type="button" id="jevSelectAll"${off(selectable === 0)} title="${escAttr(allTip)}">Select all ${num(selectable)} shown</button>
      <button type="button" id="jevClearSel"${off(chosen === 0)}>Clear selection</button>
      <button type="button" id="jevPromoteBtn" class="jev-promote"${off(chosen === 0)} title="${escAttr(goTip)}">${promoting ? "Promoting…" : `Promote ${num(chosen)} selected row${chosen === 1 ? "" : "s"}`}</button>
      <span class="jev-select-note">${esc(note)}</span>
    </div>`;
  }

  // THE PROMOTE CONFIRMATION, IN THE PANEL — never confirm(): a browser modal blocks the automation
  // harness and cannot carry the sentence that matters, which is whose judgement is being written.
  function promoteConfirmHtml() {
    const n = selectedRows().length;
    const model = result && result.model ? String(result.model) : "this model";
    const stake =
      `Each row enters the case record with the grade ${model} gave it as its severity. Severity is ` +
      "what decides whether the analysis AI ever reads a row, so this writes a model's judgement into " +
      "the evidence. It is a reading, not a finding — check the rows before you press. This panel " +
      "cannot undo it.";
    const skips =
      "None of these rows was in the forensic timeline when the review ran — the review only grades " +
      "rows the case has not analysed. The server checks again and reports anything it skips." +
      (sentIds.size > 0
        ? ` ${num(sentIds.size)} row(s) this panel already sent are not in this count and are not sent twice.`
        : "");
    return `<div class="jev-confirm" role="group" aria-label="Confirm promoting rows">
      <p class="jev-confirm-head">Promote ${num(n)} row(s) into the forensic timeline?</p>
      <p class="jev-caption">${esc(stake)}</p>
      <p class="jev-caption">${esc(skips)}</p>
      <p class="jev-confirm-actions">
        <button type="button" id="jevPromoteGo">Yes — promote ${num(n)} row(s)</button>
        <button type="button" id="jevPromoteCancel">Cancel</button>
      </p>
    </div>`;
  }

  // What the last promote did. AN INFO ROW IS PROMOTED AND STILL UNREAD BY THE AI — it lands in the
  // timeline for the analyst, but Info gets no seat in synthesis — so that is said out loud. And
  // `reasons` is NOTES, not skips: the Info remark rides in it, so "skipped" would be the wrong head.
  function promoteResultHtml() {
    if (promoteError) return `<p class="jev-error">${esc(promoteError)}</p>`;
    if (!promoteResult) return "";
    const promoted = typeof promoteResult.promoted === "number" ? promoteResult.promoted : 0;
    const skipped = typeof promoteResult.skipped === "number" ? promoteResult.skipped : 0;
    const line =
      (promoted > 0
        ? `${num(promoted)} row(s) are now in the forensic timeline, each with the grade this review gave it.`
        : "No row was written into the forensic timeline.") + (skipped > 0 ? ` ${num(skipped)} were skipped.` : "");
    const atInfo = (result && Array.isArray(result.rows) ? result.rows : []).filter((r) => sentIds.has(r.id) && r.grade === "Info").length;
    const caveat =
      atInfo > 0 && promoted > 0
        ? `<p class="jev-caption jev-truncated">${esc(`${num(atInfo)} of the row(s) you sent were graded Info. An Info row is in the timeline for you to read, but the analysis AI never sees it — only rows above Info reach synthesis. Promoting it changed what you can see, not what the AI reads.`)}</p>`
        : "";
    const reasons = Array.isArray(promoteResult.reasons) ? promoteResult.reasons : [];
    const notes = reasons.length
      ? `<p class="jev-caption">The server also reported:</p><ul class="jev-reasons">${reasons.slice(0, 20).map((r) => `<li>${esc(String(r))}</li>`).join("")}</ul>`
      : "";
    return `<p class="jev-promoted">${esc(line)}</p>${caveat}${notes}`;
  }

  function resultHtml() {
    const body = drawnRows().map(rowHtml).join("");
    const table = body
      ? `<table class="jev-table"><thead><tr><th scope="col"><span class="visually-hidden">Promote</span></th><th scope="col">Grade</th><th scope="col">Confidence</th><th scope="col">Time (UTC)</th><th scope="col">Artifact</th><th scope="col">What the row says</th></tr></thead><tbody>${body}</tbody></table>`
      : `<p class="jev-status">No row is left to show. ${hideTooling ? "Untick the tooling filter, or lower the grade and confidence filters, to see more." : "Lower the grade and confidence filters, or the model graded nothing here."}</p>`;
    const counts = { shown: visibleRows().length, kept: filteredRows().length, drawn: drawnRows().length };
    return jevCaptionHtml(result, counts) + offerHtml() + metaHtml() + promoteResultHtml() + (body ? selectionHtml() : "") + table;
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
    const cancelBtn = document.getElementById("jevCancelBtn");
    if (!el) return;
    if (chk) chk.checked = hideTooling;
    // The one control that must stay live while a run is in flight, and exists only then.
    if (cancelBtn) cancelBtn.hidden = !busy;

    const configured = statusState === "ready" && status && status.configured === true;
    // Every action is locked while a run or a promote is in flight, or a confirmation is waiting.
    // The flags in runJevReview() and promoteSelected() are the real gates; this is what the
    // analyst can see of them.
    const locked = busy || promoting || confirming || confirmingPromote || !currentCaseId || !configured;
    if (btn) {
      btn.disabled = locked;
      btn.textContent = busy && !runningAll ? "Reviewing…" : "Review missed evidence";
      btn.title = configured
        ? "Grade the Info-graded super-timeline rows the AI never sees, up to the server's row cap. Reads only; nothing is promoted until you tick rows and press Promote."
        : "Jev is not configured — see the note below.";
    }
    if (allBtn) {
      allBtn.disabled = locked;
      allBtn.textContent = busy && runningAll ? "Reading every row…" : "Read every row";
      allBtn.title = configured
        ? "Ignore the row cap and read every matching super-timeline row. Slower and dearer — it asks first, with the numbers. Reads only; nothing is promoted until you tick rows and press Promote."
        : "Jev is not configured — see the note below.";
    }
    // The filter controls follow the same lock, and always show the state the render used.
    const gradeSel = document.getElementById("jevGradeFilter");
    const confSel = document.getElementById("jevMinConfidence");
    const confOut = document.getElementById("jevMinConfidenceOut");
    const confPct = Math.round(minConfidence * 100);
    if (gradeSel) gradeSel.value = minGrade;
    if (confSel) confSel.value = String(confPct);
    if (confOut) confOut.textContent = confPct > 0 ? `${confPct}% and above` : "any";
    [gradeSel, confSel, chk].forEach((c) => c && (c.disabled = locked));

    if (statusEl) {
      let msg = "";
      if (!currentCaseId) msg = "Connect to a case to run a review.";
      else if (statusState === "loading") msg = "Checking whether the review model is configured…";
      else if (statusState === "error") msg = `Could not check the review model (${statusError}). Nothing here says the case holds no missed evidence.`;
      else if (busy)
        msg = runningAll
          ? `Reading every matching super-timeline row and grading it. ${elapsedText()}`
          : `Reading the super-timeline rows and grading them. ${elapsedText()}`;
      else if (promoting) msg = "Writing the selected rows into the forensic timeline…";
      else if (confirming) msg = "Waiting for you to confirm a full read.";
      else if (confirmingPromote) msg = "Waiting for you to confirm promoting the selected rows.";
      else if (configured && status.model) msg = `Ready — ${status.model}.`;
      statusEl.textContent = msg;
    }

    let html = "";
    if (statusState === "loading" || !currentCaseId) html = "";
    else if (statusState === "ready" && !configured) html = notConfiguredHtml();
    else if (busy) html = progressHtml();
    else if (confirming) html = jevFullReadConfirmHtml(fullReadPlan()) + (result ? resultHtml() : "");
    else if (confirmingPromote) html = promoteConfirmHtml() + (result ? resultHtml() : "");
    else if (reviewError) html = `<p class="jev-error">${esc(reviewError)}</p>`;
    else if (reviewNote) html = `<p class="jev-status">${esc(reviewNote)}</p>`;
    else if (result) html = resultHtml();
    else html = `<p class="jev-status">Nothing reviewed yet for this case. The review reads the Info-graded rows the forensic timeline leaves out, grades them, and ranks them. Nothing enters the case until you tick rows and press Promote.</p>`;
    el.innerHTML = html;

    // innerHTML is replaced on every paint, so every control below is a NEW element to find and
    // wire again. One helper, so a missing control is a no-op rather than a throw.
    const on = (sel, type, fn) => {
      const node = el.querySelector(sel);
      if (node) node.addEventListener(type, fn);
    };
    on("#jevOpenSettings", "click", () => {
      if (typeof openSettingsTab === "function") openSettingsTab("ai");
      else if (typeof openSettingsModal === "function") openSettingsModal();
    });
    on("#jevOfferAll", "click", askFullRead);
    on("#jevConfirmRun", "click", () => runJevReview(true));
    on("#jevConfirmCancel", "click", () => {
      confirming = false;
      renderJevReview();
    });
    wireSelection(on);
  }

  /** The selection and promote controls, re-wired after each paint. */
  function wireSelection(on) {
    // ONE delegated listener on the table, not one per row. It reads `data-id` off the tick itself,
    // so a target that is not a tick is ignored.
    on(".jev-table", "change", (e) => {
      const t = e && e.target;
      const id = t && t.dataset ? t.dataset.id : "";
      if (!id) return;
      if (t.checked) picked.add(id);
      else picked.delete(id);
      renderJevReview();
    });
    // SELECT ALL MEANS WHAT IS DRAWN. selectableRows() is the list the table just painted, so a row
    // any filter or the draw cap held back is not in it and cannot be ticked by this press.
    on("#jevSelectAll", "click", () => {
      selectableRows().forEach((r) => picked.add(r.id));
      renderJevReview();
    });
    on("#jevClearSel", "click", () => {
      picked = new Set();
      renderJevReview();
    });
    on("#jevPromoteBtn", "click", () => {
      if (promoting || selectedRows().length === 0) return;
      confirmingPromote = true;
      promoteError = "";
      promoteResult = null;
      renderJevReview();
    });
    on("#jevPromoteGo", "click", promoteSelected);
    on("#jevPromoteCancel", "click", () => {
      confirmingPromote = false;
      renderJevReview();
    });
  }

  // Write the ticked rows into the forensic timeline. The body comes from selectedRows() — the drawn
  // rows, ticked — never from `picked`, so the rule this panel promises holds where it matters. ONLY
  // THE IDS TRAVEL: the grade is the severity being written, so the server takes it, with the
  // confidence and the model, from its own record of the review (#1578). ONE AT A TIME.
  function promoteSelected() {
    if (promoting || !currentCaseId) return;
    const rows = selectedRows();
    // AN EMPTY SELECTION DOES NOT POST. The server answers 400 to one, and a request that can only
    // fail is a request not worth the analyst's confusion.
    if (rows.length === 0) {
      confirmingPromote = false;
      promoteError = "Nothing is selected, so nothing was sent.";
      renderJevReview();
      return;
    }
    const caseId = currentCaseId;
    const gen = ++promoteGen;
    const ids = rows.map((r) => r.id);
    const body = { rows: ids.map((id) => ({ id })) };
    promoting = true;
    confirmingPromote = false;
    promoteError = "";
    promoteResult = null;
    renderJevReview();
    fetch(`/cases/${encodeURIComponent(caseId)}/jev/promote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.json().then((b) => ({ ok: r.ok, status: r.status, body: b })))
      .then((r) => {
        if (currentCaseId !== caseId || promoteGen !== gen) return;
        if (!r.ok) {
          promoteError = `Nothing was promoted: ${r.body && r.body.error ? r.body.error : `HTTP ${r.status}`}`;
          return;
        }
        promoteResult = r.body && typeof r.body === "object" ? r.body : { promoted: 0, skipped: 0, reasons: [] };
        // THE ROWS STOP BEING PROMOTABLE AND STAY ON SCREEN. They are in the timeline now, so
        // offering them again would only produce a second write or a skip; removing them would leave
        // the analyst unable to see what they just did. Each keeps its place with a "Sent" badge.
        ids.forEach((id) => {
          sentIds.add(id);
          picked.delete(id);
        });
      })
      .catch((err) => {
        if (currentCaseId !== caseId || promoteGen !== gen) return;
        promoteError = `Nothing was promoted: ${String((err && err.message) || err)}`;
      })
      .finally(() => {
        // The generation check keeps the rule true across a case switch. No refetch of case state —
        // the server broadcasts it over the page's WebSocket.
        if (promoteGen !== gen) return;
        promoting = false;
        renderJevReview();
      });
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
    reviewNote = "";
    result = null;
    // A NEW READING IS A NEW SET OF ROWS: a tick kept from the old one could ride into the new post
    // body on a row nobody saw. The sent set goes with it.
    resetSelection();
    // Each run owns its controller, so "Stop waiting", the time limit and a case switch abort THIS
    // request and no other. Only the capped review gets the time limit — see CAPPED_TIMEOUT_MS.
    const run = {
      controller: typeof AbortController === "function" ? new AbortController() : null,
      timer: null,
    };
    activeRun = run;
    if (!readAll && typeof setTimeout === "function") {
      run.timer = setTimeout(() => {
        if (runGen === gen) stopWaiting("timeout");
      }, CAPPED_TIMEOUT_MS);
    }
    startTick();
    renderJevReview();
    fetch(`/cases/${encodeURIComponent(caseId)}/jev/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(readAll ? { all: true } : {}),
      signal: run.controller ? run.controller.signal : undefined,
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
        // An abort this panel made — "Stop waiting", the time limit, a case switch — has already
        // moved the generation on and said its own piece, so it stops at this check and is never
        // reported as a network failure. What reaches the line below is an ordinary one.
        if (currentCaseId !== caseId || runGen !== gen) return;
        reviewError = `The review did not run: ${String((err && err.message) || err)}`;
      })
      .finally(() => {
        // The timer belongs to this run whoever owns the flag now: a limit left armed after the
        // answer came would fire into a later run.
        clearRunTimer(run);
        // EVERY exit path clears the flag — a rejected fetch, a 501, an abandoned case. A busy flag
        // that survives one failure wedges the button for the rest of the session.
        //
        // The generation check is not an escape from that rule, it is what keeps it true across a
        // case switch: loadJevReview() has already cleared the flag and stopped the ticker for the
        // run this resolution belongs to, and a later run may now own both. Clearing them here
        // would unlock a run that is still in flight — the same wedge, one case along.
        if (runGen !== gen) return;
        activeRun = null;
        stopTick();
        busy = false;
        runningAll = false;
        renderJevReview();
      });
  }

  function clearRunTimer(run) {
    if (run && run.timer !== null && typeof clearTimeout === "function") clearTimeout(run.timer);
    if (run) run.timer = null;
  }

  // Abort the request in flight and forget it. The generation moves on FIRST, so the rejection the
  // abort causes — or a late answer, if the abort does not take — finds the run no longer owns the
  // panel and paints nothing.
  function abortRun() {
    const run = activeRun;
    activeRun = null;
    runGen++;
    if (!run) return;
    clearRunTimer(run);
    try {
      if (run.controller) run.controller.abort();
    } catch {
      // Nothing to recover: the generation already moved on, so the request can no longer paint.
    }
  }

  // STOP WAITING (#1552): the analyst's press ("cancel") or the capped review's time limit
  // ("timeout"). The panel lets go HERE rather than in the fetch's `finally`, so it is free again
  // even if the abort never reaches the request. It says the run may go on — the browser stopped
  // listening; the server did not stop working.
  function stopWaiting(kind) {
    if (!busy || !activeRun) return;
    abortRun();
    stopTick();
    busy = false;
    runningAll = false;
    reviewNote = STOP_MESSAGES[kind] || STOP_MESSAGES.cancel;
    renderJevReview();
    // The pressed button is hidden now; focus goes to the one that starts the next review.
    const next = kind === "cancel" ? document.getElementById("jevRunBtn") : null;
    if (next && typeof next.focus === "function") next.focus();
  }

  // Every tick, "Sent" badge and promote outcome belongs to ONE reading.
  function resetSelection() {
    picked = new Set();
    sentIds = new Set();
    promoteError = "";
    promoteResult = null;
  }

  function loadJevReview(caseId) {
    currentCaseId = caseId;
    // A case switch is also an exit path for a run started under the previous case: the flag goes
    // off, the ticker stops and the generation moves on, so the old run's `finally` cannot touch
    // any of the three again. The old request is aborted too (#1552): nobody is waiting for it now.
    busy = false;
    runningAll = false;
    confirming = false;
    promoting = false;
    confirmingPromote = false;
    abortRun();
    promoteGen++;
    stopTick();
    status = null;
    statusState = "loading";
    statusError = "";
    result = null;
    reviewError = "";
    reviewNote = "";
    resetSelection();
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
    const cancelBtn = document.getElementById("jevCancelBtn");
    if (cancelBtn) cancelBtn.addEventListener("click", () => stopWaiting("cancel"));
    const toolbarBtn = document.getElementById("jevReviewBtn");
    if (toolbarBtn) toolbarBtn.addEventListener("click", revealJevReview);
    chk.addEventListener("change", () => {
      hideTooling = chk.checked;
      renderJevReview();
    });
    // The two filters. Native <select> and <input type="range">: tabbable, keyboard-operable, and
    // they pick up the page's own :focus-visible ring (public/css/a11y.css).
    const gradeSel = document.getElementById("jevGradeFilter");
    if (gradeSel)
      gradeSel.addEventListener("change", () => {
        minGrade = grades().indexOf(gradeSel.value) >= 0 ? gradeSel.value : "";
        renderJevReview();
      });
    const confSel = document.getElementById("jevMinConfidence");
    if (confSel)
      confSel.addEventListener("input", () => {
        const v = Number(confSel.value);
        minConfidence = isFinite(v) ? Math.min(100, Math.max(0, v)) / 100 : 0;
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
