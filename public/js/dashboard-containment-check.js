// Per-finding containment check (#1925). The analyst presses a chip on a finding card; the server
// asks Jev eleven narrow questions about that finding's cited forensic-timeline events and turns the
// answers into suggested containment steps by a fixed rule. The analyst ticks the steps worth doing
// and adds them to the Playbook, where each task carries what it was based on.
//
// ADVICE ONLY. Nothing here runs a step. The panel says so in its footer.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the per-finding check results, the Jev status, and the set of
// steps the Playbook already holds. Results live in memory only and are cleared on a case switch —
// finding ids like "f1" recur across cases.
//
// NO INITIALIZER. The chip and the panel are built by the card renderer; the delegated listeners
// are bound once, from the case load, never from a render (a function a render loop reaches must not
// be able to commit).
(function () {
  const IN_PROGRESS_CAVEAT = "still in progress at the end of the collected evidence — not a live status";
  const RERUN_MESSAGE = "The check result expired or the finding changed — run the check again.";
  const NOT_CONFIGURED = "Jev is not configured. Set it up in Settings → AI.";
  // findingId → { busy, error, result, ticked:Set, added:Set, adding, message, resultAt }
  let ccByFinding = new Map();
  let ccActiveCase = "";
  let ccCaseGen = 0;
  let ccConfigured = false;
  // "<findingId>\u0000<stepId>" for every Playbook task a containment check created. Null until the
  // Playbook has loaded once; until then the server's inPlaybook flag on each step is the answer.
  let ccPlaybookKeys = null;
  // Monotonic counter: a Playbook sync newer than a check result overrides that result's flags.
  let ccClock = 0;
  let ccSyncAt = 0;
  let ccBound = false;

  const ccKey = (fid, stepId) => `${fid}\u0000${stepId}`;

  function ccRerender() {
    if (typeof render !== "function" || typeof DfirState === "undefined" || !DfirState) return;
    if (DfirState.lastState()) render(DfirState.lastState());
  }

  function loadContainmentCheck(caseId) {
    ccBindOnce();
    ccActiveCase = String(caseId || "");
    ccCaseGen += 1;
    const gen = ccCaseGen;
    ccByFinding = new Map();
    ccPlaybookKeys = null;
    ccSyncAt = 0;
    ccConfigured = false;
    if (!ccActiveCase) return Promise.resolve();
    return fetch(`/cases/${encodeURIComponent(ccActiveCase)}/jev/status`)
      .then((r) => (r.ok ? r.json() : { configured: false }))
      .then((s) => {
        if (gen !== ccCaseGen) return;
        ccConfigured = !!(s && s.configured === true);
        if (ccConfigured) ccRerender();
      })
      .catch(() => {});
  }

  function ccRecord(fid) {
    const key = String(fid);
    let rec = ccByFinding.get(key);
    if (!rec) {
      rec = { busy: false, error: "", result: null, ticked: new Set(), added: new Set(), adding: false, message: "", resultAt: 0 };
      ccByFinding.set(key, rec);
    }
    return rec;
  }

  function ccPct(n) {
    if (typeof n !== "number" || !isFinite(n)) return "";
    return `${Math.round(n <= 1 ? n * 100 : n)}%`;
  }

  // One answer as text. A yes/no answer is a probability; a choice answer is the option plus how
  // sure Jev was of it. The stored shape puts the option in `verdict` and the confidence in `value`;
  // a string `value` (the option itself) is read too.
  function ccAnswerValue(a) {
    if (!a || typeof a !== "object") return "";
    if (a.kind === "choice") {
      const numeric = typeof a.value === "number";
      const choice = numeric ? a.verdict : a.value;
      const conf = numeric ? a.value : a.confidence;
      const p = ccPct(conf);
      return String(choice == null ? "" : choice).replace(/_/g, " ") + (p ? ` (confidence ${p})` : "");
    }
    const p = ccPct(a.value);
    return [a.verdict ? String(a.verdict) : "", p ? `${p} likely` : ""].filter(Boolean).join(" · ");
  }

  // A shield, drawn like the other finding-action icons (16-unit box, currentColor stroke).
  const ICON_CCHECK =
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M8 1.8 3 3.7v3.9c0 3 2.1 5.4 5 6.6 2.9-1.2 5-3.6 5-6.6V3.7L8 1.8z"/><path d="M5.8 8.1 7.3 9.6l3-3.1"/></svg>';

  function ccDate(v) {
    return String(v == null ? "" : v).slice(0, 16).replace("T", " ");
  }

  function ccStepInPlaybook(fid, rec, step) {
    if (rec.added.has(String(step.id))) return true;
    if (ccPlaybookKeys && ccSyncAt > rec.resultAt) return ccPlaybookKeys.has(ccKey(fid, step.id));
    return !!step.inPlaybook;
  }

  function containmentCheckChip(fid) {
    if (!ccConfigured) return "";
    const rec = ccByFinding.get(String(fid));
    const busy = !!(rec && rec.busy);
    const tip = busy
      ? "Checking… — Jev is answering the containment questions for this finding"
      : "Containment check — ask Jev narrow questions about this finding and suggest containment steps (advice only)";
    return (
      `<button type="button" class="ccheck-btn" data-ccheck-run="${escAttr(String(fid))}"` +
      ` aria-label="Containment check" title="${escAttr(tip)}"${busy ? ' disabled aria-busy="true"' : ""}>` +
      `${ICON_CCHECK}</button>`
    );
  }

  function ccAnswersHtml(answers) {
    return (
      `<ul class="ccheck-answers">` +
      answers
        .map((a) => {
          const caveat = a && a.id === "in_progress" ? ` <span class="ccheck-caveat">${esc(IN_PROGRESS_CAVEAT)}</span>` : "";
          return (
            `<li><span class="ccheck-q">${esc((a && (a.label || a.id)) || "")}</span>: ` +
            `<span class="ccheck-v">${esc(ccAnswerValue(a))}</span>${caveat}</li>`
          );
        })
        .join("") +
      `</ul>`
    );
  }

  function ccCoverageHtml(cov) {
    if (!cov || typeof cov !== "object") return "";
    let text = `${Number(cov.sent) || 0} of ${Number(cov.cited) || 0} cited events sent`;
    if (Number(cov.notInTimeline) > 0) text += `, ${Number(cov.notInTimeline)} not in the forensic timeline`;
    if (cov.truncated) text += " + truncated to fit the request";
    return `<div class="ccheck-coverage">${esc(text)}</div>`;
  }

  function ccStepsHtml(fid, rec, steps) {
    if (!steps.length) return `<div class="ccheck-none">No containment step suggested.</div>`;
    return (
      `<ul class="ccheck-steps">` +
      steps
        .map((s) => {
          const inPb = ccStepInPlaybook(fid, rec, s);
          const ticked = !inPb && rec.ticked.has(String(s.id));
          const because = Array.isArray(s.basisLabels) && s.basisLabels.length
            ? ` <span class="ccheck-because">because: ${esc(s.basisLabels.join(", "))}</span>`
            : "";
          return (
            `<li><label class="ccheck-step">` +
            `<input type="checkbox" class="ccheck-step-cb" data-ccheck-fid="${escAttr(String(fid))}" data-ccheck-step="${escAttr(String(s.id))}"` +
            `${ticked ? " checked" : ""}${inPb || rec.adding ? " disabled" : ""} /> ` +
            `<span class="pb-pri pb-pri-${escAttr(String(s.priority || ""))}">${esc(s.priority)}</span> ` +
            `<span class="ccheck-step-title">${esc(s.title)}</span>${because}` +
            (inPb ? ` <span class="ccheck-inpb">in Playbook${s.taskShortId ? ` (${esc(s.taskShortId)})` : ""}</span>` : "") +
            `</label></li>`
          );
        })
        .join("") +
      `</ul>`
    );
  }

  // Pure: reads module state, writes nothing.
  function containmentCheckPanel(fid) {
    const rec = ccByFinding.get(String(fid));
    if (!rec || (!rec.busy && !rec.error && !rec.result)) return "";
    const res = rec.result;
    let body = "";
    if (rec.busy) body += `<div class="ccheck-busy">Running the containment check…</div>`;
    if (rec.error) body += `<div class="ccheck-error">${esc(rec.error)}</div>`;
    if (res) {
      const answers = Array.isArray(res.answers) ? res.answers : [];
      const steps = Array.isArray(res.steps) ? res.steps : [];
      const anyTick = steps.some((s) => rec.ticked.has(String(s.id)) && !ccStepInPlaybook(fid, rec, s));
      body +=
        `<div class="ccheck-meta">Jev ${esc(res.model)} · ${esc(ccDate(res.checkedAt))}</div>` +
        ccAnswersHtml(answers) +
        ccCoverageHtml(res.coverage) +
        `<div class="ccheck-sub">Suggested steps</div>` +
        ccStepsHtml(fid, rec, steps) +
        `<button type="button" class="ccheck-add" data-ccheck-add="${escAttr(String(fid))}"${anyTick && !rec.adding ? "" : " disabled"}>` +
        `${rec.adding ? "Adding…" : "Add to Playbook"}</button>`;
    }
    if (rec.message) body += `<div class="ccheck-msg">${esc(rec.message)}</div>`;
    return (
      `<div class="ccheck-panel" data-ccheck-panel="${escAttr(String(fid))}">` +
      `<div class="ccheck-head"><strong>Containment check</strong>` +
      `<button type="button" class="ccheck-close" data-ccheck-close="${escAttr(String(fid))}" title="Close">✕</button></div>` +
      body +
      `<div class="ccheck-foot">Advice only — nothing is run.</div>` +
      `</div>`
    );
  }

  function ccReadJson(r) {
    return r
      .json()
      .catch(() => ({}))
      .then((data) => ({ ok: r.ok, status: r.status, data: data || {} }));
  }

  function runContainmentCheck(fid) {
    const caseId = ccActiveCase;
    const key = String(fid || "");
    if (!caseId || !key) return Promise.resolve();
    const rec = ccRecord(key);
    if (rec.busy) return Promise.resolve();
    const gen = ccCaseGen;
    rec.busy = true;
    rec.error = "";
    rec.message = "";
    ccRerender();
    const stale = () => gen !== ccCaseGen || ccByFinding.get(key) !== rec;
    return fetch(`/cases/${encodeURIComponent(caseId)}/findings/${encodeURIComponent(key)}/containment-check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then(ccReadJson)
      .then(({ ok, status, data }) => {
        if (stale()) return;
        if (!ok) {
          rec.error = status === 501
            ? `${NOT_CONFIGURED}${data.error ? ` (${data.error})` : ""}`
            : `Containment check failed: ${data.error || `server returned ${status}`}`;
          return;
        }
        rec.result = data;
        rec.ticked = new Set();
        rec.added = new Set();
        ccClock += 1;
        rec.resultAt = ccClock;
      })
      .catch((err) => {
        if (!stale()) rec.error = `Containment check failed: ${(err && err.message) || "network error"}`;
      })
      .then(() => {
        if (stale()) return;
        rec.busy = false;
        ccRerender();
      });
  }

  function addContainmentSteps(fid) {
    const caseId = ccActiveCase;
    const key = String(fid || "");
    const rec = ccByFinding.get(key);
    if (!caseId || !rec || !rec.result || rec.adding) return Promise.resolve();
    const steps = (Array.isArray(rec.result.steps) ? rec.result.steps : [])
      .filter((s) => rec.ticked.has(String(s.id)) && !ccStepInPlaybook(key, rec, s))
      .map((s) => String(s.id));
    if (!steps.length) return Promise.resolve();
    const gen = ccCaseGen;
    const stale = () => gen !== ccCaseGen || ccByFinding.get(key) !== rec;
    rec.adding = true;
    rec.message = "";
    ccRerender();
    return fetch(`/cases/${encodeURIComponent(caseId)}/findings/${encodeURIComponent(key)}/containment-check/playbook`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ checkId: rec.result.checkId, steps }),
    })
      .then(ccReadJson)
      .then(({ ok, status, data }) => {
        if (stale()) return;
        if (!ok) {
          rec.message = status === 409 && data.rerun ? RERUN_MESSAGE : `Not added: ${data.error || `server returned ${status}`}`;
          return;
        }
        const added = Array.isArray(data.added) ? data.added : [];
        added.forEach((t) => {
          const sid = t && t.containmentCheck && t.containmentCheck.stepId;
          if (sid) rec.added.add(String(sid));
        });
        (Array.isArray(data.alreadyInPlaybook) ? data.alreadyInPlaybook : []).forEach((sid) => rec.added.add(String(sid)));
        rec.ticked = new Set();
        rec.message = `${added.length} step${added.length === 1 ? "" : "s"} added to the Playbook.`;
        if (typeof loadPlaybook === "function") loadPlaybook(caseId);
      })
      .catch((err) => {
        if (!stale()) rec.message = `Not added: ${(err && err.message) || "network error"}`;
      })
      .then(() => {
        if (stale()) return;
        rec.adding = false;
        ccRerender();
      });
  }

  // The Playbook is the truth for "in Playbook": a deleted task frees its step, and a task another
  // tab added marks it. Called by the Playbook panel each time its task list loads.
  function containmentSyncPlaybook(tasks) {
    const keys = new Set();
    (Array.isArray(tasks) ? tasks : []).forEach((t) => {
      const c = t && t.containmentCheck;
      if (c && c.stepId && (t.relatedFindingId || c.findingId))
        keys.add(ccKey(String(t.relatedFindingId || c.findingId), String(c.stepId)));
    });
    ccPlaybookKeys = keys;
    ccClock += 1;
    ccSyncAt = ccClock;
    let any = false;
    ccByFinding.forEach((rec) => {
      rec.added = new Set();
      if (rec.result) any = true;
    });
    if (any) ccRerender();
  }

  // The compact "why this task exists" line on a Playbook task a containment check created.
  function containmentAttributionHtml(task) {
    const c = task && task.containmentCheck;
    if (!c || typeof c !== "object") return "";
    const basis = Array.isArray(c.basis) ? c.basis.map(String) : [];
    const answers = (Array.isArray(c.answers) ? c.answers : []).filter((a) => a && typeof a === "object");
    const used = basis.length ? answers.filter((a) => basis.includes(String(a.id))) : answers;
    const parts = used.map(
      (a) => `${esc(a.label || a.id)}: ${esc(ccAnswerValue(a))}`,
    );
    const caveat = c.inProgressCaveat
      ? ` · <span class="ccheck-caveat">${esc(typeof c.inProgressCaveat === "string" ? c.inProgressCaveat : IN_PROGRESS_CAVEAT)}</span>`
      : "";
    return (
      `<div class="ccheck-attr">Containment check · ${esc(c.model)} · ${esc(ccDate(c.checkedAt))}` +
      (parts.length ? ` · based on ${parts.join("; ")}` : "") +
      caveat +
      `</div>`
    );
  }

  function ccBindOnce() {
    if (ccBound) return;
    ccBound = true;
    document.addEventListener("click", (e) => {
      const t = e && e.target;
      if (!t || !t.closest) return;
      const run = t.closest("[data-ccheck-run]");
      if (run) return void runContainmentCheck(run.getAttribute("data-ccheck-run"));
      const add = t.closest("[data-ccheck-add]");
      if (add) return void addContainmentSteps(add.getAttribute("data-ccheck-add"));
      const close = t.closest("[data-ccheck-close]");
      if (close) {
        const rec = ccByFinding.get(String(close.getAttribute("data-ccheck-close")));
        if (rec && !rec.busy && !rec.adding) {
          ccByFinding.delete(String(close.getAttribute("data-ccheck-close")));
          ccRerender();
        }
      }
    });
    document.addEventListener("change", (e) => {
      const cb = e && e.target && e.target.closest && e.target.closest(".ccheck-step-cb");
      if (!cb) return;
      const rec = ccByFinding.get(String(cb.getAttribute("data-ccheck-fid")));
      if (!rec) return;
      const sid = String(cb.getAttribute("data-ccheck-step"));
      if (cb.checked) rec.ticked.add(sid);
      else rec.ticked.delete(sid);
      // Flip the one button in place: a full render here would drop focus from the box just ticked.
      const panel = cb.closest(".ccheck-panel");
      const btn = panel && panel.querySelector && panel.querySelector("[data-ccheck-add]");
      if (btn) btn.disabled = rec.adding || rec.ticked.size === 0;
    });
  }

  window.loadContainmentCheck = loadContainmentCheck;
  window.containmentCheckChip = containmentCheckChip;
  window.containmentCheckPanel = containmentCheckPanel;
  window.containmentAttributionHtml = containmentAttributionHtml;
  window.containmentSyncPlaybook = containmentSyncPlaybook;
})();
