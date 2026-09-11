// Finding attack outcome (#930 item 8) — the analyst's statement of what happened, on two axes:
// did the malicious action itself run (execution), and what did a security control do (control).
// Server-backed in state/finding-outcome.json so it survives synthesis, exactly like finding
// workflow (#87): the model rebuilds the finding list every run and would wipe anything written
// onto a finding.
//
// TWO AXES, NEVER ONE VERDICT. A blocked attack used to have nowhere to go on a card — dismiss it
// (wrong: the detection was right) or leave it open at High (wrong: it did not succeed). And a
// payload that RAN and was then quarantined is both "observed" and "remediated" at once; one
// dropdown would force the analyst to lie on one axis. So there are two dropdowns, and the report
// prints both.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the findingId → record map and the two label tables.
//
// NO INITIALIZER: the per-finding controls are built by findingOutcomeControls() as the cards are
// rendered, which is where they have to be.
(function () {
  let outcomeByFinding = new Map();
  // The case whose records the map holds. Cleared SYNCHRONOUSLY on a case switch and checked when
  // the fetch returns, so a slow or failed load can never leave the previous case's outcomes on
  // the new case's cards — ids like "f1" recur across cases.
  let activeCase = "";
  // Per-finding PATCH generation. Two quick edits to one finding can answer out of order, and a
  // save for case A can answer after case B has loaded; only the newest request for the active
  // case may touch the map, the cards, or the toast.
  const patchSeq = new Map();
  // The vocabularies mirror EXECUTION_OUTCOMES / CONTROL_DISPOSITIONS in stateTypes.ts. The server
  // rejects anything else with a 400, so a drift here shows up as a visible failure, not a silent one.
  const EXECUTION_LABELS = {
    observed: "Execution observed",
    "not-observed": "Execution not observed",
    unknown: "Execution unknown",
  };
  const CONTROL_LABELS = {
    blocked: "Blocked before execution",
    remediated: "Remediated after execution",
    "remediation-failed": "Remediation failed",
    allowed: "Allowed by control",
    "none-observed": "No control action seen",
    unknown: "Control unknown",
  };
  function loadFindingOutcome(caseId) {
    bindOnce();
    activeCase = String(caseId);
    outcomeByFinding = new Map();
    fetch(`/cases/${caseId}/finding-outcome`)
      .then((r) => r.json())
      .then((list) => {
        if (String(caseId) !== activeCase) return; // a later switch already owns the map
        outcomeByFinding = new Map();
        (Array.isArray(list) ? list : []).forEach((r) => {
          if (r && r.findingId) outcomeByFinding.set(String(r.findingId), r);
        });
        if (DfirState.lastState()) render(DfirState.lastState());
      })
      .catch(() => {});
  }
  // One icon button with the native <select> overlaid, the same shape as the workflow status
  // control, so the two outcome dropdowns sit in the card's action row like every other control.
  function axisControl(fid, axis, current, labels, icon, placeholder) {
    const opts = [["", placeholder]]
      .concat(Object.keys(labels).map((v) => [v, labels[v]]))
      .map(([v, l]) => `<option value="${v}"${v === current ? " selected" : ""}>${l}</option>`)
      .join("");
    const title = current ? labels[current] : placeholder;
    return (
      `<span class="fwf-status-wrap" title="${escAttr(title)}">` +
      `<span class="fwf-btn fwf-status-btn fout-btn${current ? " fout-" + axis + "-" + current : ""}" aria-hidden="true">${icon}</span>` +
      `<select class="fout-select fout-${axis}" data-fout="${escAttr(String(fid))}" aria-label="${escAttr(placeholder)}">${opts}</select>` +
      `</span>`
    );
  }
  // Delegated 'change' (a select does not emit 'click'), bound ONCE from the case load rather than
  // at script load: this module has no initializer and the page contract forbids touching the DOM
  // outside a function. Not from the card renderer either — that runs in a loop, and a function a
  // loop reaches must not be able to commit (dashboardSelection contract). Its own select class, so
  // the workflow handler in dashboard.html never sees these controls.
  let bound = false;
  function bindOnce() {
    if (bound) return;
    bound = true;
    document.addEventListener("change", (e) => {
      const sel = e.target && e.target.closest && e.target.closest(".fout-select");
      if (!sel) return;
      if (sel.classList.contains("fout-exec")) setFindingExecution(sel.getAttribute("data-fout"), sel.value);
      else if (sel.classList.contains("fout-ctl")) setFindingControl(sel.getAttribute("data-fout"), sel.value);
    });
  }
  function findingOutcomeControls(fid) {
    const rec = outcomeByFinding.get(String(fid)) || {};
    return (
      `<span class="finding-outcome">` +
      axisControl(fid, "exec", rec.execution || "", EXECUTION_LABELS, ICON_TARGET, "Execution outcome") +
      axisControl(fid, "ctl", rec.control || "", CONTROL_LABELS, ICON_FLAG, "Control disposition") +
      `</span>`
    );
  }
  // PATCH one axis; the server drops the record when both axes and the note are empty.
  //
  // A native <select> shows the new value the instant it is chosen, before the server has said
  // anything. If the save then fails — disk full, permissions, a timeout — the card would go on
  // looking saved while the report and the next session omit it. So a failure re-renders (which
  // rebuilds the controls from the LAST SAVED map, reverting the select) and says so on screen.
  function patchFindingOutcome(fid, patch) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !fid) return;
    const key = String(fid);
    const seq = (patchSeq.get(key) || 0) + 1;
    patchSeq.set(key, seq);
    // Stale = the analyst has since switched case, or edited this finding again. Either way this
    // response describes a world the page no longer shows.
    const stale = () => caseId !== activeCase || patchSeq.get(key) !== seq;
    const revertOutcomeSave = (why) => {
      if (stale()) return;
      if (DfirState.lastState()) render(DfirState.lastState());
      if (typeof showToast === "function") showToast(`Attack outcome not saved: ${why}`, "error");
    };
    fetch(`/cases/${caseId}/findings/${encodeURIComponent(String(fid))}/outcome`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...patch, updatedBy: investigatorName() }),
    })
      .then((r) => r.json().then((data) => ({ ok: r.ok, status: r.status, data })))
      .then(({ ok, status, data }) => {
        if (!ok || !data || !("record" in data)) {
          revertOutcomeSave((data && data.error) || `server returned ${status}`);
          return;
        }
        if (stale()) return;
        if (data.record) outcomeByFinding.set(key, data.record);
        else outcomeByFinding.delete(key);
        if (DfirState.lastState()) render(DfirState.lastState());
      })
      .catch((err) => revertOutcomeSave((err && err.message) || "network error"));
  }
  function setFindingExecution(fid, value) {
    patchFindingOutcome(fid, { execution: value || null });
  }
  function setFindingControl(fid, value) {
    patchFindingOutcome(fid, { control: value || null });
  }

  window.loadFindingOutcome = loadFindingOutcome;
  window.findingOutcomeControls = findingOutcomeControls;
  window.setFindingExecution = setFindingExecution;
  window.setFindingControl = setFindingControl;
})();
