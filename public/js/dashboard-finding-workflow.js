// Finding assignment + workflow status (#87) — the per-finding analyst owner and triage state,
// server-backed so it survives synthesis (#415 tier 3).
//
// SPLIT OUT OF A BANNER THAT HELD TWO FEATURES. The "Finding assignment" comment heads 211 lines,
// of which the last 152 are Pinned Findings (#220) — a separate feature with its own state, its own
// drag handling and its own panel. The cohesion check reported clusters of 7 and 10 and it was
// right; they are two modules, not one.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the findingId → { assignee, status } map and the status
// label table.
//
// NO INITIALIZER: the per-finding controls are built by findingWorkflowControls() as the cards are
// rendered, which is where they have to be.
(function () {
  // ── Finding assignment + workflow status (#87) ──────────────────────────────────────────
  // Per-finding analyst owner + triage state, server-backed (state/finding-workflow.json) so it
  // survives synthesis. workflowByFinding maps findingId -> { assignee, status }. Merged onto the
  // finding cards; changes PATCH the server and the finding_workflow_changed WS syncs other clients.
  let workflowByFinding = new Map();
  const FINDING_WF_STATUS_LABELS = {
    new: "New",
    in_progress: "In progress",
    in_review: "In review",
    resolved: "Resolved",
  };
  function loadFindingWorkflow(caseId) {
    fetch(`/cases/${caseId}/finding-workflow`)
      .then((r) => r.json())
      .then((list) => {
        workflowByFinding = new Map();
        (Array.isArray(list) ? list : []).forEach((r) => {
          if (r && r.findingId) workflowByFinding.set(String(r.findingId), r);
        });
        if (DfirState.lastState()) render(DfirState.lastState()); // refresh the inline assignee/status controls
      })
      .catch(() => {});
  }
  // The assignee + status controls shown on each finding card — icon action buttons matching the
  // comment/tag/pin/FP set. Status is a colour-coded icon with the native <select> overlaid on top
  // (so a click opens the real dropdown); Assign is a person icon that also shows the owner's name.
  function findingWorkflowControls(fid) {
    const wf = workflowByFinding.get(String(fid)) || {};
    const status = wf.status || "";
    const opts = [
      ["", "— status —"],
      ["new", "New"],
      ["in_progress", "In progress"],
      ["in_review", "In review"],
      ["resolved", "Resolved"],
    ]
      .map(
        ([v, l]) =>
          `<option value="${v}"${v === status ? " selected" : ""}>${l}</option>`,
      )
      .join("");
    const statusLabel = status ? FINDING_WF_STATUS_LABELS[status] : "None";
    const assignee = (wf.assignee || "").trim();
    const statusCtl =
      `<span class="fwf-status-wrap" title="Workflow status: ${escAttr(statusLabel)}">` +
      `<span class="fwf-btn fwf-status-btn${status ? " fwf-" + status : ""}" aria-hidden="true">${ICON_FLOW}</span>` +
      `<select class="fwf-status" data-fwf="${escAttr(String(fid))}" aria-label="Workflow status">${opts}</select>` +
      `</span>`;
    // Assigned → a compact initials chip (full name in the tooltip) so it stays one icon-button wide;
    // unassigned → the plain person icon. Keeps all the row actions on a single line.
    const assignCtl =
      `<button type="button" class="fwf-btn fwf-assignee${assignee ? " assigned" : ""}" data-fwf="${escAttr(String(fid))}" ` +
      `title="${assignee ? "Assigned to " + escAttr(assignee) + " — click to change" : "Assign this finding to an analyst"}">` +
      `${assignee ? `<span class="fwf-initials">${esc(_workflowInitials(assignee))}</span>` : ICON_USER}</button>`;
    return `<span class="finding-workflow">${statusCtl}${assignCtl}</span>`;
  }
  // PATCH one field; the server drops the record when both assignee and status become empty.
  function patchFindingWorkflow(fid, patch) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !fid) return;
    fetch(
      `/cases/${caseId}/findings/${encodeURIComponent(String(fid))}/workflow`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...patch, updatedBy: investigatorName() }),
      },
    )
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        // Reconcile locally for instant feedback; the WS finding_workflow_changed also arrives.
        if (data && "record" in data) {
          if (data.record) workflowByFinding.set(String(fid), data.record);
          else workflowByFinding.delete(String(fid));
          if (DfirState.lastState()) render(DfirState.lastState());
        }
      })
      .catch(() => {});
  }
  function setFindingWorkflowStatus(fid, value) {
    patchFindingWorkflow(fid, { status: value || "" });
  }
  function assignFinding(fid) {
    const wf = workflowByFinding.get(String(fid)) || {};
    const next = window.prompt(
      "Assign this finding to (leave blank to clear):",
      wf.assignee || "",
    );
    if (next === null) return; // cancelled
    patchFindingWorkflow(fid, { assignee: next.trim() });
  }

  window.loadFindingWorkflow = loadFindingWorkflow;
  window.findingWorkflowControls = findingWorkflowControls;
  window.setFindingWorkflowStatus = setFindingWorkflowStatus;
  window.assignFinding = assignFinding;
})();
