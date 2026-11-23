// The job card's Cancel button for a running bundle hunt, and the dialog it opens.
//
// THE ANALYST DECIDES WHAT HAPPENS IN VELOCIRAPTOR. Cancelling here always stops the companion from
// collecting the hunt, but the hunt itself lives on the Velociraptor server and keeps collecting from
// the fleet until someone stops it there. So the dialog asks: stop tracking it here only, also stop
// it in Velociraptor (the default), or also delete it — and the delete choice says plainly that it
// removes the hunt's collected results from the server too.
//
// HOLDS NOTHING. The hunt the open dialog is about is kept on the overlay's dataset, and the click
// wiring is one delegated listener, so js/dashboard-velo-triage.js only has to render the button
// (veloCancelHuntBtnHtml) and the cancelled card's line (veloCancelledDetail).

const VELO_CANCELLABLE = new Set(["running", "unreachable"]);

// The Cancel button for one job card, or "" when the hunt cannot be cancelled (finished, or a
// collect is running — the server refuses that too).
function veloCancelHuntBtnHtml(job) {
  if (!job || !VELO_CANCELLABLE.has(job.status) || job.collectActive) return "";
  return (
    ` <button class="velo-cancel-hunt-btn" data-hid="${escAttr(job.huntId)}" data-name="${escAttr(job.bundleName || "")}"` +
    ` title="Stop this hunt — you choose whether to also stop or delete it in Velociraptor">Cancel</button>`
  );
}

// The card's one-line explanation for a cancelled hunt; "" for any other status.
function veloCancelledDetail(job) {
  if (!job || job.status !== "cancelled") return "";
  const c = job.cancelled || {};
  const who = c.by ? ` by ${c.by}` : "";
  const what =
    c.action === "delete"
      ? "and deleted from Velociraptor"
      : c.action === "stop"
        ? "and stopped in Velociraptor"
        : "here only — it may still be running in Velociraptor";
  // Never answered (the companion restarted mid-call): the stop / delete is unconfirmed.
  if (c.pending)
    return `cancelled${who} here — Velociraptor never confirmed the ${c.action === "delete" ? "delete" : "stop"}; check the hunt in Velociraptor. No results were collected.`;
  // A refusal replaces the claim, never sits next to it: "deleted — but refused" reads as both.
  if (c.serverError)
    return `cancelled${who} here, but Velociraptor refused (${c.serverError}) — check the hunt in Velociraptor. No results were collected.`;
  return `cancelled${who} ${what}. No results were collected.`;
}

function veloCancelEl(id) {
  return document.getElementById(id);
}

function veloOpenCancelDialog(huntId, bundleName) {
  const overlay = veloCancelEl("veloCancelOverlay");
  if (!overlay) return;
  overlay.dataset.hid = huntId;
  veloCancelEl("vcaTitle").textContent = `Cancel hunt ${huntId}${bundleName ? ` ("${bundleName}")` : ""}`;
  veloCancelEl("vcaStop").checked = true;
  veloCancelEl("vcaMsg").textContent = "";
  veloCancelEl("vcaConfirm").disabled = false;
  overlay.classList.add("open");
}

function veloCloseCancelDialog() {
  const overlay = veloCancelEl("veloCancelOverlay");
  if (overlay) overlay.classList.remove("open");
}

async function veloConfirmCancel() {
  const overlay = veloCancelEl("veloCancelOverlay");
  const caseId = typeof veloCaseId === "function" ? veloCaseId() : null;
  const huntId = overlay && overlay.dataset.hid;
  if (!caseId || !huntId) return;
  const picked = document.querySelector('input[name="vcaChoice"]:checked');
  const velociraptor = picked ? picked.value : "stop";
  const msg = veloCancelEl("vcaMsg");
  const confirmBtn = veloCancelEl("vcaConfirm");
  confirmBtn.disabled = true;
  msg.textContent = "cancelling…";
  try {
    const r = await fetch(
      `/cases/${encodeURIComponent(caseId)}/velociraptor/hunt-jobs/${encodeURIComponent(huntId)}/cancel`,
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ velociraptor }) },
    );
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      msg.textContent = "not cancelled: " + (j.error || `HTTP ${r.status}`);
      confirmBtn.disabled = false;
      return;
    }
    if (j.serverError) {
      // Cancelled here, refused there: keep the dialog open long enough to read why.
      msg.textContent = `Cancelled here, but Velociraptor refused: ${j.serverError}. Check the hunt in Velociraptor.`;
    } else veloCloseCancelDialog();
    if (typeof loadVeloHuntJobs === "function") loadVeloHuntJobs(caseId);
  } catch (e) {
    msg.textContent = "not cancelled: " + e.message;
    confirmBtn.disabled = false;
  }
}

function initVeloHuntCancel() {
  document.addEventListener("click", (e) => {
    const btn = e.target && e.target.closest ? e.target.closest(".velo-cancel-hunt-btn") : null;
    if (btn) veloOpenCancelDialog(btn.dataset.hid, btn.dataset.name);
  });
  const confirmBtn = veloCancelEl("vcaConfirm");
  const backBtn = veloCancelEl("vcaBack");
  if (confirmBtn) confirmBtn.onclick = veloConfirmCancel;
  if (backBtn) backBtn.onclick = veloCloseCancelDialog;
}

// Guarded so the pure helpers above load in a test sandbox with no DOM.
if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initVeloHuntCancel);
  else initVeloHuntCancel();
}

window.veloCancelHuntBtnHtml = veloCancelHuntBtnHtml;
window.veloCancelledDetail = veloCancelledDetail;
