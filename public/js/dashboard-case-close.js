// Close case, and what happens to its cloud credentials (#2347).
//
// A case with cloud accounts asks first: Delete credentials (the default) or Keep credentials. The
// dialog lists each account by provider, name and account / tenant / project ID, and reminds the
// analyst that deleting the companion's copy does not stop the key working — revoke it in AWS,
// Azure or GCP as well. A case with no accounts (or that the caller cannot list them for, or the
// demo, where every cloud route is off) closes at once, as before. A running cloud collection
// makes the server refuse the close; its message is shown in the dialog.
//
// Account names come from analysts, so every one is written with textContent, never innerHTML.
(function () {
  "use strict";

  const PROVIDER_LABELS = { aws: "AWS", gcp: "GCP", microsoft: "Microsoft" };
  const byId = (id) => document.getElementById(id);
  // { caseId, resolve } while the dialog is open.
  let pending = null;

  function identifier(a) {
    const s = a.settings || {};
    if (a.provider === "gcp") return `project ${s.projectId || "not recorded"}`;
    if (a.provider === "microsoft") return `tenant ${s.tenantId || "not recorded"}`;
    const m = /^arn:aws[a-z-]*:iam::(\d{12}):/.exec(s.roleArn || "");
    return m ? `account ${m[1]}` : "account ID not recorded (access key)";
  }

  async function caseAccounts(caseId) {
    try {
      const res = await fetch(`/cases/${encodeURIComponent(caseId)}/cloud-accounts`);
      if (!res.ok) return [];
      const body = await res.json();
      return Array.isArray(body.accounts) ? body.accounts : [];
    } catch {
      return [];
    }
  }

  async function patchClosed(caseId, cloudCredentials) {
    const init = {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cloudCredentials ? { status: "closed", cloudCredentials } : { status: "closed" }),
    };
    const res = await fetch(`/cases/${encodeURIComponent(caseId)}/status`, init);
    let body = {};
    try {
      body = await res.json();
    } catch {
      body = {};
    }
    return { ok: res.ok, status: res.status, body };
  }

  function accountLine(a) {
    const li = document.createElement("li");
    li.textContent = `${PROVIDER_LABELS[a.provider] || a.provider} — ${a.name} — ${identifier(a)}`;
    return li;
  }

  function openDialog(caseId, accounts) {
    byId("ccaCaseName").textContent = `Close case "${caseId}". It has ${accounts.length} cloud account${accounts.length === 1 ? "" : "s"}:`;
    byId("ccaList").replaceChildren(...accounts.map(accountLine));
    byId("ccaDelete").checked = true;
    byId("ccaMsg").textContent = "";
    byId("ccaConfirm").disabled = false;
    byId("closeCaseOverlay").classList.add("open");
  }

  function finish(closed) {
    byId("closeCaseOverlay").classList.remove("open");
    const done = pending;
    pending = null;
    if (done) done.resolve(closed);
  }

  async function confirmClose() {
    if (!pending) return;
    const choice = byId("ccaKeep").checked ? "keep" : "delete";
    byId("ccaConfirm").disabled = true;
    byId("ccaMsg").textContent = "closing…";
    const res = await patchClosed(pending.caseId, choice);
    if (!res.ok) {
      byId("ccaConfirm").disabled = false;
      byId("ccaMsg").textContent = res.body.error || `Close failed (HTTP ${res.status})`;
      return;
    }
    if (res.body.cloudCredentialsError) alert(res.body.cloudCredentialsError);
    finish(true);
  }

  /**
   * Closes `caseId`, asking about its cloud credentials first when it has any. Resolves true once
   * the case is closed, false when the analyst cancelled or the close failed (already reported).
   */
  async function closeCaseWithCredentials(caseId) {
    const accounts = await caseAccounts(caseId);
    if (accounts.length === 0) {
      const res = await patchClosed(caseId);
      if (!res.ok) alert("Failed to close case: " + (res.body.error || "HTTP " + res.status));
      return res.ok;
    }
    if (pending) pending.resolve(false);
    return new Promise((resolve) => {
      pending = { caseId, resolve };
      openDialog(caseId, accounts);
    });
  }

  function initCaseClose() {
    if (!byId("closeCaseOverlay")) return;
    byId("ccaConfirm").onclick = confirmClose;
    byId("ccaCancel").onclick = () => finish(false);
  }

  window.closeCaseWithCredentials = closeCaseWithCredentials;
  window.initCaseClose = initCaseClose;
})();
