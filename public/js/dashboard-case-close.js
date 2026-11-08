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

  // How long the close may stay on the wire before the dialog stops waiting for it (#2412). Aborting
  // the request does not undo a close the server already made — so a timeout, like a network error,
  // is "outcome unknown", and the case's status is read back before anything is claimed.
  const CLOSE_TIMEOUT_MS = 30000;

  async function patchClosed(caseId, cloudCredentials) {
    const canTime = typeof AbortController === "function" && typeof setTimeout === "function";
    const ac = canTime ? new AbortController() : null;
    const timer = ac ? setTimeout(() => ac.abort(), CLOSE_TIMEOUT_MS) : null;
    const stopTimer = () => {
      if (timer !== null && typeof clearTimeout === "function") clearTimeout(timer);
    };
    const init = {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cloudCredentials ? { status: "closed", cloudCredentials } : { status: "closed" }),
    };
    if (ac) init.signal = ac.signal;
    // A network failure is an answer too (#2412): thrown past the dialog it left "closing…" on screen
    // with the button disabled for good. It is NOT a refusal, though — the server may have closed
    // the case and lost the reply — so it is reconciled against the case's status.
    let res;
    try {
      res = await fetch(`/cases/${encodeURIComponent(caseId)}/status`, init);
    } catch (err) {
      stopTimer();
      return reconcileUnknown(caseId, err);
    }
    let body = {};
    try {
      body = await res.json();
    } catch {
      body = {};
    }
    stopTimer();
    return { ok: res.ok, status: res.status, body };
  }

  // The case's lifecycle status from the case list, or null when that cannot be read either.
  async function caseStatus(caseId) {
    try {
      const res = await fetch("/cases");
      if (!res.ok) return null;
      const cases = await res.json();
      const meta = Array.isArray(cases) ? cases.find((c) => c && c.caseId === caseId) : null;
      return meta ? meta.status || null : null;
    } catch {
      return null;
    }
  }

  async function reconcileUnknown(caseId, err) {
    const status = await caseStatus(caseId);
    if (status === "closed") return { ok: true, status: 200, body: {}, reconciled: true };
    const reason = err && err.name === "AbortError" ? "no answer in time" : (err && err.message) || "network error";
    if (status)
      return { ok: false, status: 0, body: { error: `Close failed — the companion did not answer (${reason}); the case is still ${status}.` } };
    return {
      ok: false,
      status: 0,
      unknown: true,
      body: {
        error: `The companion did not answer (${reason}), and the case's status could not be read — the close may have gone through. Check the case status before retrying.`,
      },
    };
  }

  // Refresh what shows the case's lifecycle. The toolbar describes the case on screen, so it is only
  // repainted for that case; the case list is always refreshed.
  function refreshLifecycle(caseId) {
    const current = (byId("caseId") || {}).value;
    if (typeof window.loadCaseLifecycle === "function" && typeof current === "string" && current.trim() === caseId)
      window.loadCaseLifecycle(caseId);
    if (typeof window.loadCaseList === "function") window.loadCaseList();
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
    byId("ccaCancel").disabled = false;
    byId("closeCaseOverlay").classList.add("open");
  }

  function finish(closed) {
    byId("closeCaseOverlay").classList.remove("open");
    const done = pending;
    pending = null;
    if (!done) return;
    // A cancel after an unknown outcome: the case may be closed, so show what the server now says.
    if (!closed && done.unknown) refreshLifecycle(done.caseId);
    done.resolve(closed);
  }

  // CANCEL CANNOT HIDE A CLOSE (#2412). Once the close is on the wire, Cancel is disabled: resolving
  // "not closed" there let the case close on the server while nothing refreshed the lifecycle or the
  // case list. It comes back with Confirm when the close fails. A dialog replaced while its close was
  // on the wire (a second close opened over it) has already told its caller "not closed", so a close
  // that then succeeds refreshes the lifecycle and the case list itself.
  async function confirmClose() {
    if (!pending) return;
    const mine = pending;
    const choice = byId("ccaKeep").checked ? "keep" : "delete";
    byId("ccaConfirm").disabled = true;
    byId("ccaCancel").disabled = true;
    byId("ccaMsg").textContent = "closing…";
    const res = await patchClosed(mine.caseId, choice);
    if (pending !== mine) {
      if (res.ok || res.unknown) {
        if (res.body.cloudCredentialsError) alert(res.body.cloudCredentialsError);
        refreshLifecycle(mine.caseId);
      }
      return;
    }
    if (!res.ok) {
      mine.unknown = !!res.unknown;
      byId("ccaConfirm").disabled = false;
      byId("ccaCancel").disabled = false;
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
      if (res.unknown) {
        alert(res.body.error);
        refreshLifecycle(caseId);
      } else if (!res.ok) alert("Failed to close case: " + (res.body.error || "HTTP " + res.status));
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
