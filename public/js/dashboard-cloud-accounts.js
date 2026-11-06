// Settings → Cloud accounts (#2307, per case since #2308): the AWS accounts, Microsoft tenants and
// GCP projects that cloud collection will use, and the vault that keeps their credentials.
//
// Accounts belong to cases. The main list is the open case's accounts (/cases/<id>/cloud-accounts,
// which needs write on the case). Below it, "Cloud credentials held" (/cloud-accounts, #2347) lists
// every credential the caller may see: the accounts of cases they write, each with its cases and
// their status (open, closed — credentials kept), who added it and when, and when it was last used.
// An instance administrator (or the single user) sees every account, including unattached ones —
// added before #2308 or left after a case delete — and alone may delete those. Rows can be ticked
// and deleted together; every delete confirmation reminds the analyst to revoke the key in the cloud.
// On the public demo every cloud route answers 403 with `demo: true`, and the panel hides itself.
//
// The server never sends a stored credential back — only the NAMES of the secrets an account holds.
// An empty secret field on Edit keeps the stored value; typing a new value replaces it (rotation).
// Account names come from analysts, so every one is written with textContent, never innerHTML.
//
// Since #2309 the add form shows the provider's minimum read-only policy (sent with the account
// list), and each account has Check access: one read per picked source, reported in the server's
// fixed wording. Results echo cloud error text, so they too are written with textContent only.
(function () {
  "use strict";

  const PROVIDER_LABELS = { aws: "AWS", gcp: "GCP", microsoft: "Microsoft" };
  // [input id, provider, "settings" | "secrets", field]. Field names are the server's (accountInput.ts).
  const FIELDS = [
    ["caAwsAuthMode", "aws", "settings", "authMode"],
    ["caAwsRoleArn", "aws", "settings", "roleArn"],
    ["caAwsBase", "aws", "settings", "baseCredential"],
    ["caAwsRegion", "aws", "settings", "region"],
    ["caAwsSession", "aws", "settings", "sessionSeconds"],
    ["caAwsExternalId", "aws", "secrets", "externalId"],
    ["caAwsKeyId", "aws", "secrets", "accessKeyId"],
    ["caAwsSecret", "aws", "secrets", "secretAccessKey"],
    ["caAwsSessionToken", "aws", "secrets", "sessionToken"],
    ["caGcpProject", "gcp", "settings", "projectId"],
    ["caGcpAuthMode", "gcp", "settings", "authMode"],
    ["caGcpTarget", "gcp", "settings", "targetServiceAccount"],
    ["caGcpBase", "gcp", "settings", "baseCredential"],
    ["caGcpKeyJson", "gcp", "secrets", "serviceAccountKeyJson"],
    ["caMsTenant", "microsoft", "settings", "tenantId"],
    ["caMsClient", "microsoft", "settings", "clientId"],
    ["caMsFormat", "microsoft", "settings", "certificateFormat"],
    ["caMsPem", "microsoft", "secrets", "certificatePem"],
    ["caMsPfxPassword", "microsoft", "secrets", "pfxPassword"],
  ];

  // The sources a read check can test, per provider (integrations/cloudCheck/readCheckTypes.ts).
  const CHECK_SOURCES = {
    aws: [
      ["cloudtrail-lookup", "CloudTrail event history"],
      ["s3-trail", "CloudTrail S3 bucket"],
    ],
    microsoft: [
      ["entra-signins", "Entra sign-in logs"],
      ["entra-directory-audits", "Entra directory audit logs"],
    ],
    gcp: [
      ["audit-logs", "Admin Activity, System Event and Policy audit logs"],
      ["data-access-logs", "Data Access audit logs"],
    ],
  };
  const STATUS_TEXT = { succeeded: "Read worked", failed: "Failed", "not-tested": "Not tested" };
  const CASE_STATUS_TEXT = {
    open: "open",
    closed: "closed — credentials kept",
    archived: "archived",
    missing: "deleted",
  };
  const REVOKE_REMINDER =
    "Deleting the companion's copy does not stop the credential working: also revoke the key or app secret in AWS, Azure or GCP.";

  // The account open in the form and where it was opened from: { account, url } — `url` is the
  // account's own route (case or instance-wide). null for a new account.
  let editing = null;
  // The minimum policy per provider, from the last account list the server sent.
  let policies = {};
  // The account open in the check panel: { account, url, boxes: [[sourceId, checkbox]] }, or null.
  let checking = null;
  // The ticked rows of the held-credentials list: account id -> account.
  let selected = new Map();

  const byId = (id) => document.getElementById(id);

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  function setMsg(text, isError) {
    const box = byId("cloudAccountsMsg");
    if (!box) return;
    box.textContent = text || "";
    box.style.color = isError ? "var(--badge-danger-text)" : "";
  }

  async function readJson(res) {
    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  function currentCaseId() {
    const box = byId("caseId");
    return box && typeof box.value === "string" ? box.value.trim() : "";
  }

  function caseBase(caseId) {
    return `/cases/${encodeURIComponent(caseId)}/cloud-accounts`;
  }

  async function getJson(url) {
    try {
      const res = await fetch(url);
      return { ok: res.ok, status: res.status, body: await readJson(res) };
    } catch (e) {
      return { ok: false, status: 0, body: { error: e.message } };
    }
  }

  async function send(url, method, body) {
    const init = { method };
    if (body !== undefined) {
      init.headers = { "Content-Type": "application/json" };
      init.body = JSON.stringify(body);
    }
    const res = await fetch(url, init);
    return { ok: res.ok, status: res.status, body: await readJson(res) };
  }

  function keyLine(body) {
    const line = byId("cloudVaultKeyLine");
    if (!line) return;
    if (!body.keyState) {
      line.textContent = "";
      return;
    }
    const where = body.keyPath || "on the server";
    if (body.keyState === "present") line.textContent = `Vault key file: ${where}`;
    else if (body.keyState === "missing")
      line.textContent = `Vault key file: ${where} — not found. It is made when you add the first account.`;
    else if (body.keyState === "insecure")
      line.textContent = `Vault key file: ${where} — permissions too open. Limit it to its owner (chmod 600).`;
    else line.textContent = `Vault key file: ${where} — not a valid vault key.`;
    const bad = body.keyState === "invalid" || body.keyState === "insecure";
    line.style.color = bad ? "var(--badge-danger-text)" : "";
  }

  function summary(a) {
    const s = a.settings || {};
    if (a.provider === "aws") return s.roleArn || "access key";
    if (a.provider === "gcp") return s.projectId || "";
    return s.tenantId || "";
  }

  function accountRow(a, metaText, lead) {
    const row = el("div", null, "server-set-row");
    row.setAttribute("role", "listitem");
    if (lead) row.appendChild(lead);
    row.appendChild(el("strong", a.name, "server-set-name"));
    row.appendChild(el("span", PROVIDER_LABELS[a.provider] || a.provider, "server-set-badge"));
    row.appendChild(el("span", summary(a), "server-set-meta"));
    if (metaText) row.appendChild(el("span", metaText, "server-set-meta"));
    if (a.locked) {
      const lock = el("span", a.locked, "server-set-meta");
      lock.style.color = "var(--badge-danger-text)";
      row.appendChild(lock);
    }
    return row;
  }

  function sharedText(a, caseId) {
    const others = (a.caseIds || []).filter((c) => c !== caseId);
    const hidden = Number(a.otherCases) || 0;
    const parts = others.length ? [`Also in ${others.join(", ")}`] : [];
    if (hidden) parts.push(`${hidden} case${hidden === 1 ? "" : "s"} you cannot write`);
    return parts.join("; ");
  }

  // One account of the open case: Edit, Share with case…, Detach, Delete.
  function renderCaseRow(a, caseId) {
    const row = accountRow(a, sharedText(a, caseId));
    const url = `${caseBase(caseId)}/${encodeURIComponent(a.id)}`;
    const actions = el("span", null, "server-set-actions");
    if (!a.locked) actions.appendChild(button("Edit", () => openForm(a, url)));
    if (!a.locked) actions.appendChild(button("Check access", () => openCheck(a, url)));
    actions.appendChild(button("Share with case…", () => shareAccount(a, url)));
    actions.appendChild(button("Detach", () => detachAccount(a, url, caseId)));
    actions.appendChild(button("Delete", () => deleteAccount(a, url)));
    row.appendChild(actions);
    return row;
  }

  function shortDate(iso) {
    return typeof iso === "string" && iso ? iso.slice(0, 16).replace("T", " ") + " UTC" : "";
  }

  // "Cases: c1 (open), c2 (closed — credentials kept)", or "Not attached to a case".
  function casesText(a) {
    const cases = Array.isArray(a.cases) ? a.cases : (a.caseIds || []).map((caseId) => ({ caseId }));
    const hidden = Number(a.otherCases) || 0;
    if (cases.length === 0 && hidden === 0) return "Not attached to a case";
    const parts = cases.map((c) => (c.status ? `${c.caseId} (${CASE_STATUS_TEXT[c.status] || c.status})` : c.caseId));
    if (hidden) parts.push(`${hidden} case${hidden === 1 ? "" : "s"} you cannot write`);
    return `Cases: ${parts.join(", ")}`;
  }

  function heldDetails(a) {
    const by = a.createdBy && a.createdBy.displayName ? a.createdBy.displayName : "not recorded";
    const used = a.lastUsedAt ? shortDate(a.lastUsedAt) : "not recorded";
    return `${casesText(a)} · Added by ${by}, ${shortDate(a.createdAt)} · Last used: ${used}`;
  }

  // Deletable from the list: the administrator any; anyone else only with write on every case.
  function canDelete(a, admin) {
    return admin || ((a.caseIds || []).length > 0 && !(Number(a.otherCases) > 0));
  }

  // One row of "Cloud credentials held": tick box, details, and (administrator) Attach / Edit; Delete.
  function renderHeldRow(a, caseId, admin) {
    let tick = null;
    if (canDelete(a, admin)) {
      tick = el("input");
      tick.type = "checkbox";
      tick.setAttribute("aria-label", `Select ${a.name}`);
      tick.checked = selected.has(a.id);
      tick.onchange = () => toggleSelected(a, tick.checked);
    }
    const row = accountRow(a, heldDetails(a), tick);
    const url = `/cloud-accounts/${encodeURIComponent(a.id)}`;
    const actions = el("span", null, "server-set-actions");
    if (admin && caseId && !(a.caseIds || []).includes(caseId))
      actions.appendChild(button("Attach to this case", () => attachTo(a, `${url}/attach`, caseId)));
    if (admin && !a.locked) actions.appendChild(button("Edit", () => openForm(a, url)));
    if (canDelete(a, admin)) actions.appendChild(button("Delete", () => deleteAccount(a, url)));
    row.appendChild(actions);
    return row;
  }

  function toggleSelected(a, on) {
    const next = new Map(selected);
    if (on) next.set(a.id, a);
    else next.delete(a.id);
    selected = next;
    const btn = byId("cloudAccountsDeleteSelected");
    if (btn) {
      btn.disabled = selected.size === 0;
      btn.textContent = selected.size ? `Delete selected (${selected.size})` : "Delete selected";
    }
  }

  async function deleteSelected() {
    const picked = [...selected.values()];
    if (picked.length === 0) return;
    const names = picked.map((a) => `'${a.name}'`).join(", ");
    const ok = confirm(
      `Delete ${picked.length} cloud account${picked.length === 1 ? "" : "s"} (${names})? Each stored credential is ` +
        `erased for every case it is attached to, and each case's custody log records it.\n\n${REVOKE_REMINDER}`,
    );
    if (!ok) return;
    const res = await send("/cloud-accounts/delete", "POST", { ids: picked.map((a) => a.id) });
    await loadCloudAccounts(); // clears the message line, so the outcome is written after it
    setMsg(
      res.ok ? `Deleted ${Number(res.body.deleted) || 0} cloud account(s).` : res.body.error || `Delete failed (HTTP ${res.status})`,
      !res.ok,
    );
  }

  function hidePanel() {
    for (const id of ["cloudAccountsPanel", "cloudAccountsHead"]) {
      const node = byId(id);
      if (node) node.hidden = true;
    }
  }

  function button(label, onClick) {
    const b = el("button", label);
    b.type = "button";
    b.onclick = onClick;
    return b;
  }

  function renderCaseList(box, caseId, res) {
    if (!caseId) {
      box.replaceChildren(el("div", "Open a case to see and add its cloud accounts.", "server-set-meta"));
      return;
    }
    if (!res.ok) {
      box.replaceChildren();
      setMsg(`Cloud accounts cannot be loaded: ${res.body.error || `HTTP ${res.status}`}`, true);
      return;
    }
    const accounts = Array.isArray(res.body.accounts) ? res.body.accounts : [];
    box.replaceChildren(...accounts.map((a) => renderCaseRow(a, caseId)));
    if (accounts.length === 0) box.appendChild(el("div", "No cloud accounts in this case yet.", "server-set-meta"));
  }

  // "Cloud credentials held" (#2347): what the caller may see; the administrator sees every account.
  function renderHeldList(caseId, res) {
    const section = byId("cloudAccountsAll");
    const box = byId("cloudAccountsAllList");
    const admin = res.ok && res.body.admin !== false;
    const reset = byId("cloudVaultResetBtn");
    if (reset) reset.hidden = !admin;
    if (!section || !box) return;
    const accounts = res.ok && Array.isArray(res.body.accounts) ? res.body.accounts : [];
    section.hidden = !res.ok || (!admin && accounts.length === 0);
    selected = new Map();
    toggleSelected({ id: "" }, false);
    if (section.hidden) return;
    box.replaceChildren(...accounts.map((a) => renderHeldRow(a, caseId, admin)));
    if (accounts.length === 0) box.appendChild(el("div", "No cloud accounts yet.", "server-set-meta"));
  }

  async function loadCloudAccounts() {
    const box = byId("cloudAccountsList");
    if (!box) return;
    const caseId = currentCaseId();
    const inCase = caseId ? await getJson(caseBase(caseId)) : { ok: false, status: 0, body: {} };
    // The held-credentials list, cut by the server to what this caller may see (#2347).
    const all = await getJson("/cloud-accounts");
    if (inCase.body.demo || all.body.demo) return hidePanel();
    const sent = (all.ok && all.body.minimumPolicies) || (inCase.ok && inCase.body.minimumPolicies);
    if (sent && typeof sent === "object") policies = sent;
    setMsg("", false);
    const admin = all.ok && all.body.admin !== false;
    keyLine(admin ? all.body : inCase.body);
    renderCaseList(box, caseId, inCase);
    renderHeldList(caseId, all);
    const add = byId("cloudAccountAddBtn");
    if (add) add.disabled = !caseId && !admin;
  }

  function showProvider(provider) {
    document.querySelectorAll("#cloudAccountForm [data-cloud-provider]").forEach((node) => {
      node.hidden = node.dataset.cloudProvider !== provider;
    });
    renderPolicy(provider);
  }

  // The provider's minimum read-only policy, in the add/edit form.
  function renderPolicy(provider) {
    const box = byId("caPolicyBox");
    if (!box) return;
    const policy = policies[provider];
    box.hidden = !policy;
    if (!policy) return;
    byId("caPolicyTitle").textContent = policy.title || "";
    byId("caPolicyGrant").textContent = policy.grant || "";
    const notes = Array.isArray(policy.notes) ? policy.notes : [];
    byId("caPolicyNotes").replaceChildren(...notes.map((n) => el("li", n)));
  }

  function checkbox(id, label) {
    const wrap = el("label");
    const box = el("input");
    box.type = "checkbox";
    box.checked = true;
    box.dataset.source = id;
    wrap.appendChild(box);
    wrap.appendChild(el("span", ` ${label}`));
    return { wrap, box };
  }

  // Opens the check panel for one account of the open case, every source picked.
  function openCheck(account, url) {
    const panel = byId("cloudCheckPanel");
    if (!panel) return;
    const sources = CHECK_SOURCES[account.provider] || [];
    const made = sources.map(([id, label]) => ({ id, ...checkbox(id, label) }));
    checking = { account, url, boxes: made.map((m) => [m.id, m.box]) };
    byId("ccTitle").textContent = `Check access: ${account.name}`;
    byId("ccSources").replaceChildren(...made.map((m) => m.wrap));
    byId("ccS3Fields").hidden = account.provider !== "aws";
    byId("ccResult").replaceChildren();
    panel.hidden = false;
  }

  function closeCheck() {
    checking = null;
    const panel = byId("cloudCheckPanel");
    if (panel) panel.hidden = true;
  }

  function checkBody() {
    const body = { sources: checking.boxes.filter(([, box]) => box.checked).map(([id]) => id) };
    if (checking.account.provider === "aws") {
      const bucket = byId("ccS3Bucket").value.trim();
      const prefix = byId("ccS3Prefix").value.trim();
      if (bucket) body.s3Bucket = bucket;
      if (prefix) body.s3Prefix = prefix;
    }
    return body;
  }

  function renderReport(report) {
    const out = byId("ccResult");
    const lines = [];
    if (report.signedInAs) lines.push(el("div", `Signed in as ${report.signedInAs}`));
    for (const r of Array.isArray(report.results) ? report.results : []) {
      const status = STATUS_TEXT[r.status] || r.status;
      const line = el("div", `${status}: ${r.label}${r.detail ? ` — ${r.detail}` : ""}`);
      if (r.status === "failed") line.style.color = "var(--badge-danger-text)";
      lines.push(line);
    }
    lines.push(el("p", report.summary || ""));
    out.replaceChildren(...lines);
  }

  async function runCheck() {
    if (!checking) return;
    const body = checkBody();
    if (body.sources.length === 0) {
      byId("ccResult").replaceChildren(el("div", "Pick at least one source to check."));
      return;
    }
    const target = checking;
    byId("ccRun").disabled = true;
    byId("ccResult").replaceChildren(el("div", "Checking… each source can take up to 20 seconds."));
    let res;
    try {
      res = await send(`${target.url}/check`, "POST", body);
    } catch (e) {
      res = { ok: false, status: 0, body: { error: e.message } };
    }
    byId("ccRun").disabled = false;
    if (checking !== target) return;
    if (!res.ok || !res.body.report) {
      const msg = el("div", res.body.error || `Check failed (HTTP ${res.status})`);
      msg.style.color = "var(--badge-danger-text)";
      byId("ccResult").replaceChildren(msg);
      return;
    }
    renderReport(res.body.report);
  }

  function openForm(account, url) {
    editing = account ? { account, url } : null;
    const form = byId("cloudAccountForm");
    form.reset();
    byId("caMsPfx").value = "";
    byId("caProvider").disabled = !!account;
    if (account) {
      byId("caName").value = account.name;
      byId("caProvider").value = account.provider;
      for (const [id, provider, part, field] of FIELDS) {
        if (provider !== account.provider || part !== "settings") continue;
        const v = (account.settings || {})[field];
        if (v !== undefined && v !== null) byId(id).value = String(v);
      }
      const stored = (account.storedSecrets || []).join(", ") || "none";
      byId("caStoredSecrets").textContent = `Stored secrets: ${stored}. Leave a secret empty to keep it; type a new value to replace it.`;
    } else {
      byId("caStoredSecrets").textContent = "";
    }
    showProvider(byId("caProvider").value);
    form.hidden = false;
    byId("caName").focus();
  }

  function closeForm() {
    editing = null;
    byId("cloudAccountForm").reset();
    byId("cloudAccountForm").hidden = true;
  }

  function readFileBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).replace(/^data:[^,]*,/, ""));
      reader.onerror = () => reject(new Error("The PFX file cannot be read."));
      reader.readAsDataURL(file);
    });
  }

  async function formBody() {
    const provider = byId("caProvider").value;
    const body = { name: byId("caName").value, provider, settings: {}, secrets: {} };
    for (const [id, p, part, field] of FIELDS) {
      if (p !== provider) continue;
      const v = byId(id).value;
      if (v !== "") body[part][field] = field === "sessionSeconds" ? Number(v) : v;
    }
    const pfx = byId("caMsPfx").files && byId("caMsPfx").files[0];
    if (provider === "microsoft" && pfx) body.secrets.pfxBase64 = await readFileBase64(pfx);
    return body;
  }

  async function saveForm(event) {
    event.preventDefault();
    let body;
    try {
      body = await formBody();
    } catch (e) {
      setMsg(e.message, true);
      return;
    }
    // A new account goes into the open case; with no case open, an administrator adds it unattached.
    const caseId = currentCaseId();
    const url = editing ? editing.url : caseId ? caseBase(caseId) : "/cloud-accounts";
    const res = await fetch(url, {
      method: editing ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const out = await readJson(res);
    if (!res.ok) {
      setMsg(out.error || `Save failed (HTTP ${res.status})`, true);
      return;
    }
    closeForm();
    setMsg(out.notice || "Saved.", false);
    if (out.notice) alert(out.notice);
    loadCloudAccounts();
  }

  async function deleteAccount(a, url) {
    const ok = confirm(
      `Delete cloud account '${a.name}'? Its stored credential is erased for every case it is attached to, and ` +
        `each case's custody log records it.\n\n${REVOKE_REMINDER}`,
    );
    if (!ok) return;
    const res = await send(url, "DELETE");
    setMsg(res.ok ? "Deleted." : res.body.error || `Delete failed (HTTP ${res.status})`, !res.ok);
    loadCloudAccounts();
  }

  async function detachAccount(a, url, caseId) {
    if (!confirm(`Detach '${a.name}' from case ${caseId}? Other cases that use it keep it.`)) return;
    const res = await send(`${url}/detach`, "POST");
    setMsg(res.ok ? "Detached from this case." : res.body.error || `Detach failed (HTTP ${res.status})`, !res.ok);
    loadCloudAccounts();
  }

  async function attachTo(a, attachUrl, caseId) {
    const res = await send(attachUrl, "POST", { caseId });
    setMsg(res.ok ? `'${a.name}' attached to case ${caseId}.` : res.body.error || `Attach failed (HTTP ${res.status})`, !res.ok);
    loadCloudAccounts();
  }

  function shareAccount(a, url) {
    const target = prompt(`Share '${a.name}' with which case? Enter the case ID (you need write access to it).`);
    if (target && target.trim()) attachTo(a, `${url}/attach`, target.trim());
  }

  async function resetVault() {
    const ok = confirm(
      "Reset vault deletes EVERY cloud account and its stored credential. The key file and all case " +
        "evidence stay. Use it when the key file is lost and the accounts must be added again. Go ahead?",
    );
    if (!ok) return;
    const res = await fetch("/cloud-accounts/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    });
    const out = await readJson(res);
    if (!res.ok) setMsg(out.error || `Reset failed (HTTP ${res.status})`, true);
    else setMsg(`Vault reset: ${Number(out.removed) || 0} accounts deleted.`, false);
    loadCloudAccounts();
  }

  function initCloudAccounts() {
    if (!byId("cloudAccountsPanel")) return;
    byId("cloudAccountAddBtn").onclick = () => openForm(null, null);
    byId("cloudVaultResetBtn").onclick = resetVault;
    if (byId("cloudAccountsDeleteSelected")) byId("cloudAccountsDeleteSelected").onclick = deleteSelected;
    byId("caCancel").onclick = closeForm;
    if (byId("ccRun")) byId("ccRun").onclick = runCheck;
    if (byId("ccClose")) byId("ccClose").onclick = closeCheck;
    byId("cloudAccountForm").addEventListener("submit", saveForm);
    byId("caProvider").addEventListener("change", (e) => showProvider(e.target.value));
    document.querySelectorAll(".stab").forEach((tab) => {
      if (tab.dataset.stab === "integrations") tab.addEventListener("click", loadCloudAccounts);
    });
    loadCloudAccounts();
  }

  window.initCloudAccounts = initCloudAccounts;
  window.loadCloudAccounts = loadCloudAccounts;
})();
