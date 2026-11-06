// Settings → Cloud accounts (#2307, per case since #2308): the AWS accounts, Microsoft tenants and
// GCP projects that cloud collection will use, and the vault that keeps their credentials.
//
// Accounts belong to cases. The main list is the open case's accounts (/cases/<id>/cloud-accounts,
// which needs write on the case). An instance administrator also sees every account with its cases
// (/cloud-accounts) — including accounts added before #2308, which have no case until attached.
// On the public demo every cloud route answers 403 with `demo: true`, and the panel hides itself.
//
// The server never sends a stored credential back — only the NAMES of the secrets an account holds.
// An empty secret field on Edit keeps the stored value; typing a new value replaces it (rotation).
// Account names come from analysts, so every one is written with textContent, never innerHTML.
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

  // The account open in the form and where it was opened from: { account, url } — `url` is the
  // account's own route (case or instance-wide). null for a new account.
  let editing = null;

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

  function accountRow(a, metaText) {
    const row = el("div", null, "server-set-row");
    row.setAttribute("role", "listitem");
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
    actions.appendChild(button("Share with case…", () => shareAccount(a, url)));
    actions.appendChild(button("Detach", () => detachAccount(a, url, caseId)));
    actions.appendChild(button("Delete", () => deleteAccount(a, url)));
    row.appendChild(actions);
    return row;
  }

  // One account in the administrator's instance-wide list: its cases, Attach to this case, Edit, Delete.
  function renderAdminRow(a, caseId) {
    const cases = (a.caseIds || []).length ? `Cases: ${a.caseIds.join(", ")}` : "Not attached to a case";
    const row = accountRow(a, cases);
    const url = `/cloud-accounts/${encodeURIComponent(a.id)}`;
    const actions = el("span", null, "server-set-actions");
    if (caseId && !(a.caseIds || []).includes(caseId))
      actions.appendChild(button("Attach to this case", () => attachTo(a, `${url}/attach`, caseId)));
    if (!a.locked) actions.appendChild(button("Edit", () => openForm(a, url)));
    actions.appendChild(button("Delete", () => deleteAccount(a, url)));
    row.appendChild(actions);
    return row;
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

  function renderAdminList(caseId, res) {
    const section = byId("cloudAccountsAll");
    const box = byId("cloudAccountsAllList");
    const reset = byId("cloudVaultResetBtn");
    if (reset) reset.hidden = !res.ok;
    if (!section || !box) return;
    section.hidden = !res.ok;
    if (!res.ok) return;
    const accounts = Array.isArray(res.body.accounts) ? res.body.accounts : [];
    box.replaceChildren(...accounts.map((a) => renderAdminRow(a, caseId)));
    if (accounts.length === 0) box.appendChild(el("div", "No cloud accounts yet.", "server-set-meta"));
  }

  async function loadCloudAccounts() {
    const box = byId("cloudAccountsList");
    if (!box) return;
    const caseId = currentCaseId();
    const inCase = caseId ? await getJson(caseBase(caseId)) : { ok: false, status: 0, body: {} };
    // The instance-wide list answers only an instance administrator (403 for everyone else).
    const all = await getJson("/cloud-accounts");
    if (inCase.body.demo || all.body.demo) return hidePanel();
    setMsg("", false);
    keyLine(all.ok ? all.body : inCase.body);
    renderCaseList(box, caseId, inCase);
    renderAdminList(caseId, all);
    const add = byId("cloudAccountAddBtn");
    if (add) add.disabled = !caseId && !all.ok;
  }

  function showProvider(provider) {
    document.querySelectorAll("#cloudAccountForm [data-cloud-provider]").forEach((node) => {
      node.hidden = node.dataset.cloudProvider !== provider;
    });
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
    if (!confirm(`Delete cloud account '${a.name}'? Its stored credential is erased for every case it is attached to.`))
      return;
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
    byId("caCancel").onclick = closeForm;
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
