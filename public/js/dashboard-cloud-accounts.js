// Settings → Cloud accounts (#2307): the AWS accounts, Microsoft tenants and GCP projects that
// cloud collection will use, and the vault that keeps their credentials.
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

  let editing = null; // the account open in the form; null for a new one

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

  function keyLine(body) {
    const line = byId("cloudVaultKeyLine");
    if (!line) return;
    const where = body.keyPath || "(unknown)";
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

  function renderRow(a) {
    const row = el("div", null, "server-set-row");
    row.setAttribute("role", "listitem");
    row.appendChild(el("strong", a.name, "server-set-name"));
    row.appendChild(el("span", PROVIDER_LABELS[a.provider] || a.provider, "server-set-badge"));
    row.appendChild(el("span", summary(a), "server-set-meta"));
    if (a.locked) {
      const lock = el("span", a.locked, "server-set-meta");
      lock.style.color = "var(--badge-danger-text)";
      row.appendChild(lock);
    }
    const actions = el("span", null, "server-set-actions");
    if (!a.locked) actions.appendChild(button("Edit", () => openForm(a)));
    actions.appendChild(button("Delete", () => deleteAccount(a)));
    row.appendChild(actions);
    return row;
  }

  function button(label, onClick) {
    const b = el("button", label);
    b.type = "button";
    b.onclick = onClick;
    return b;
  }

  async function loadCloudAccounts() {
    const box = byId("cloudAccountsList");
    if (!box) return;
    let body;
    try {
      const res = await fetch("/cloud-accounts");
      body = await readJson(res);
      if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    } catch (e) {
      setMsg(`Cloud accounts cannot be loaded: ${e.message}`, true);
      return;
    }
    keyLine(body);
    const accounts = Array.isArray(body.accounts) ? body.accounts : [];
    box.replaceChildren(...accounts.map(renderRow));
    if (accounts.length === 0) box.appendChild(el("div", "No cloud accounts yet.", "server-set-meta"));
  }

  function showProvider(provider) {
    document.querySelectorAll("#cloudAccountForm [data-cloud-provider]").forEach((node) => {
      node.hidden = node.dataset.cloudProvider !== provider;
    });
  }

  function openForm(account) {
    editing = account;
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
    const url = editing ? `/cloud-accounts/${encodeURIComponent(editing.id)}` : "/cloud-accounts";
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

  async function deleteAccount(a) {
    if (!confirm(`Delete cloud account '${a.name}'? Its stored credential is erased.`)) return;
    const res = await fetch(`/cloud-accounts/${encodeURIComponent(a.id)}`, { method: "DELETE" });
    if (!res.ok) setMsg((await readJson(res)).error || `Delete failed (HTTP ${res.status})`, true);
    else setMsg("Deleted.", false);
    loadCloudAccounts();
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
    byId("cloudAccountAddBtn").onclick = () => openForm(null);
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
