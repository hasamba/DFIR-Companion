// Settings → Sigma rules (#2204): the SigmaHQ release the import-time engine runs, its settings,
// updates (check / preview / install / install from file / roll back) and the disabled-rules list.
//
// A CLASSIC SCRIPT, like every js/dashboard-*.js file. It wires itself once the page has loaded —
// its buttons, and its own tab button (to load the tab when opened) — so the frozen inline script in
// dashboard.html does not grow (#384 size ledger).
//
// Every string from the server is rendered with textContent, never innerHTML: a release installed
// from a file carries rule titles and reasons nobody vetted.

function sigmaEl(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (cls) el.className = cls;
  return el;
}

function sigmaMsg(text, isError) {
  const box = document.getElementById("sigmaMessage");
  if (!box) return;
  box.textContent = text || "";
  box.style.color = isError ? "var(--danger, #e5534b)" : "";
}

async function sigmaFetch(url, init) {
  const res = await fetch(url, init);
  let body = {};
  try {
    body = await res.json();
  } catch {
    body = {};
  }
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

function sigmaReleaseLine(r) {
  if (!r) return "none";
  const src = r.source === "bundled" ? "bundled with the Companion" : r.source === "github" ? "downloaded from GitHub" : "installed from a file";
  const verified = r.source === "file" ? " — not checked against GitHub" : r.verified ? " — SHA-256 verified" : "";
  const when = r.installedAt ? `, ${r.installedAt.slice(0, 10)}` : "";
  return `${r.release} (${src}${when}${verified})`;
}

// The statuses field is a plain env input the generic Settings save posts; the three checkboxes
// are a view of it, kept in step both ways.
function sigmaSyncStatusBoxes() {
  const input = document.getElementById("env-DFIR_SIGMA_RULE_STATUSES");
  if (!input) return;
  const set = new Set((input.value || "stable,test").split(",").map((s) => s.trim().toLowerCase()));
  document.querySelectorAll("[data-sigma-status]").forEach((box) => {
    box.checked = set.has(box.dataset.sigmaStatus);
  });
}

function sigmaStatusBoxChanged() {
  const input = document.getElementById("env-DFIR_SIGMA_RULE_STATUSES");
  if (!input) return;
  const picked = [...document.querySelectorAll("[data-sigma-status]")].filter((b) => b.checked).map((b) => b.dataset.sigmaStatus);
  input.value = picked.join(",");
}

function sigmaRenderStatus(s) {
  document.getElementById("sigmaActive").textContent = sigmaReleaseLine(s.active);
  document.getElementById("sigmaPrevious").textContent = s.previous ? sigmaReleaseLine(s.previous) : "none";
  const counts = document.getElementById("sigmaCounts");
  counts.textContent = "";
  for (const [src, row] of Object.entries(s.counts || {})) {
    if (src === "other") continue;
    const parts = Object.entries(row).map(([k, n]) => `${n} ${k === "status" ? "filtered by status" : k}`);
    counts.appendChild(sigmaEl("div", `${src}: ${parts.join(", ")}`));
  }
  const notes = [];
  if (!s.enabled) notes.push("Sigma grading is switched off (DFIR_SIGMA_RULES=off).");
  for (const p of s.problems || []) notes.push(p);
  const st = s.settings && s.settings.statuses;
  if (st && st.ignored && st.ignored.length) notes.push(`Ignored statuses: ${st.ignored.join(", ")} — only stable, test and experimental can be used.`);
  if (s.settings && s.settings.minLevel && s.settings.minLevel.invalid) notes.push(`"${s.settings.minLevel.invalid}" is not a level; using high.`);
  const lc = s.lastCheck;
  if (lc && lc.updateAvailable) notes.push(`New Sigma release available: ${lc.latest}. Use Check for updates to preview it.`);
  const box = document.getElementById("sigmaNotes");
  box.textContent = "";
  for (const n of notes) box.appendChild(sigmaEl("div", n));
  const demo = !!s.demoMode;
  ["sigmaCheckBtn", "sigmaFileBtn", "sigmaRollbackBtn"].forEach((id) => {
    const b = document.getElementById(id);
    if (b) b.disabled = demo || (id === "sigmaRollbackBtn" && !s.previous);
  });
  document.getElementById("sigmaDemo").hidden = !demo;
}

function sigmaRenderRules(list) {
  const body = document.getElementById("sigmaRulesBody");
  body.textContent = "";
  const shown = list.filter((r) => r.source);
  for (const r of shown) {
    const tr = document.createElement("tr");
    tr.appendChild(sigmaEl("td", r.title));
    tr.appendChild(sigmaEl("td", r.source));
    const outcome = r.outcome === "status" ? "filtered by status" : r.outcome === "disabled" ? `disabled (${r.disabledBy || "analyst"})` : r.outcome;
    tr.appendChild(sigmaEl("td", outcome));
    tr.appendChild(sigmaEl("td", (r.reasons || []).join("; ")));
    const act = document.createElement("td");
    if (r.outcome === "loaded" || r.outcome === "disabled") {
      const btn = sigmaEl("button", r.outcome === "loaded" ? "Disable" : "Enable", "btn-mini");
      btn.type = "button";
      btn.addEventListener("click", () => sigmaToggleRule(r.id, r.outcome === "loaded"));
      act.appendChild(btn);
    }
    tr.appendChild(act);
    body.appendChild(tr);
  }
  document.getElementById("sigmaRulesCount").textContent = `(${shown.length} rules for the log sources the Companion grades)`;
}

async function loadSigmaRules() {
  sigmaSyncStatusBoxes();
  try {
    sigmaRenderStatus(await sigmaFetch("/sigma/status"));
    sigmaRenderRules((await sigmaFetch("/sigma/rules")).rules || []);
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

function sigmaRenderPreview(p) {
  const box = document.getElementById("sigmaPreview");
  box.textContent = "";
  box.hidden = false;
  // The token lives on the preview itself, so this file holds no state of its own.
  box.dataset.token = p.token;
  box.appendChild(sigmaEl("div", `Release: ${sigmaReleaseLine(p.release)}`));
  box.appendChild(sigmaEl("div", `SHA-256: ${p.release.sha256 || "—"}`));
  const d = p.diff;
  box.appendChild(sigmaEl("div", `For the log sources the Companion grades: ${d.added.length} added, ${d.changed.length} changed, ${d.removed.length} removed. ${d.otherSources} rules for other log sources are not compared.`));
  const loads = Object.entries(p.loads || {}).map(([k, n]) => `${k} ${n}`).join(", ");
  box.appendChild(sigmaEl("div", `Rules that would load with the current settings: ${loads || "none"}`));
  for (const [label, items] of [["Added", d.added], ["Changed", d.changed], ["Removed", d.removed]]) {
    if (!items.length) continue;
    const det = document.createElement("details");
    det.appendChild(sigmaEl("summary", `${label} (${items.length})`));
    const ul = document.createElement("ul");
    for (const r of items) ul.appendChild(sigmaEl("li", r.title));
    det.appendChild(ul);
    box.appendChild(det);
  }
  for (const pr of p.problems || []) box.appendChild(sigmaEl("div", pr, "sfield-hint"));
  const btn = sigmaEl("button", "Install this release", "btn-mini");
  btn.type = "button";
  btn.disabled = !p.usable;
  btn.addEventListener("click", sigmaInstall);
  box.appendChild(btn);
}

async function sigmaCheck() {
  sigmaMsg("Checking SigmaHQ for a newer release…");
  try {
    const r = await sigmaFetch("/sigma/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    if (!r.check.updateAvailable) sigmaMsg(`Up to date: the latest SigmaHQ release is ${r.check.latest}.`);
    else {
      sigmaMsg(`Release ${r.check.latest} is available. Review the changes below; nothing is installed until you click Install.`);
      sigmaRenderPreview(r.preview);
    }
    await loadSigmaRules();
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

function sigmaBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

async function sigmaInstallFile() {
  const input = document.getElementById("sigmaFile");
  const file = input && input.files && input.files[0];
  if (!file) return sigmaMsg("Choose a SigmaHQ release zip first (for example sigma_all_rules.zip).", true);
  sigmaMsg(`Reading ${file.name}…`);
  try {
    const zipBase64 = sigmaBase64(await file.arrayBuffer());
    const r = await sigmaFetch("/sigma/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: "file", name: file.name, zipBase64 }),
    });
    sigmaMsg(`Review ${file.name} below; nothing is installed until you click Install.`);
    sigmaRenderPreview(r.preview);
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

async function sigmaInstall() {
  const preview = document.getElementById("sigmaPreview");
  const token = preview && preview.dataset.token;
  if (!token) return;
  try {
    const r = await sigmaFetch("/sigma/install", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    delete preview.dataset.token;
    preview.hidden = true;
    sigmaMsg(`Installed ${r.active.release}. It grades the next import; existing cases keep their grading.`);
    await loadSigmaRules();
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

async function sigmaRollback() {
  if (!confirm("Switch back to the previous Sigma release? It grades the next import; existing cases keep their grading.")) return;
  try {
    const r = await sigmaFetch("/sigma/rollback", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    sigmaMsg(`Rolled back to ${r.active.release}.`);
    await loadSigmaRules();
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

async function sigmaToggleRule(id, disable) {
  let reason = "";
  if (disable) {
    reason = prompt("Why switch this rule off? (shown next to it)", "noisy in this environment");
    if (reason === null) return;
  }
  try {
    await sigmaFetch("/sigma/disabled", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, disabled: disable, reason }),
    });
    await loadSigmaRules();
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

function initSigmaRules() {
  // Load the tab when its own button is clicked (a listener, not a deep link — see openSettingsTab).
  document.querySelectorAll(".stab").forEach((b) => {
    if (b.dataset.stab === "sigma") b.addEventListener("click", loadSigmaRules);
  });
  document.getElementById("sigmaCheckBtn")?.addEventListener("click", sigmaCheck);
  document.getElementById("sigmaFileBtn")?.addEventListener("click", sigmaInstallFile);
  document.getElementById("sigmaRollbackBtn")?.addEventListener("click", sigmaRollback);
  document.querySelectorAll("[data-sigma-status]").forEach((box) => box.addEventListener("change", sigmaStatusBoxChanged));
}

// Self-start, the way js/hunt-workbench.js does: guarded so a page-less test context loads it cleanly.
if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initSigmaRules, { once: true });
  else initSigmaRules();
}
