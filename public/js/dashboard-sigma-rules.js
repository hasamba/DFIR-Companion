// Settings → Sigma rules (#2204): the SigmaHQ release the import-time engine runs, its settings,
// updates (check / preview / install / install from file / roll back), the disabled-rules list and
// per-rule exclusions (#2218).
//
// A CLASSIC SCRIPT, like every js/dashboard-*.js file. It wires itself once the page has loaded —
// its buttons, and its own tab button (to load the tab when opened) — so the frozen inline script in
// dashboard.html does not grow (#384 size ledger).
//
// Every string from the server is rendered with textContent, never innerHTML: a release installed
// from a file carries rule titles and reasons nobody vetted.

// The largest release zip the server accepts. Matches SIGMA_RELEASE_MAX_ZIP_BYTES in
// companion/src/analysis/sigmaReleaseArchive.ts; dashboardSigmaRules.test.ts pins the two together.
const SIGMA_MAX_ZIP_BYTES = 32 * 1024 * 1024;

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

// True in the public demo, where the server refuses every change (#2216). It reads the notice
// sigmaRenderStatus shows, so this file keeps no state. Every button that changes something uses it.
const SIGMA_DEMO_TITLE = "Not available in the public demo";
function sigmaDemoActive() {
  const n = document.getElementById("sigmaDemo");
  return !!n && !n.hidden;
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
    const why = sigmaEl("td", (r.reasons || []).join("; "));
    sigmaAppendExclusions(why, r);
    tr.appendChild(why);
    const act = document.createElement("td");
    if (r.outcome === "loaded") act.appendChild(sigmaRuleButton("Exclude…", () => sigmaExcludeRule(r.id)));
    if (r.outcome === "loaded" || r.outcome === "disabled")
      act.appendChild(sigmaRuleButton(r.outcome === "loaded" ? "Disable" : "Enable", () => sigmaToggleRule(r.id, r.outcome === "loaded")));
    tr.appendChild(act);
    body.appendChild(tr);
  }
  document.getElementById("sigmaRulesCount").textContent = `(${shown.length} rules for the log sources the Companion grades)`;
}

// A mini button for the rules table, disabled in the public demo (#2216).
function sigmaRuleButton(label, onClick) {
  const btn = sigmaEl("button", label, "btn-mini");
  btn.type = "button";
  btn.disabled = sigmaDemoActive();
  if (btn.disabled) btn.title = SIGMA_DEMO_TITLE;
  btn.addEventListener("click", onClick);
  return btn;
}

// #2218: each exclusion under its rule, as text, with a Remove button.
function sigmaAppendExclusions(cell, r) {
  for (const x of r.exclusions || []) {
    const line = sigmaEl("div", `${x.field} = ${x.value} — ${x.reason}`, "sfield-hint");
    line.appendChild(sigmaRuleButton("Remove", () => sigmaRemoveExclusion(r.id, x.field, x.value)));
    cell.appendChild(line);
  }
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
  btn.disabled = !p.usable || sigmaDemoActive();
  if (sigmaDemoActive()) btn.title = SIGMA_DEMO_TITLE;
  btn.addEventListener("click", sigmaInstall);
  box.appendChild(btn);
  sigmaAppendMeasure(box, p);
}

// #2209: "Measure against this case" beside Install, only with a case open. It runs the case's
// re-grade preview (#2206) with the staged release, on click only, and changes nothing.
function sigmaAppendMeasure(box, p) {
  if (!sigmaRegradeCaseId()) return;
  const btn = sigmaEl("button", "Measure against this case", "btn-mini");
  btn.type = "button";
  btn.disabled = !p.usable || sigmaDemoActive();
  if (sigmaDemoActive()) btn.title = SIGMA_DEMO_TITLE;
  btn.addEventListener("click", sigmaMeasureRelease);
  box.appendChild(btn);
}

async function sigmaMeasureRelease() {
  const preview = document.getElementById("sigmaPreview");
  const token = preview && preview.dataset.token;
  const caseId = sigmaRegradeCaseId();
  if (!token || !caseId || sigmaDemoActive()) return;
  sigmaMsg(`Measuring the release against ${caseId}…`);
  try {
    const url = `/cases/${encodeURIComponent(caseId)}/sigma/regrade?release=${encodeURIComponent(token)}`;
    sigmaRenderMeasure(await sigmaFetch(url));
    sigmaMsg("Measured. Nothing was changed.");
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

function sigmaMeasureLines(r) {
  if (!r.enabled) return r.notes || [];
  const files = r.files || [];
  if (!files.length) return [`This case has no CloudTrail, Entra, M365 or web log import — release ${r.release} cannot change it.`];
  const c = r.counts || {};
  const n = (k) => Number(c[k]) || 0;
  const skipped = files.filter((f) => f.status === "skipped").length;
  const lines = [
    `On this case, release ${r.release} would raise ${n("raised")} row(s), lower ${n("lowered")} and leave ${n("unchanged")} unchanged; ${n("entersForensic")} would join the forensic timeline and ${n("leavesForensic")} would leave it (scanned ${files.length - skipped} of ${files.length} Sigma-graded import(s)).`,
  ];
  if (skipped) lines.push(`${skipped} import(s) were not scanned — the stored file is missing or changed — so their rows are not counted.`);
  if (n("lowered")) lines.push("A lowered row loses only the Sigma grade: it never drops below the importer's own grade, and a row the analyst promoted stays in the forensic timeline.");
  return lines;
}

function sigmaRenderMeasure(r) {
  const box = document.getElementById("sigmaPreview");
  if (!box) return;
  // A second click replaces the earlier measure rather than stacking it.
  box.querySelector?.("[data-sigma-measure]")?.remove();
  const out = sigmaEl("div");
  out.dataset.sigmaMeasure = "1";
  for (const line of sigmaMeasureLines(r)) out.appendChild(sigmaEl("div", line));
  if (r.enabled) for (const note of r.notes || []) out.appendChild(sigmaEl("div", note, "sfield-hint"));
  out.appendChild(sigmaEl("div", "Nothing was changed. Install the release, then use Re-grade this case to apply it.", "sfield-hint"));
  box.appendChild(out);
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
  // Refuse before reading (#2213): base64-encoding a multi-GB file freezes or crashes the tab.
  if (file.size > SIGMA_MAX_ZIP_BYTES) {
    const mb = (file.size / 1048576).toFixed(1);
    return sigmaMsg(
      `${file.name} is ${mb} MB — too large for a SigmaHQ release zip (limit 32 MB). Choose sigma_all_rules.zip or a similar release file.`,
      true,
    );
  }
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
  if (sigmaDemoActive()) return;
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

async function sigmaPutExclusion(body) {
  await sigmaFetch("/sigma/exclusions", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// #2218: keep the rule on but skip one known-benign value. Applies from the next import only.
async function sigmaExcludeRule(id) {
  if (sigmaDemoActive()) return;
  const field = prompt("Exclude records by which field? (a field the rule's log source has, for example userIdentity.arn)", "");
  if (field === null || !field.trim()) return;
  const value = prompt(`Skip this rule when ${field.trim()} equals… (* and ? are wildcards; letter case is ignored)`, "");
  if (value === null || !value.trim()) return;
  const reason = prompt("Why is this value benign here? (shown next to the rule)", "known-benign in this environment");
  if (reason === null) return;
  try {
    await sigmaPutExclusion({ id, field: field.trim(), value: value.trim(), reason });
    sigmaMsg("Exclusion saved. It applies from the next import; events already imported keep their grading.");
    await loadSigmaRules();
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

async function sigmaRemoveExclusion(id, field, value) {
  if (sigmaDemoActive()) return;
  try {
    await sigmaPutExclusion({ id, field, value, remove: true });
    sigmaMsg("Exclusion removed. It applies from the next import; events already imported keep their grading.");
    await loadSigmaRules();
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

// #2206: re-grade the open case with the current rules. A preview first (it changes nothing), then
// an Apply button, disabled in the public demo like every other change here.
function sigmaRegradeCaseId() {
  const input = document.getElementById("caseId");
  return ((input && input.value) || "").trim();
}

const SIGMA_REGRADE_STATUS = {
  current: "already graded with the current rules",
  other: "graded with another release or setting",
  never: "never graded by Sigma",
  skipped: "skipped — the stored file is missing or changed",
};

function sigmaRegradeCountsText(c) {
  const parts = [`${Number(c.rows) || 0} row(s) graded by Sigma: ${Number(c.raised) || 0} raised, ${Number(c.lowered) || 0} lowered, ${Number(c.unchanged) || 0} unchanged`];
  if (c.tokenOnly) parts.push(`${c.tokenOnly} only re-stamped with the current release`);
  parts.push(`${Number(c.entersForensic) || 0} join the forensic timeline, ${Number(c.leavesForensic) || 0} leave it`);
  return `${parts.join("; ")}.`;
}

function sigmaRenderRegrade(r, caseId, applied) {
  const box = document.getElementById("sigmaRegrade");
  if (!box) return;
  box.textContent = "";
  box.hidden = false;
  if (!r.enabled) {
    for (const n of r.notes || []) box.appendChild(sigmaEl("div", n));
    return;
  }
  const c = r.counts || {};
  const head = applied
    ? `Re-graded with SigmaHQ ${r.release}.`
    : r.current
      ? `Already graded with the current rules (SigmaHQ ${r.release}). A re-grade changes nothing.`
      : `A re-grade with SigmaHQ ${r.release} would change:`;
  box.appendChild(sigmaEl("div", head));
  box.appendChild(sigmaEl("div", sigmaRegradeCountsText(c)));
  if (applied && r.demoted) box.appendChild(sigmaEl("div", `${r.demoted} row(s) left the forensic timeline; they stay in the super-timeline.`));
  for (const f of r.files || []) box.appendChild(sigmaEl("div", `${f.file} (${f.importer}): ${SIGMA_REGRADE_STATUS[f.status] || f.status}`, "sfield-hint"));
  for (const n of r.notes || []) box.appendChild(sigmaEl("div", n, "sfield-hint"));
  if (applied || !((Number(c.changed) || 0) + (Number(c.tokenOnly) || 0))) return;
  const btn = sigmaEl("button", "Apply re-grade", "btn-mini");
  btn.type = "button";
  btn.disabled = sigmaDemoActive();
  if (btn.disabled) btn.title = SIGMA_DEMO_TITLE;
  btn.addEventListener("click", () => sigmaRegradeApply(caseId));
  box.appendChild(btn);
}

async function sigmaRegradePreview() {
  const caseId = sigmaRegradeCaseId();
  if (!caseId) {
    sigmaMsg("Open a case to re-grade it.", true);
    return;
  }
  try {
    sigmaRenderRegrade(await sigmaFetch(`/cases/${encodeURIComponent(caseId)}/sigma/regrade`), caseId, false);
  } catch (e) {
    sigmaMsg(e.message, true);
  }
}

async function sigmaRegradeApply(caseId) {
  if (sigmaDemoActive()) return;
  try {
    const r = await sigmaFetch(`/cases/${encodeURIComponent(caseId)}/sigma/regrade`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    sigmaRenderRegrade(r, caseId, true);
    sigmaMsg("Re-grade done. No AI run started; the case's conclusions are marked out of date.");
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
  document.getElementById("sigmaRegradeBtn")?.addEventListener("click", sigmaRegradePreview);
  document.querySelectorAll("[data-sigma-status]").forEach((box) => box.addEventListener("change", sigmaStatusBoxChanged));
}

// Self-start, the way js/hunt-workbench.js does: guarded so a page-less test context loads it cleanly.
if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initSigmaRules, { once: true });
  else initSigmaRules();
}
