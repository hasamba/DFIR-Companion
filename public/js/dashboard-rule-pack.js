// Super-Timeline → Content tagger → Rule pack (#2349): the detection rules released separately from
// the app as `rules-*` GitHub releases.
//
// Shows which rules are in use (the rules bundled with the app, an installed pack — downloaded or
// installed from a file — or an analyst-edited copy based on one), and offers:
//   - Check for updates: the newest pack this app can load, downloaded from GitHub's release hosts
//     and checked against GitHub's SHA-256 and the pack's own manifest, then a review of the rules
//     it adds, changes and removes. Nothing installs until Install is clicked.
//   - Install from file: the same review for an offline lab, marked "not checked against GitHub".
//   - Measure against this case: rows of the open case the pack would grade or tag differently.
//     Changes nothing.
//   - Roll back: to the previous pack, or to the bundled rules.
// After an install, open cases keep their grades until Run tagger is pressed, and it says so.
//
// A CLASSIC SCRIPT that self-starts once the page is parsed. Every string is rendered with
// textContent: pack names, rule keys and descriptions come from downloaded or uploaded files.

let rulePackReview = null;

function rpEl(tag, text, css) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (css) el.style.cssText = css;
  return el;
}

function rpBtn(text, onClick, title, disabled) {
  const b = rpEl("button", text);
  b.className = "ev-bulk-btn";
  if (title) b.title = title;
  if (disabled) b.disabled = true;
  b.onclick = onClick;
  return b;
}

function rpMsg(text, bad) {
  const el = document.getElementById("rulePackMsg");
  if (!el) return;
  el.textContent = text || "";
  el.style.color = bad ? "var(--badge-danger-text)" : "var(--text-muted)";
}

async function rpPost(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
  const d = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, d };
}

function rpOriginText(pack) {
  if (!pack) return "";
  if (pack.origin === "file") return `installed from a file — not checked against GitHub (SHA-256 ${String(pack.rulesSha256 || "").slice(0, 12)}…)`;
  return "downloaded from GitHub, SHA-256 checked";
}

function rpSourcesText(pack) {
  const s = (pack && pack.sources) || [];
  return s.length ? "Upstream sources: " + s.map((x) => `${x.name} @ ${String(x.commit).slice(0, 10)} (${x.date})`).join("; ") : "";
}

async function loadRulePack() {
  const panel = document.getElementById("rulePackPanel");
  if (!panel) return;
  try {
    const r = await fetch("/tagger/pack");
    // 403: not an administrator in team mode; 501: not configured. Neither sees the panel.
    if (!r.ok) { panel.hidden = true; if (window.DfirDetectionRules) window.DfirDetectionRules.drSetTagger(null); return; }
    renderRulePackStatus(await r.json());
    panel.hidden = false;
  } catch (e) {
    panel.hidden = true;
  }
}

function renderRulePackStatus(st) {
  const box = document.getElementById("rulePackStatus");
  if (!box) return;
  box.textContent = "";
  box.appendChild(rpEl("strong", "Rule pack: ", ""));
  box.appendChild(rpEl("span", st.activeRules ? `in use — ${st.activeRules}` : "the rules bundled with the app", ""));
  if (st.installed) {
    box.appendChild(rpEl("div", `Installed pack: ${st.installed.version}, ${st.installed.ruleCount} rule(s), ${rpOriginText(st.installed)}`, "font-size:11px;color:var(--text-muted)"));
    const src = rpSourcesText(st.installed);
    if (src) box.appendChild(rpEl("div", src, "font-size:11px;color:var(--text-muted)"));
  }
  if (st.problem) box.appendChild(rpEl("div", st.problem, "font-size:11px;color:var(--warning-bg-strong)"));
  if (st.lastCheck && st.lastCheck.status === "update") box.appendChild(rpEl("div", st.lastCheck.message, "font-size:11px;color:var(--warning-bg-strong)"));
  const bar = rpEl("div", null, "display:flex;gap:6px;flex-wrap:wrap;margin-top:4px");
  const off = !!st.demoMode;
  const why = off ? "The public demo does not download or install rule packs" : "";
  bar.appendChild(rpBtn("Check for updates", checkRulePack, why || "Find the newest rule pack this app can load and review it — nothing installs until you click Install", off));
  bar.appendChild(rpBtn("Install from file", chooseRulePackFile, why || "Review a pack's tags.yaml (and its rule-pack-manifest.json) from disk — for an offline lab", off));
  if (st.previous) bar.appendChild(rpBtn(`Roll back to ${st.previous.version}`, () => rollbackRulePack("previous"), why || "Make the previous pack the installed one", off));
  if (st.installed) bar.appendChild(rpBtn("Roll back to bundled rules", () => rollbackRulePack("bundled"), why || "Stop using the installed pack; the rules bundled with the app are used", off));
  box.appendChild(bar);
  if (off) box.appendChild(rpEl("div", "Rule pack downloads are disabled in the public demo.", "font-size:11px;color:var(--text-muted)"));
  // #2389: the one-line summary of the Detection rules box.
  if (window.DfirDetectionRules) window.DfirDetectionRules.drSetTagger(st);
}

async function checkRulePack() {
  rpMsg("Checking GitHub for a newer rule pack…");
  try {
    const { ok, d } = await rpPost("/tagger/pack/check");
    if (!ok) { rpMsg("Check failed: " + (d.error || "unknown error") + " Nothing was installed.", true); return; }
    rpMsg(d.check ? d.check.message : "");
    if (d.review) renderRulePackReview(d.review);
    else closeRulePackReview();
  } catch (e) {
    rpMsg("Check failed: " + e.message, true);
  }
}

function chooseRulePackFile() {
  const input = document.createElement("input");
  input.type = "file";
  input.multiple = true;
  input.accept = ".yaml,.yml,.json";
  input.onchange = () => installRulePackFromFiles(Array.from(input.files || []));
  input.click();
}

async function installRulePackFromFiles(files) {
  const rules = files.find((f) => /\.ya?ml$/i.test(f.name));
  const manifest = files.find((f) => /\.json$/i.test(f.name));
  if (!rules) { rpMsg("Choose the pack's tags.yaml (and, if you have it, rule-pack-manifest.json).", true); return; }
  try {
    const body = { name: rules.name, rulesText: await rules.text() };
    if (manifest) body.manifestText = await manifest.text();
    const { ok, d } = await rpPost("/tagger/pack/file", body);
    if (!ok) { rpMsg("Refused: " + (d.error || "unknown error") + " Nothing was installed.", true); return; }
    rpMsg(manifest ? "" : "No manifest chosen: the pack has no version or minimum app version, only the file's SHA-256.");
    renderRulePackReview(d.review);
  } catch (e) {
    rpMsg("Could not read the file: " + e.message, true);
  }
}

function rpRuleLine(key, side) {
  const s = side || {};
  return `${key} · ${s.severity || "no grade"}${s.description ? " — " + s.description : ""}`;
}

function rpGroup(pane, title, items, sideOf) {
  if (!items || !items.length) return;
  pane.appendChild(rpEl("div", `${title} (${items.length})`, "font-weight:600;margin-top:6px"));
  for (const i of items) pane.appendChild(rpEl("div", rpRuleLine(i.key, sideOf(i)), "padding-left:8px"));
}

function renderRulePackReview(review) {
  rulePackReview = review;
  const pane = document.getElementById("rulePackReview");
  if (!pane) return;
  pane.textContent = "";
  const p = review.pack;
  pane.appendChild(rpEl("div", `Rule pack ${p.version} — ${p.ruleCount} rule(s), ${rpOriginText(p)}`, "font-weight:600"));
  const src = rpSourcesText(p);
  if (src) pane.appendChild(rpEl("div", src, "font-size:11px;color:var(--text-muted)"));
  const c = review.counts || {};
  pane.appendChild(rpEl("div", `Compared with ${review.comparedWith}: ${c.added || 0} added, ${c.changed || 0} changed, ${c.removed || 0} removed.`, ""));
  if (review.activeSource === "user") {
    pane.appendChild(rpEl("div", "You run your own edited rules. They stay active: after installing, the pack's added and changed rules are offered in the rule-updates review above, and your edits are kept.", "color:var(--text-muted)"));
  } else if (review.activeSource === "env") {
    pane.appendChild(rpEl("div", "An operator rules file (TAGGER_RULES_FILE) is active and stays active after installing.", "color:var(--text-muted)"));
  }
  rpGroup(pane, "Added", review.added, (i) => i.upstream);
  rpGroup(pane, "Changed", review.changed, (i) => i.upstream);
  rpGroup(pane, "Removed", review.removed, (i) => i.rule);
  const bar = rpEl("div", null, "display:flex;gap:6px;flex-wrap:wrap;margin-top:8px");
  bar.appendChild(rpBtn("Measure against this case", measureRulePack, "Count the rows of the open case this pack would grade or tag differently — nothing is changed"));
  bar.appendChild(rpBtn("Install", installRulePack, "Make this pack the installed rule pack"));
  bar.appendChild(rpBtn("Cancel", closeRulePackReview, "Close the review; nothing is installed"));
  pane.appendChild(bar);
  pane.appendChild(rpEl("div", "", "margin-top:4px")).id = "rulePackMeasure";
  pane.hidden = false;
}

function closeRulePackReview() {
  rulePackReview = null;
  const pane = document.getElementById("rulePackReview");
  if (pane) { pane.textContent = ""; pane.hidden = true; }
}

async function measureRulePack() {
  if (!rulePackReview) return;
  const out = document.getElementById("rulePackMeasure");
  const caseId = typeof superCaseId === "function" ? superCaseId() : "";
  if (!caseId) { if (out) out.textContent = "Open a case first."; return; }
  if (out) out.textContent = "Measuring…";
  const { ok, d } = await rpPost("/tagger/pack/measure", { token: rulePackReview.token, caseId });
  if (!out) return;
  if (!ok) { out.textContent = "Measure failed: " + (d.error || "unknown error"); return; }
  out.textContent =
    `Against ${d.comparedWith}, over ${d.scanned} row(s): ${d.raised} would be raised, ${d.intoForensic} would enter the forensic timeline, ` +
    `${d.noLongerRaised} would no longer be raised, ${d.wouldStayOut} would stay out of the forensic timeline, ${d.tagsChanged} would be tagged differently. ` +
    d.note;
}

async function installRulePack() {
  if (!rulePackReview) return;
  const { ok, d } = await rpPost("/tagger/pack/install", { token: rulePackReview.token });
  if (!ok) { rpMsg("Install failed: " + (d.error || "unknown error"), true); return; }
  closeRulePackReview();
  rpMsg(`Installed rule pack ${d.installed.version}. Open cases keep their current grades until you press Run tagger.`);
  const msg = document.getElementById("rulePackMsg");
  if (msg && typeof runTagger === "function") msg.appendChild(rpBtn("Run tagger", () => runTagger(), "Re-grade the open case with the active rules"));
  await loadRulePack();
  if (typeof loadTaggerUpdates === "function") loadTaggerUpdates();
}

async function rollbackRulePack(to) {
  const label = to === "bundled" ? "the rules bundled with the app" : "the previous rule pack";
  if (typeof confirm === "function" && !confirm(`Roll back to ${label}? Open cases keep their grades until Run tagger is pressed.`)) return;
  const { ok, d } = await rpPost("/tagger/pack/rollback", { to });
  if (!ok) { rpMsg("Roll back failed: " + (d.error || "unknown error"), true); return; }
  rpMsg(`Rolled back to ${d.installed ? "rule pack " + d.installed.version : label}. Open cases keep their current grades until you press Run tagger.`);
  await loadRulePack();
  if (typeof loadTaggerUpdates === "function") loadTaggerUpdates();
}

window.DfirRulePack = {
  loadRulePack,
  renderRulePackStatus,
  checkRulePack,
  chooseRulePackFile,
  installRulePackFromFiles,
  renderRulePackReview,
  measureRulePack,
  installRulePack,
  rollbackRulePack,
};

// Self-start once the page is parsed; guarded so a page-less test context loads it cleanly.
if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loadRulePack, { once: true });
  else loadRulePack();
}
