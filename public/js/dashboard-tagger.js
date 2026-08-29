// The AI tagger-rule feature, lifted whole out of dashboard.html's inline script (#415, tier 3).
//
// TWELVE FUNCTIONS, THE WHOLE FEATURE, AND THAT IS THE POINT. Tier 3 is the 231 bindings that look
// global only because the page shares one scope, and the tempting move is to extract whichever
// functions happen to qualify. Measuring first showed why that is a trap: of fourteen features
// examined, eleven would land in TWO places — velociraptor 15 movable against 27 not, mcp 13/14,
// report templates 47/39 — because a feature is usually part standalone and part entangled with the
// shared filter state. Half a feature in a module is worse than none: the reader now has to know
// which half is where.
//
// The tagger is one of the two features measured as wholly movable (KEV is the other). It touches
// no shared dashboard state at all — every one of these reads the DOM, calls the server, and writes
// the DOM back. So it moves as a unit or not at all, and it moves as a unit.
//
// A CLASSIC SCRIPT, like the eight helper modules and js/dashboard-state.js. Two reasons, and the
// second is specific to tier 3:
//
//   1. the inline script still calls runTagger() and refreshTaggerRuleList() by bare name, and a
//      classic script's top-level declarations are globals. See js/dashboard-escape.js.
//   2. every entry point here is reached through the ACTIONS dispatch table, which is built as
//      `toggleTaggerSuggest: (el) => toggleTaggerSuggest()` — an arrow, so the name resolves at
//      CLICK time rather than when the table is built. That is what lets a feature move out without
//      editing a single dispatch entry, and it is worth knowing before the next feature moves.
//
// esc/escAttr come from js/dashboard-escape.js and resolve as globals at call time.

// ── Content-based tagger (Timesketch tagger analyzer, ported) ────────────────────────────────
// Run the rules over the whole case, tagging matching events; report per-rule match counts.
async function runTagger() {
  const caseId = superCaseId();
  if (!caseId) return;
  const msg = document.getElementById("taggerMsg");
  msg.style.color = "var(--text-muted)";
  msg.textContent = "Running tagger…";
  try {
    const r = await fetch(`/cases/${caseId}/tagger/run`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const d = await r.json();
    if (!r.ok) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Tagger error: " + (d.error || r.status); return; }
    const hits = (d.perRule || []).filter(x => x.matched > 0).sort((a, b) => b.matched - a.matched);
    const top = hits.slice(0, 6).map(x => `${x.id}: ${x.matched}`).join(", ");
    msg.style.color = "var(--text-muted)";
    msg.textContent = `Tagged ${d.totalMatched} event(s), +${d.tagsWritten} tag(s)`
      + (d.mutatedCount ? `, ${d.mutatedCount} severity/MITRE update(s)` : "")
      + ` [scope: ${d.scope}]` + (top ? " — " + top + (hits.length > 6 ? ", …" : "") : "");
    if (typeof loadTags === "function") loadTags(caseId);
    if (typeof loadSuperTimeline === "function") loadSuperTimeline(caseId);
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Tagger failed: " + e.message; }
}

// ── NL → rule (PR #112 follow-up) ──────────────────────────────────────────
async function suggestTaggerRule() {
  const caseId = document.getElementById("caseId").value.trim();
  const desc = document.getElementById("taggerSuggestInput").value.trim();
  const msg = document.getElementById("taggerSuggestMsg");
  if (!caseId) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Connect to a case first."; return; }
  if (!desc) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Describe the rule first."; return; }
  const btn = document.getElementById("taggerSuggestBtn");
  btn.disabled = true;
  msg.style.color = "var(--text-muted)";
  msg.textContent = "Drafting… (one AI call)";
  try {
    const r = await fetch(`/cases/${caseId}/tagger/suggest-rule`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ description: desc }),
    });
    const d = await r.json();
    if (!r.ok || d.error) {
      const hint = /501/.test(String(r.status)) ? " — AI provider not configured (Settings → AI)" : "";
      msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Suggest error: " + (d.error || r.status) + hint; return;
    }
    const result = document.getElementById("taggerSuggestResult");
    const explain = document.getElementById("taggerSuggestExplain");
    const yaml = document.getElementById("taggerSuggestYaml");
    if (d.kind === "decline") {
      result.hidden = true;
      msg.style.color = "var(--warning-bg-strong)"; msg.textContent = "Can't make a rule: " + d.reason;
      return;
    }
    msg.textContent = "";
    explain.textContent = d.explanation || "";
    yaml.value = d.ruleYaml || "";
    document.getElementById("taggerSuggestResultMsg").textContent = "";
    result.hidden = false;
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Suggest failed: " + e.message; }
  finally { btn.disabled = false; }
}

async function previewTaggerRule() {
  const caseId = document.getElementById("caseId").value.trim();
  const ruleYaml = document.getElementById("taggerSuggestYaml").value;
  const msg = document.getElementById("taggerSuggestResultMsg");
  const matchBox = document.getElementById("taggerSuggestMatches");
  matchBox.hidden = true; matchBox.innerHTML = "";
  if (!caseId) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Connect to a case first."; return; }
  msg.style.color = "var(--text-muted)"; msg.textContent = "Checking…";
  try {
    const r = await fetch(`/cases/${caseId}/tagger/preview`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ruleYaml }),
    });
    const d = await r.json();
    if (!r.ok || d.error) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Invalid rule: " + (d.error || r.status); return; }
    msg.style.color = d.matched > 0 ? "var(--text-muted)" : "var(--warning-bg-strong)";
    msg.textContent = `Would match ${d.matched} event(s) in this case${d.scope ? " (scope: " + d.scope + ")" : ""}.`;
    // Show the actual matching events (a capped sample) so the analyst can see WHAT it covers.
    const sample = d.sample || [];
    if (sample.length) {
      const header = document.createElement("div");
      header.style.cssText = "color:var(--text-bright);margin-bottom:4px";
      header.textContent = `Matching events${d.matched > sample.length ? ` (showing first ${sample.length} of ${d.matched})` : ""}:`;
      matchBox.appendChild(header);
      sample.forEach((ev) => {
        const row = document.createElement("div");
        row.style.cssText = "padding:1px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis";
        const ts = (ev.timestamp || "").replace("T", " ").replace(/\.\d+Z$/, "Z");
        row.textContent = `${ts}  ${ev.asset ? "[" + ev.asset + "] " : ""}${ev.description || ev.id}`;
        row.title = ev.description || ev.id;
        matchBox.appendChild(row);
      });
      matchBox.hidden = false;
    }
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Check failed: " + e.message; }
}

// Toggle the AI rule-authoring + rule-management pane (collapsed by default; opened from the toolbar).
function toggleTaggerSuggest() {
  const wrap = document.getElementById("taggerSuggestWrap");
  if (!wrap) return;
  wrap.hidden = !wrap.hidden;
  if (!wrap.hidden) refreshTaggerRuleList();
}

async function addSuggestedTaggerRule() {
  const ruleYaml = document.getElementById("taggerSuggestYaml").value;
  const msg = document.getElementById("taggerSuggestResultMsg");
  msg.style.color = "var(--text-muted)"; msg.textContent = "Adding…";
  try {
    const r = await fetch(`/tagger/rules/add`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ruleYaml }),
    });
    const d = await r.json();
    if (!r.ok || d.error) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Add error: " + (d.error || r.status); return; }
    msg.style.color = "var(--success-bg)"; msg.textContent = `Added rule "${d.id}" — ${d.ruleCount} rule(s) total.`;
    discardSuggestedTaggerRule();
    refreshTaggerRuleList();
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Add failed: " + e.message; }
}

function discardSuggestedTaggerRule() {
  document.getElementById("taggerSuggestResult").hidden = true;
  document.getElementById("taggerSuggestYaml").value = "";
  document.getElementById("taggerSuggestInput").value = "";
  const matchBox = document.getElementById("taggerSuggestMatches");
  if (matchBox) { matchBox.hidden = true; matchBox.innerHTML = ""; }
}

async function refreshTaggerRuleList() {
  const rows = document.getElementById("taggerRuleRows");
  const msg = document.getElementById("taggerRuleListMsg");
  if (!rows) return;
  try {
    const r = await fetch(`/tagger/rules`);
    const d = await r.json();
    if (!r.ok || d.error) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = d.error || ("error " + r.status); return; }
    msg.style.color = "var(--text-muted)";
    msg.textContent = `${d.ruleCount} rule(s) · source: ${d.source}`;
    const readonly = d.source === "env";
    rows.innerHTML = "";
    (d.rules || []).forEach((rule) => {
      const row = document.createElement("div");
      row.style.cssText = "display:flex;gap:6px;align-items:center;padding:2px 0;border-bottom:1px solid var(--border-color)";
      const label = document.createElement("span");
      label.style.cssText = "flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
      label.textContent = `${rule.id}${rule.severity ? " · " + rule.severity : ""}${rule.description ? " — " + rule.description : ""}`;
      row.appendChild(label);
      if (!readonly) {
        const btn = document.createElement("button");
        btn.className = "ev-bulk-btn"; btn.textContent = "✕";
        btn.title = "Remove this rule";
        btn.onclick = () => removeTaggerRule(rule.id);
        row.appendChild(btn);
      }
      rows.appendChild(row);
    });
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "list failed: " + e.message; }
}

async function removeTaggerRule(ruleId) {
  if (!confirm(`Remove the rule "${ruleId}"? (Reset to defaults restores all shipped rules.)`)) return;
  const msg = document.getElementById("taggerRuleListMsg");
  try {
    const r = await fetch(`/tagger/rules/${encodeURIComponent(ruleId)}`, { method: "DELETE" });
    const d = await r.json();
    if (!r.ok || d.error) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Remove error: " + (d.error || r.status); return; }
    refreshTaggerRuleList();
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Remove failed: " + e.message; }
}

async function resetTaggerRules() {
  if (!confirm("Discard ALL rule customizations (AI-added rules, manual edits, and removals) and restore the shipped default rules?")) return;
  const msg = document.getElementById("taggerRuleListMsg");
  try {
    const r = await fetch(`/tagger/rules/reset`, { method: "POST" });
    const d = await r.json();
    if (!r.ok || d.error) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Reset error: " + (d.error || r.status); return; }
    refreshTaggerRuleList();
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Reset failed: " + e.message; }
}

async function clearTaggerTags() {
  const caseId = superCaseId();
  if (!caseId) return;
  if (!confirm("Remove every tag applied by the tagger? (Your manual analyst tags are kept.)")) return;
  const msg = document.getElementById("taggerMsg");
  try {
    const r = await fetch(`/cases/${caseId}/tagger/clear`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const d = await r.json();
    if (!r.ok) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Clear error: " + (d.error || r.status); return; }
    msg.style.color = "var(--text-muted)";
    msg.textContent = `Removed ${d.removed} tagger tag(s).`;
    if (typeof loadTags === "function") loadTags(caseId);
    if (typeof loadSuperTimeline === "function") loadSuperTimeline(caseId);
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Clear failed: " + e.message; }
}

// The revision of the text currently sitting in the editor box. Sent back on save so the server can
// refuse a submission that would delete a rule somebody else added while this editor was open. Set
// ONLY when the box is filled from the server — never after a structural add/remove/reset, because
// the box still holds the pre-edit text at that point and silently freshening this would hand back
// exactly the overwrite it exists to prevent. The 409 is the safety net for that case.
let taggerRulesRevision = "";

async function toggleTaggerRules() {
  const pane = document.getElementById("taggerRulesPane");
  if (!pane.hidden) { pane.hidden = true; return; }
  pane.hidden = false;
  const msg = document.getElementById("taggerRulesMsg");
  msg.textContent = "";
  try {
    const r = await fetch(`/tagger/rules`);
    const d = await r.json();
    document.getElementById("taggerRulesText").value = d.text || "";
    taggerRulesRevision = d.revision || "";
    document.getElementById("taggerRulesSource").textContent =
      (d.source || "default") + (d.error ? ` (current file invalid: ${d.error})` : ` — ${d.ruleCount} rule(s)`);
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Failed to load rules: " + e.message; }
  refreshTaggerRuleList();
}

async function saveTaggerRules() {
  const msg = document.getElementById("taggerRulesMsg");
  const text = document.getElementById("taggerRulesText").value;
  msg.style.color = "var(--text-muted)";
  msg.textContent = "Saving…";
  try {
    const r = await fetch(`/tagger/rules`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text, revision: taggerRulesRevision }),
    });
    const d = await r.json();
    if (r.status === 409) {
      // Somebody else changed the rules while this box was open. Saving would delete their change,
      // so say what happened and what to do rather than reporting a generic rejection.
      msg.style.color = "var(--badge-danger-text)";
      msg.textContent = "Not saved — the rules changed since you opened the editor. Close and reopen it to pick up the current rules, then reapply your edit.";
      return;
    }
    if (!r.ok) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Rejected: " + (d.error || r.status); return; }
    taggerRulesRevision = d.revision || "";
    msg.style.color = "#6bcB77";
    msg.textContent = `Saved — ${d.ruleCount} rule(s). Run tagger to apply.`;
    document.getElementById("taggerRulesSource").textContent = `user — ${d.ruleCount} rule(s)`;
  } catch (e) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "Save failed: " + e.message; }
}

// Published for the inline script and the ACTIONS table. Every function this file declares is
// listed: one that is still called by name from dashboard.html but missing here is a
// ReferenceError, which is the mistake #414 shipped and tests/dashboard/dashboardModules.test.ts
// now checks in both directions.
window.DfirTagger = {
  runTagger,
  suggestTaggerRule,
  previewTaggerRule,
  toggleTaggerSuggest,
  addSuggestedTaggerRule,
  discardSuggestedTaggerRule,
  refreshTaggerRuleList,
  removeTaggerRule,
  resetTaggerRules,
  clearTaggerTags,
  toggleTaggerRules,
  saveTaggerRules,
};
