// Super-Timeline → Content tagger: "your detection rules are older than the built-in set" (#2344).
//
// An analyst who ever saved an edit, added an AI-suggested rule or removed one is running their own
// copy of the rules, and that copy got none of the rules shipped since. This module shows a notice
// when the built-in set has something new for that copy, a review of it, and applies the analyst's
// selection through POST /tagger/rules/updates/apply — the editor's lock and stale-revision check.
//
// What the review never does:
//   - re-add a rule the analyst deleted — those are listed as "removed by you", restored one by one;
//   - overwrite an analyst-edited rule the built-in set also changed — both versions are shown and
//     nothing is applied for it until the analyst picks a side;
//   - write a TAGGER_RULES_FILE source — that gets the review and a download of the merged rules;
//   - re-grade a case — open cases keep their grades until Run tagger is pressed, and it says so.
//
// A CLASSIC SCRIPT that self-starts once the page is parsed, and is refreshed by
// js/dashboard-tagger.js after every rule edit. Holds only its own review state. Every string is
// rendered with textContent: rule keys and descriptions come from rule files an operator or an AI
// suggestion wrote.

let taggerUpdatesView = null;
let taggerUpdateChoices = {};
// While the "open cases keep their grades — press Run tagger" note is up, a refresh triggered by the
// rule list reloading must not replace it before the analyst has read it.
let taggerUpdatesNoteUp = false;

function tuEl(tag, text, css) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (css) el.style.cssText = css;
  return el;
}

function tuBtn(text, onClick, title) {
  const b = tuEl("button", text);
  b.className = "ev-bulk-btn";
  if (title) b.title = title;
  b.onclick = onClick;
  return b;
}

function tuGrade(side) {
  return (side && side.severity) || "no grade";
}

function tuLabel(key, side) {
  return `${key} · ${tuGrade(side)}${side && side.description ? " — " + side.description : ""}`;
}

// The copy's changed-rule count for the notice: built-in changes plus conflicts (both are changes).
function tuChangedCount(view) {
  const c = view.counts || {};
  return (c.changed || 0) + (c.conflicts || 0);
}

// Pre-selected: rules that are new for certain, and built-in changes to rules the analyst never
// touched. Never pre-selected: conflicts, rules the analyst removed, and "new, or removed by you"
// on a copy saved before changes were tracked — each of those is the analyst's call.
function tuDefaultChoices(view) {
  const choices = {};
  for (const i of view.added || []) if (!i.uncertain) choices[i.key] = "upstream";
  for (const i of view.changed || []) choices[i.key] = "upstream";
  return choices;
}

async function loadTaggerUpdates() {
  const notice = document.getElementById("taggerUpdatesNotice");
  if (!notice) return;
  try {
    const r = await fetch("/tagger/rules/updates");
    // 403: not an administrator in team mode — rule edits are not theirs, so neither is the notice.
    if (!r.ok) { notice.hidden = true; taggerUpdatesView = null; return; }
    const view = await r.json();
    taggerUpdatesView = view;
    taggerUpdateChoices = tuDefaultChoices(view);
    renderTaggerUpdatesNotice(view);
    const pane = document.getElementById("taggerUpdatesPane");
    if (pane && !pane.hidden) renderTaggerUpdatesReview(view);
  } catch (e) {
    notice.hidden = true;
  }
}

// What the copy is compared with: the built-in set, or an installed rule pack (#2349).
function tuUpstreamName(view) {
  return (view && view.upstreamLabel && view.upstreamLabel.indexOf("rule pack") === 0) ? `the installed ${view.upstreamLabel}` : "the built-in set";
}

function renderTaggerUpdatesNotice(view) {
  if (taggerUpdatesNoteUp) return;
  const notice = document.getElementById("taggerUpdatesNotice");
  notice.textContent = "";
  if (!view || !view.notice) { notice.hidden = true; return; }
  const added = (view.counts && view.counts.added) || 0;
  const text =
    `Your detection rules are older than ${tuUpstreamName(view)}: ${added} added, ${tuChangedCount(view)} changed since your copy.` +
    (view.readOnly ? " Your rules come from an operator file (TAGGER_RULES_FILE), so they can be reviewed and downloaded merged, not changed here." : "");
  notice.appendChild(tuEl("span", text + " ", ""));
  notice.appendChild(tuBtn("Review changes", openTaggerUpdates, "See every added and changed built-in rule and pick what to bring in"));
  notice.appendChild(tuBtn("Dismiss", dismissTaggerUpdates, "Hide this notice until the built-in rules change again"));
  notice.hidden = false;
}

function openTaggerUpdates() {
  const pane = document.getElementById("taggerUpdatesPane");
  if (!pane || !taggerUpdatesView) return;
  pane.hidden = false;
  renderTaggerUpdatesReview(taggerUpdatesView);
}

function closeTaggerUpdates() {
  const pane = document.getElementById("taggerUpdatesPane");
  if (pane) pane.hidden = true;
}

function tuCheck(key, labelText, checked) {
  const row = tuEl("label", null, "display:flex;gap:6px;align-items:flex-start;padding:2px 0");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = !!checked;
  box.onchange = () => {
    if (box.checked) taggerUpdateChoices[key] = "upstream";
    else delete taggerUpdateChoices[key];
  };
  row.appendChild(box);
  row.appendChild(tuEl("span", labelText));
  return row;
}

function tuYaml(title, yaml) {
  const wrap = tuEl("div", null, "flex:1;min-width:220px");
  wrap.appendChild(tuEl("div", title, "font-weight:600"));
  wrap.appendChild(tuEl("pre", yaml || "", "white-space:pre-wrap;font-family:var(--font-code);font-size:11px;background:var(--bg-secondary);padding:6px;border-radius:6px;margin:2px 0"));
  return wrap;
}

function tuSideBySide(item) {
  const box = tuEl("div", null, "display:flex;gap:8px;flex-wrap:wrap;margin:2px 0 6px 22px");
  box.appendChild(tuYaml("Yours", item.mine && item.mine.yaml));
  box.appendChild(tuYaml("Built-in", item.upstream && item.upstream.yaml));
  return box;
}

function tuGroup(pane, title, items, renderItem) {
  if (!items || !items.length) return;
  pane.appendChild(tuEl("div", `${title} (${items.length})`, "font-weight:600;margin-top:8px;color:var(--text-bright)"));
  for (const item of items) pane.appendChild(renderItem(item));
}

function tuAddedRow(item) {
  const note = item.uncertain ? " (new, or removed by you — this copy was saved before changes were tracked)" : "";
  return tuCheck(item.key, tuLabel(item.key, item.upstream) + note, taggerUpdateChoices[item.key] === "upstream");
}

function tuChangedRow(item) {
  const wrap = tuEl("div");
  const text = `${item.key}: ${tuGrade(item.mine)} → ${tuGrade(item.upstream)}` +
    (item.upstream && item.upstream.description ? " — " + item.upstream.description : "");
  wrap.appendChild(tuCheck(item.key, text, taggerUpdateChoices[item.key] === "upstream"));
  wrap.appendChild(tuSideBySide(item));
  return wrap;
}

function tuRadio(key, value, text) {
  const label = tuEl("label", null, "margin-right:10px");
  const radio = document.createElement("input");
  radio.type = "radio";
  radio.name = `tu-${key}`;
  radio.checked = taggerUpdateChoices[key] === value;
  radio.onchange = () => { taggerUpdateChoices[key] = value; };
  label.appendChild(radio);
  label.appendChild(tuEl("span", " " + text));
  return label;
}

function tuConflictRow(item) {
  const wrap = tuEl("div", null, "padding:2px 0");
  const why = item.uncertain ? "changed — unknown which side (this copy was saved before changes were tracked)" : "you and the built-in set both changed this rule";
  wrap.appendChild(tuEl("div", `${item.key}: ${why}`));
  const pick = tuEl("div", null, "margin-left:22px");
  pick.appendChild(tuRadio(item.key, "mine", "Keep mine"));
  pick.appendChild(tuRadio(item.key, "upstream", "Use built-in"));
  wrap.appendChild(pick);
  wrap.appendChild(tuSideBySide(item));
  return wrap;
}

function tuRemovedRow(item) {
  return tuCheck(item.key, `Restore ${tuLabel(item.key, item.upstream)} — removed by you`, taggerUpdateChoices[item.key] === "upstream");
}

function renderTaggerUpdatesReview(view) {
  const pane = document.getElementById("taggerUpdatesPane");
  pane.textContent = "";
  pane.appendChild(tuEl("div", "Built-in rule updates — your own edits and rules are always kept.", "font-weight:600"));
  tuGroup(pane, `Added in ${tuUpstreamName(view)}`.replace("in the built-in set", "to the built-in set"), view.added, tuAddedRow);
  // A copy saved before changes were tracked has every added rule unticked ("new, or removed by
  // you"). One click selects the whole group; rules the analyst is sure they removed can be unticked.
  if ((view.added || []).some((i) => i.uncertain)) {
    pane.appendChild(tuBtn("Select all added rules", () => selectAllTaggerUpdates("added"), "Tick every rule in the added group"));
  }
  tuGroup(pane, `Changed in ${tuUpstreamName(view)}`, view.changed, tuChangedRow);
  tuGroup(pane, "Changed on both sides — pick one", view.conflicts, tuConflictRow);
  tuGroup(pane, "Removed by you — restore one at a time", view.removedByYou, tuRemovedRow);
  const bar = tuEl("div", null, "display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:8px");
  if (!view.readOnly) bar.appendChild(tuBtn("Add new rules", applyTaggerUpdates, "Bring the selected rules into your copy"));
  bar.appendChild(tuBtn("Download merged rules", exportTaggerUpdates, "Download your rules with the selected built-in rules merged in (nothing is changed on the server)"));
  bar.appendChild(tuBtn("Close", closeTaggerUpdates));
  const msg = tuEl("span", "", "font-size:12px;color:var(--text-muted)");
  msg.id = "taggerUpdatesMsg";
  bar.appendChild(msg);
  pane.appendChild(bar);
}

function selectAllTaggerUpdates(group) {
  const view = taggerUpdatesView;
  if (!view) return;
  for (const i of view[group] || []) taggerUpdateChoices[i.key] = "upstream";
  renderTaggerUpdatesReview(view);
}

function tuMsg(text, color) {
  const msg = document.getElementById("taggerUpdatesMsg");
  if (!msg) return;
  msg.style.color = color || "var(--text-muted)";
  msg.textContent = text;
}

// The note shown after applying. Open cases are NOT re-graded — that stays the analyst's action.
function tuAppliedNote(d) {
  const notice = document.getElementById("taggerUpdatesNotice");
  notice.textContent = "";
  const n = (d.applied || []).length;
  notice.appendChild(tuEl("span",
    `Brought in ${n} built-in rule(s); your rules now hold ${d.ruleCount}. Open cases keep their current grades until you press Super-Timeline → Content tagger → Run tagger.` +
    (d.baseEstablished ? " Rules you did not select are now listed as removed by you or kept as your edits." : ""),
    ""));
  notice.appendChild(tuBtn("Run tagger on this case", () => runTagger(), "Re-grade the connected case with the current rules"));
  notice.appendChild(tuBtn("OK", () => {
    taggerUpdatesNoteUp = false;
    notice.hidden = true;
    renderTaggerUpdatesNotice(taggerUpdatesView);
  }));
  notice.hidden = false;
  taggerUpdatesNoteUp = true;
}

// What the review was made against: the copy AND the rules it is compared with (#2344/#2349). The
// server refuses (409) when either changed since — e.g. a rule pack installed or rolled back.
function tuReviewed(view) {
  return { revision: view.revision, upstreamId: view.upstreamId, upstreamRevision: view.upstreamRevision };
}

function tuStaleText(d, verb) {
  return d && d.reason === "upstream"
    ? `Not ${verb} — the rules your copy is compared with changed since this review was loaded (a rule pack was installed or rolled back, or the app was updated). It has been reloaded; check it and try again.`
    : `Not ${verb} — the rules changed since this review was loaded. It has been reloaded; check it and try again.`;
}

async function applyTaggerUpdates() {
  const view = taggerUpdatesView;
  if (!view || view.readOnly) return;
  tuMsg("Applying…");
  try {
    const r = await fetch("/tagger/rules/updates/apply", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...tuReviewed(view), choices: taggerUpdateChoices }),
    });
    const d = await r.json();
    if (r.status === 409) {
      await loadTaggerUpdates(); // re-renders the review, so the message goes after it
      tuMsg(tuStaleText(d, "applied"), "var(--badge-danger-text)");
      return;
    }
    if (!r.ok) { tuMsg("Not applied: " + (d.error || r.status), "var(--badge-danger-text)"); return; }
    closeTaggerUpdates();
    await loadTaggerUpdates();
    tuAppliedNote(d);
    if (typeof refreshTaggerRuleList === "function") refreshTaggerRuleList();
  } catch (e) { tuMsg("Apply failed: " + e.message, "var(--badge-danger-text)"); }
}

async function exportTaggerUpdates() {
  const view = taggerUpdatesView;
  if (!view) return;
  tuMsg("Preparing download…");
  try {
    const r = await fetch("/tagger/rules/updates/export", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...tuReviewed(view), choices: taggerUpdateChoices }),
    });
    if (r.status === 409) {
      const d = await r.json();
      await loadTaggerUpdates();
      tuMsg(tuStaleText(d, "downloaded"), "var(--badge-danger-text)");
      return;
    }
    if (!r.ok) { const d = await r.json(); tuMsg("Download failed: " + (d.error || r.status), "var(--badge-danger-text)"); return; }
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "tagger-rules-merged.yaml";
    a.click();
    URL.revokeObjectURL(url);
    tuMsg("Downloaded — nothing was changed on the server.");
  } catch (e) { tuMsg("Download failed: " + e.message, "var(--badge-danger-text)"); }
}

async function dismissTaggerUpdates() {
  const view = taggerUpdatesView;
  if (!view || !view.upstreamRevision) return;
  try {
    const r = await fetch("/tagger/rules/updates/dismiss", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ upstreamRevision: view.upstreamRevision }),
    });
    if (!r.ok) return;
    document.getElementById("taggerUpdatesNotice").hidden = true;
    closeTaggerUpdates();
  } catch (e) { /* the notice simply stays; dismissing again is harmless */ }
}

window.DfirTaggerUpdates = {
  loadTaggerUpdates,
  renderTaggerUpdatesNotice,
  openTaggerUpdates,
  closeTaggerUpdates,
  renderTaggerUpdatesReview,
  selectAllTaggerUpdates,
  applyTaggerUpdates,
  exportTaggerUpdates,
  dismissTaggerUpdates,
};

// Self-start once the page is parsed; guarded so a page-less test context loads it cleanly.
if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loadTaggerUpdates, { once: true });
  else loadTaggerUpdates();
}
