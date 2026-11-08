// Super-Timeline → Content tagger → Detection rules (#2389): one collapsible box with a line each
// for the tagger rules (rule pack, #2349) and the Sigma rules (#2204), and an update button on a
// line only when a newer release was found. Collapsed by default; the browser remembers the choice.
//
// It installs nothing. "Review update…" opens the review that already exists: the rule pack review
// in this box, or Settings → Sigma rules with its preview. Install is still the analyst's click.
//
// The tagger line is fed by js/dashboard-rule-pack.js (drSetTagger) and the Sigma line by
// js/dashboard-sigma-rules.js (drSetSigma) every time they render, so an install or roll back
// there updates this summary too. On its own it reads /sigma/status once at start.
//
// A CLASSIC SCRIPT. Every string is rendered with textContent: release names come from GitHub.

const DR_OPEN_KEY = "dfir.detectionRules.open";
const drState = { tagger: null, sigma: null };

// The tagger line, from GET /tagger/pack. PURE.
function drTaggerLine(st) {
  if (!st) return null;
  const what = st.inUse === "pack" && st.installed ? `rule pack ${st.installed.version}` : st.activeRules || "bundled with the app";
  const lc = st.lastCheck;
  if (st.problem) return { label: "Tagger rules", text: `${what} — see details`, action: null, warn: true };
  if (lc && lc.status === "update") return { label: "Tagger rules", text: `${what} — ${lc.latest} available`, action: "tagger", button: "Review update…" };
  if (lc && lc.status === "error") return { label: "Tagger rules", text: `${what} — the last check failed`, action: "tagger", button: "Check again" };
  if (lc) return { label: "Tagger rules", text: `${what} — current`, action: null };
  return { label: "Tagger rules", text: `${what} — not checked`, action: "tagger", button: "Check for updates" };
}

// The Sigma line, from GET /sigma/status. PURE.
function drSigmaLine(s) {
  if (!s || !s.active) return null;
  const what = `SigmaHQ ${s.active.release}`;
  const lc = s.lastCheck;
  if (s.enabled === false) return { label: "Sigma rules", text: `${what} — grading switched off`, action: null };
  if (lc && lc.error) return { label: "Sigma rules", text: `${what} — the last check failed`, action: "sigma", button: "Check again" };
  if (lc && lc.updateAvailable) return { label: "Sigma rules", text: `${what} — ${lc.latest} available`, action: "sigma", button: "Review update…" };
  if (lc) return { label: "Sigma rules", text: `${what} — current`, action: null };
  return { label: "Sigma rules", text: `${what} — not checked`, action: "sigma", button: "Check for updates" };
}

function drButton(line) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "ev-bulk-btn";
  b.textContent = line.button;
  b.onclick = (ev) => {
    // The button sits in <summary>: without this a click would also fold the box.
    ev.preventDefault();
    ev.stopPropagation();
    drRunAction(line.action);
  };
  return b;
}

function drRunAction(action) {
  const box = document.getElementById("detectionRulesBox");
  if (action === "tagger") {
    if (box) box.open = true;
    if (window.DfirRulePack) window.DfirRulePack.checkRulePack();
    return;
  }
  if (action === "sigma" && typeof openSettingsTab === "function") {
    openSettingsTab("sigma");
    if (typeof sigmaCheck === "function") sigmaCheck();
  }
}

function drRender() {
  const box = document.getElementById("detectionRulesBox");
  const lines = document.getElementById("detectionRulesLines");
  if (!box || !lines) return;
  const shown = [drTaggerLine(drState.tagger), drSigmaLine(drState.sigma)].filter(Boolean);
  box.hidden = shown.length === 0;
  lines.textContent = "";
  for (const line of shown) {
    const row = document.createElement("div");
    row.className = "dr-line";
    const label = document.createElement("span");
    label.className = "dr-label";
    label.textContent = line.label;
    const text = document.createElement("span");
    text.textContent = line.text;
    if (line.warn) text.className = "dr-warn";
    row.append(label, text);
    if (line.action) row.appendChild(drButton(line));
    lines.appendChild(row);
  }
}

function drSetTagger(st) {
  drState.tagger = st || null;
  drRender();
}

function drSetSigma(s) {
  drState.sigma = s || null;
  drRender();
}

async function drLoadSigma() {
  try {
    const r = await fetch("/sigma/status");
    // 403 / 501: not an administrator, or no Sigma store — the line is left out.
    if (r.ok) drSetSigma(await r.json());
  } catch {
    /* offline: the Sigma line is left out */
  }
}

function drInit() {
  const box = document.getElementById("detectionRulesBox");
  if (!box) return;
  try {
    box.open = localStorage.getItem(DR_OPEN_KEY) === "1";
  } catch {
    /* no storage: start collapsed */
  }
  box.addEventListener("toggle", () => {
    try {
      localStorage.setItem(DR_OPEN_KEY, box.open ? "1" : "0");
    } catch {
      /* no storage: the choice lasts for this page */
    }
  });
  const settings = document.getElementById("drSigmaSettingsBtn");
  if (settings) settings.onclick = () => typeof openSettingsTab === "function" && openSettingsTab("sigma");
  drLoadSigma();
}

window.DfirDetectionRules = { drTaggerLine, drSigmaLine, drSetTagger, drSetSigma, drRunAction, drRender, drLoadSigma, drInit };

if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", drInit, { once: true });
  else drInit();
}
