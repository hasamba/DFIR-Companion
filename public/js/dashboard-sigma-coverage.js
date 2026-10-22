// Hunt Workbench → Sigma coverage (#2217): for each origin this case's super-timeline holds, which
// Sigma log sources grade it at import and how many rules run — or that nothing grades it. Each row
// opens the super-timeline filtered to that origin.
//
// A CLASSIC SCRIPT, like every js/dashboard-*.js file. It wires itself once the page has loaded, so
// the frozen inline script in dashboard.html does not grow (#384 size ledger). It holds no state:
// the case a render belongs to is checked against the case picker when the answer lands.
//
// Every string from the server is rendered with textContent, never innerHTML: origin labels come
// from imported evidence, and an artifact name is attacker-shaped.
//
// Analyst-only. Nothing here reaches an AI prompt (the AI never reads the super-timeline).

const SIGMA_COV_STATE_TEXT = {
  covered: "Sigma rules running",
  "no-loaded-rules": "No loaded rules — every rule for this source is switched off, refused or filtered",
  "not-graded": "Not graded by Sigma",
  "sigma-off": "Sigma grading is switched off",
};

function sigmaCovEl(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (cls) el.className = cls;
  return el;
}

function sigmaCovCaseId() {
  const input = document.getElementById("caseId");
  return ((input && input.value) || "").trim();
}

function sigmaCovSourcesText(row) {
  const sources = Array.isArray(row.sigmaSources) ? row.sigmaSources : [];
  if (!sources.length) return "—";
  return sources
    .map((s) => {
      const parts = [`${Number(s.loaded) || 0} loaded`];
      if (s.disabled) parts.push(`${s.disabled} switched off`);
      if (s.refused) parts.push(`${s.refused} refused`);
      if (s.status) parts.push(`${s.status} filtered by status`);
      return `${s.label}: ${parts.join(", ")}`;
    })
    .join("; ");
}

function sigmaCovHeadline(data) {
  if (!data.enabled) return "Sigma grading is switched off (DFIR_SIGMA_RULES=off) — nothing below is graded";
  return `${Number(data.graded) || 0} of ${Number(data.total) || 0} ingested sources have Sigma rules running`;
}

function pivotSigmaCoverage(origin, allOrigins) {
  if (typeof window.filterSuperTimelineToOrigin === "function") window.filterSuperTimelineToOrigin(origin, allOrigins);
}

function renderSigmaCoverage(box, data) {
  box.textContent = "";
  const rows = Array.isArray(data.rows) ? data.rows : [];
  const headline = document.getElementById("sigmaCoverageHeadline");
  if (headline) headline.textContent = sigmaCovHeadline(data);
  if (!rows.length) {
    box.appendChild(sigmaCovEl("div", "This case's super-timeline holds no events yet.", "hq-help"));
    return;
  }
  const allOrigins = rows.map((r) => String(r.origin));
  const table = sigmaCovEl("table");
  const head = sigmaCovEl("tr");
  for (const h of ["Origin", "Events", "Coverage", "Sigma sources and rules", ""]) head.appendChild(sigmaCovEl("th", h));
  table.appendChild(head);
  for (const row of rows) {
    const tr = sigmaCovEl("tr");
    tr.appendChild(sigmaCovEl("td", row.origin));
    tr.appendChild(sigmaCovEl("td", Number(row.events) || 0));
    const state = sigmaCovEl("td", SIGMA_COV_STATE_TEXT[row.state] || row.state);
    if (row.caveat) state.appendChild(sigmaCovEl("div", row.caveat, "hq-help"));
    tr.appendChild(state);
    tr.appendChild(sigmaCovEl("td", sigmaCovSourcesText(row)));
    const cell = sigmaCovEl("td");
    const btn = sigmaCovEl("button", "Show in super-timeline");
    btn.type = "button";
    btn.addEventListener("click", () => pivotSigmaCoverage(String(row.origin), allOrigins));
    cell.appendChild(btn);
    tr.appendChild(cell);
    table.appendChild(tr);
  }
  box.appendChild(table);
}

async function loadSigmaCoverage(caseId) {
  const box = document.getElementById("sigmaCoverage");
  if (!box) return;
  const forCase = caseId || sigmaCovCaseId();
  if (!forCase) {
    box.textContent = "Open a case to see which of its sources Sigma grades.";
    return;
  }
  try {
    const res = await fetch(`/cases/${encodeURIComponent(forCase)}/sigma/coverage`);
    let body = {};
    try {
      body = await res.json();
    } catch {
      body = {};
    }
    // The analyst moved to another case while this was in flight: this answer is not theirs.
    if (sigmaCovCaseId() !== forCase) return;
    if (!res.ok) {
      box.textContent = `Sigma coverage unavailable: ${body.error || `request failed (${res.status})`}`;
      return;
    }
    renderSigmaCoverage(box, body);
  } catch (e) {
    if (sigmaCovCaseId() === forCase) box.textContent = `Sigma coverage unavailable: ${e.message}`;
  }
}

function initSigmaCoverage() {
  document.getElementById("sigmaCoverageRefresh")?.addEventListener("click", () => loadSigmaCoverage());
}

// Self-start, the way js/dashboard-sigma-rules.js does: guarded so a page-less test context loads it.
if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initSigmaCoverage, { once: true });
  else initSigmaCoverage();
}
