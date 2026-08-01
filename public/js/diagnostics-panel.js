// Diagnostics panel renderers, extracted from dashboard.html's inline script (#384).
//
// These build HTML STRINGS from a diagnostics report -- no DOM, no fetch, no shared dashboard
// state -- which is why they were the first slice that could move. renderDiagnostics() still lives
// inline and calls into here through window.DfirDiagnostics; module scripts run after classic
// inline scripts, and every call site here is inside a function that runs on a data load, never at
// parse time.
//
// `esc` IS DUPLICATED ON PURPOSE. The inline script has 661 call sites for it, so it cannot move in
// this pass, and a module cannot read the inline scope. Rather than have the dashboard depend on
// this module for an XSS-critical primitive at load time, the module carries its own copy and
// tests/reports/diagnosticsPanel.test.ts asserts the two implementations stay identical -- a drift
// guard instead of a runtime coupling.

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function diagFmtBytes(b) {
  if (b == null || !isFinite(b) || b < 0) return "—";
  if (b < 1024) return Math.round(b) + " B";
  const u = ["KB", "MB", "GB", "TB", "PB"]; let v = b / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? Math.round(v) : v.toFixed(1)) + " " + u[i];
}
function diagFmtAge(ms) {
  if (ms == null || !isFinite(ms) || ms <= 0) return "0s";
  const s = Math.floor(ms / 1000); if (s < 60) return s + "s";
  const m = Math.floor(s / 60); if (m < 60) return m + "m";
  const h = Math.floor(m / 60); if (h < 24) return h + "h";
  return Math.floor(h / 24) + "d";
}
function diagFmtCost(usd) {
  if (usd == null || !isFinite(usd)) return "n/a";
  return "$" + usd.toFixed(usd < 1 ? 4 : 2);
}
function diagAiCostBucketRow(label, bucket) {
  const costText = bucket.hasCost ? diagFmtCost(bucket.totalCostUSD) : "n/a";
  const tokText = bucket.hasTokens
    ? `${bucket.totalInputTokens.toLocaleString()} in / ${bucket.totalOutputTokens.toLocaleString()} out`
    : "n/a";
  const models = Object.entries(bucket.byModel);
  const modelRows = models.length
    ? `<details data-safe-style="margin:2px 0 4px 12px"><summary data-safe-style="cursor:pointer;color:#6aa9ff;font-size:11.5px">${models.length} model(s)</summary>` +
      models.map(([key, m]) => `<div data-safe-style="font-size:11.5px;color:#9aa4b2;margin:2px 0 2px 8px;font-family:monospace">
        ${esc(key)} — ${m.calls} call(s), ${m.hasCost ? diagFmtCost(m.costUSD) : "n/a"}, ${m.hasTokens ? `${m.inputTokens.toLocaleString()}/${m.outputTokens.toLocaleString()} tok` : "n/a tok"}
      </div>`).join("") + `</details>`
    : "";
  return diagRow(esc(label), `${bucket.totalCalls} call(s) · ${costText} · ${tokText}`) + modelRows;
}
function renderAiCostCard(cost) {
  if (!cost) return "";
  const total = {
    totalCalls: cost.vision.totalCalls + cost.synthesis.totalCalls + cost.other.totalCalls,
    totalCostUSD: cost.vision.totalCostUSD + cost.synthesis.totalCostUSD + cost.other.totalCostUSD,
    hasCost: cost.vision.hasCost || cost.synthesis.hasCost || cost.other.hasCost,
    totalInputTokens: cost.vision.totalInputTokens + cost.synthesis.totalInputTokens + cost.other.totalInputTokens,
    totalOutputTokens: cost.vision.totalOutputTokens + cost.synthesis.totalOutputTokens + cost.other.totalOutputTokens,
    hasTokens: cost.vision.hasTokens || cost.synthesis.hasTokens || cost.other.hasTokens,
    byModel: {},
  };
  // A bucket that never reported cost/tokens makes the total "partial", not wrong —
  // say so rather than silently under-reporting real spend as a clean $ total.
  // Only buckets that actually made calls count toward this check — an unused bucket
  // (e.g. "Other" on a typical case) isn't a data-reporting gap.
  const usedBuckets = [cost.vision, cost.synthesis, cost.other].filter(b => b.totalCalls > 0);
  const someHaveCost = usedBuckets.some(b => b.hasCost);
  const allHaveCost = usedBuckets.every(b => b.hasCost);
  const totalNote = usedBuckets.length > 0 && someHaveCost && !allHaveCost
    ? `<div data-safe-style="font-size:11px;color:#7e8aa0;margin-top:2px">partial — not every bucket's provider reports cost</div>` : "";
  const rows = diagAiCostBucketRow("Vision", cost.vision)
    + diagAiCostBucketRow("Synthesis", cost.synthesis)
    + diagAiCostBucketRow("Other", cost.other)
    + `<div data-safe-style="border-top:1px solid var(--border-color);margin-top:6px;padding-top:6px">`
    + diagRow("Total", `${total.totalCalls} call(s) · ${total.hasCost ? diagFmtCost(total.totalCostUSD) : "n/a"} · ${total.hasTokens ? `${total.totalInputTokens.toLocaleString()} in / ${total.totalOutputTokens.toLocaleString()} out` : "n/a"}`)
    + totalNote + `</div>`;
  return diagCard("AI cost — this case", rows);
}
const DIAG_LEVEL_COLOR = { none: "#5ad17a", warning: "#ffce8a", danger: "#ffb05a", critical: "#ff5a5a" };
function diagCard(title, rows) {
  return `<div data-safe-style="background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:10px 12px;margin-bottom:10px">
    <div data-safe-style="font-weight:600;color:var(--text-primary);margin-bottom:6px">${esc(title)}</div>${rows}</div>`;
}
function diagRow(label, value, color) {
  return `<div data-safe-style="display:flex;justify-content:space-between;gap:12px;padding:1px 0">
    <span data-safe-style="color:#9aa4b2">${esc(label)}</span>
    <span data-safe-style="text-align:right${color ? `;color:${color}` : ""}">${value}</span></div>`;
}
function renderOperationalDiagnostics(o) {
  if (!o || !o.enabled) {
    return diagCard("Local performance & capacity", diagRow("Status", "disabled — core behavior is unchanged", "#7e8aa0"));
  }
  const slow = o.slowest || {};
  const cap = o.capacity || {};
  const warningRows = (o.warnings || []).map(w =>
    `<div data-safe-style="color:#ffb05a;margin-top:4px">⚠ ${esc(w)}</div>`).join("");
  const hotspot = (label, item) => item
    ? diagRow(label, `${esc(item.name)} · ${Math.round(item.durationMs).toLocaleString()} ms<div data-safe-style="font-size:11px;color:#7e8aa0">${esc(item.remediation)}</div>`)
    : "";
  return diagCard("Local performance & capacity", [
    diagRow("Retention", `${o.sampleCount.toLocaleString()} sample(s) · ${Math.round(o.retentionDays)} days maximum`),
    diagRow("Importer yield", `${o.imports.accepted.toLocaleString()} accepted · ${o.imports.rejected.toLocaleString()} rejected · ${o.imports.promoted.toLocaleString()} promoted`),
    diagRow("Query latency", `p50 ${Math.round(o.queries.p50Ms)} ms · p95 ${Math.round(o.queries.p95Ms)} ms · ${o.queries.unindexed} unindexed`),
    diagRow("Jobs", `${o.jobs.queued} queued · ${o.jobs.running} running · ${o.jobs.retries} retries · ${o.jobs.stalled} stalled`, o.jobs.stalled ? "#ffb05a" : ""),
    diagRow("AI", `${o.ai.calls} call(s) · p95 ${Math.round(o.ai.p95Ms)} ms · ${o.ai.retries} retries · ${o.ai.rateLimits} rate limits`),
    diagRow("Exports", `${o.exports.count} run(s) · p95 ${Math.round(o.exports.p95Ms)} ms · ${diagFmtBytes(o.exports.outputBytes)}`),
    diagRow("Live connection", `${o.websocket.active} active · ${o.websocket.reconnects} reconnect · ${o.websocket.dropped} dropped · ${o.websocket.rejects} rejected`),
    diagRow("Case databases", diagFmtBytes(cap.databaseBytes || 0)),
    cap.growthBytesPerDay != null ? diagRow("Projected growth", `${diagFmtBytes(cap.growthBytesPerDay)}/day${cap.projectedDaysRemaining != null ? ` · ${cap.projectedDaysRemaining.toFixed(1)} days of free disk` : ""}`) : "",
    hotspot("Slowest importer", slow.importer),
    hotspot("Slowest query", slow.query),
    hotspot("Slowest job", slow.job),
    warningRows,
  ].join(""));
}
// Per-importer health table (#84): one row per custom (declarative) importer — last-run age,
// success/fail, rows parsed (kept/total, dropped), last error — plus malformed-spec load errors
// from the registry, so all import health signals for custom importers live in one place.
function renderPerImporterHealth(im) {
  const perImporter = im.perImporter || [];
  const loadErrors = im.loadErrors || [];
  if (!perImporter.length && !loadErrors.length) return "";
  let html = `<div data-safe-style="margin-top:10px;border-top:1px solid var(--border-color);padding-top:8px">
    <div data-safe-style="color:#9aa4b2;margin-bottom:4px">Per-importer breakdown (${perImporter.length}):</div>`;
  if (perImporter.length) {
    html += `<div data-safe-style="max-height:220px;overflow:auto">` + perImporter.map(p => {
      const ok = p.lastStatus === "ok";
      const statusColor = p.lastStatus == null ? "#7e8aa0" : ok ? "#5ad17a" : "#ff9f9f";
      const statusText = p.lastStatus == null ? "never run" : ok ? "ok" : "failed";
      const age = p.lastRunAt ? diagFmtAge(Date.now() - Date.parse(p.lastRunAt)) + " ago" : "—";
      const rows = p.lastStatus != null ? `${p.kept ?? 0}/${p.total ?? 0} kept, ${p.dropped ?? 0} dropped` : "—";
      return `<div data-safe-style="border-left:2px solid ${ok ? "#2a5a3a" : p.lastStatus ? "#5a2a2a" : "#3a3f4a"};padding:2px 0 2px 8px;margin:3px 0;font-family:monospace;font-size:11.5px">
        <span data-safe-style="color:#cbd3df">${esc(p.label)}</span> <span data-safe-style="color:#7e8aa0">(${esc(p.id)})</span>
        — <span data-safe-style="color:${statusColor}">${statusText}</span> · ${age} · ${rows}
        ${p.lastError ? `<br><span data-safe-style="color:#ffb0b0">${esc(p.lastError)}</span>` : ""}</div>`;
    }).join("") + `</div>`;
  }
  if (loadErrors.length) {
    html += `<div data-safe-style="margin-top:6px;color:#9aa4b2">Spec load errors (${loadErrors.length}):</div>`;
    html += `<div data-safe-style="max-height:160px;overflow:auto;margin-top:3px">` + loadErrors.map(e =>
      `<div data-safe-style="border-left:2px solid #5a2a2a;padding:2px 0 2px 8px;margin:3px 0;font-family:monospace;font-size:11.5px">
        <span data-safe-style="color:#ff9f9f">${esc(e.file)}</span><br>
        ${e.errors.map(x => `<span data-safe-style="color:#ffb0b0">${esc(x.path)}: ${esc(x.message)}</span>`).join("<br>")}</div>`).join("") + `</div>`;
  }
  html += `</div>`;
  return html;
}
export {
  diagFmtBytes,
  diagFmtAge,
  diagFmtCost,
  diagAiCostBucketRow,
  renderAiCostCard,
  diagCard,
  diagRow,
  renderOperationalDiagnostics,
  renderPerImporterHealth,
  DIAG_LEVEL_COLOR,
};

// The dashboard's inline diagnostics functions reach these through the namespaced global, the same
// contract graph-view.js and settings-search.js already use.
//
// EVERY function this module defines is exposed, not just the top-level renderers. The first cut of
// this file published only the four renderers, on the assumption that the helpers had moved with
// their only callers. They had not: renderDiagnostics, diagComputeSizes, loadCaseStats and
// loadCaseBackups still make 46 bare calls to diagRow/diagCard/diagFmtBytes/diagFmtAge. An ES
// module's declarations are NOT globals, so every one of those was a ReferenceError and the whole
// Diagnostics panel threw at runtime -- while all 29 unit tests passed, because they exercise this
// module directly and never load the page.
//
// The rule this encodes: if the inline script still calls it, the namespace must publish it.
// tests/reports/diagnosticsPanel.test.ts now asserts exactly that, in both directions.
if (typeof window !== "undefined") {
  window.DfirDiagnostics = {
    esc,
    diagFmtBytes,
    diagFmtAge,
    diagFmtCost,
    diagAiCostBucketRow,
    renderAiCostCard,
    diagCard,
    diagRow,
    renderOperationalDiagnostics,
    renderPerImporterHealth,
    DIAG_LEVEL_COLOR,
  };
}
