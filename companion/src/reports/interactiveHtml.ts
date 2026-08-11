import type {
  InvestigationState,
  ForensicEvent,
  Finding,
  FindingStatus,
  Severity,
} from "../analysis/stateTypes.js";
import type { CaseMeta } from "../types.js";
import type { ReportMeta } from "./reportMeta.js";
import { emptyReportMeta } from "./reportMeta.js";
import { CSP_NONCE_PLACEHOLDER } from "../http/securityHeaders.js";
import { escapeHtml } from "./escapeHtml.js";

// A self-contained, interactive HTML report (#233). Unlike the canonical print-oriented HTML
// report (html.ts), this is a single-page app: all case data is embedded as a JSON blob inside a
// <script> tag, and the inline JS renders filterable timeline tables, expandable finding cards,
// and a min-confidence slider — all client-side, with no external dependencies. The file is fully
// portable (email it, drop it on a share, open it offline).
//
// WHAT GETS EMBEDDED: only the fields this page actually draws, never the InvestigationState.
//
// That distinction is a confidentiality property, not a size optimisation. The state carries
// collections this report never renders — `iocExcludeRules[].note` records an analyst's private
// rationale for dismissing an IOC ("client's internal AD domain"), and `openThreads`,
// `keyQuestions`, `uncertainties`, `lastSummary` and `attackerPath` are all working notes. Embedding
// the whole object put every one of them in a file whose entire purpose is to be emailed, invisible
// on the rendered page, so an analyst reviewing the report before sending it could not see what they
// were about to disclose. Projecting to the two view-models below means anything not on screen is
// not in the file. Adding a field here is therefore a deliberate act, which is the point.
//
// SIZE GUARD: the projection above removes the heavyweight per-event fields (`message` carries
// untruncated ScriptBlock text), and then the timeline is capped twice over — by row count and by
// serialized bytes, whichever binds first. Both are needed: severity is a poor proxy for volume
// here (every YARA hit is stamped High, and Sigma/Chainsaw detections are High/Critical by
// construction), so "keep the important ones" bounds nothing on a real case, and one event can be
// tens of kilobytes on its own, so a row count alone bounds nothing either. Rows are dropped whole
// and lowest-severity-first; event text is never truncated mid-string, because a mangled artifact
// path is worse than an absent one.

const SIZE_LIMIT = 2000;
const MAX_TIMELINE_BYTES = 4 * 1024 * 1024;

const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

/** One forensic-timeline row: exactly the six columns the table shows, plus the search-key fields. */
export interface TimelineRow {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  asset?: string;
  sources?: string[];
  artifactName?: string;
}

/** One finding card: exactly the fields the expanded card renders. */
export interface FindingCard {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  confidence?: number;
  confidenceReason?: string;
  mitreTechniques: string[];
  relatedIocs: string[];
  firstSeen: string;
  status: FindingStatus;
}

export interface InteractiveCaseData {
  caseId: string;
  caseName: string;
  investigator: string;
  updatedAt: string;
  incidentId: string;
  companyName: string;
  restrictions: string;
  findings: FindingCard[];
  timeline: TimelineRow[];
  /** True when the guard dropped rows; `timeline.length` vs `totalEvents` gives the shortfall. */
  truncated: boolean;
  totalEvents: number;
}

// Serialize the case data as a JSON string that is safe to embed inside a <script> tag.
//
// Escaping the literal `</script>` is NOT sufficient, which is worth spelling out because it is the
// obvious-looking guard and it is wrong. The HTML script-data tokenizer ends the element on
// `</script` followed by whitespace, `/`, or `>`, so `</script >` and `</script/>` both close it
// while matching no `</script>` pattern. Separately, `<!--` followed by `<script` flips the
// tokenizer into script-data-double-escaped state, where the real closing tag is swallowed and the
// attacker chooses where the element actually ends.
//
// Escaping every `<` to its \\u003c form collapses all three cases into one rule: no literal `<`
// survives, so no tokenizer transition can fire. That is a plain JSON string escape, so the parsed
// value is byte-identical to the input and nothing downstream un-escapes it. This mirrors what
// routes/aiSynthesis.ts already does for its embedded deck JSON.
//
// DFIR field text (filenames, IOC values, phishing-body excerpts, AI/analyst prose) is untrusted,
// so this guard must run regardless of content. It matters most in the saved/emailed copy of the
// report, which carries no CSP at all.
function safeJsonForScript(data: unknown): string {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}

function toTimelineRow(e: ForensicEvent): TimelineRow {
  return {
    id: e.id,
    timestamp: e.timestamp,
    description: e.description,
    severity: e.severity,
    mitreTechniques: e.mitreTechniques,
    asset: e.asset,
    sources: e.sources,
    artifactName: e.artifactName,
  };
}

function toFindingCard(f: Finding): FindingCard {
  return {
    id: f.id,
    severity: f.severity,
    title: f.title,
    description: f.description,
    confidence: f.confidence,
    confidenceReason: f.confidenceReason,
    mitreTechniques: f.mitreTechniques,
    relatedIocs: f.relatedIocs,
    firstSeen: f.firstSeen,
    status: f.status,
  };
}

function serializedBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

/**
 * Cap the timeline at whichever of the two ceilings binds first, dropping the least severe rows.
 *
 * Selection runs in severity order so the rows that survive are the ones that drive triage, but the
 * result is restored to the original chronological order before it is returned — an out-of-order
 * timeline would be actively misleading in a forensic report.
 *
 * The first row is admitted unconditionally. Without that, a single event larger than the whole byte
 * budget would yield an empty timeline behind a banner claiming the report had merely been trimmed.
 */
function selectTimeline(events: ForensicEvent[]): { rows: TimelineRow[]; truncated: boolean } {
  const all = events.map(toTimelineRow);
  if (all.length <= SIZE_LIMIT && serializedBytes(all) <= MAX_TIMELINE_BYTES) {
    return { rows: all, truncated: false };
  }

  const byPriority = all
    .map((row, index) => ({ row, index }))
    .sort((a, b) => SEVERITY_RANK[a.row.severity] - SEVERITY_RANK[b.row.severity] || a.index - b.index);

  const kept: { row: TimelineRow; index: number }[] = [];
  let bytes = 0;
  for (const entry of byPriority) {
    if (kept.length >= SIZE_LIMIT) break;
    const size = serializedBytes(entry.row);
    if (kept.length > 0 && bytes + size > MAX_TIMELINE_BYTES) break;
    bytes += size;
    kept.push(entry);
  }

  kept.sort((a, b) => a.index - b.index);
  return { rows: kept.map((e) => e.row), truncated: kept.length < all.length };
}

function buildData(
  state: InvestigationState,
  caseMeta: CaseMeta | null,
  reportMeta: ReportMeta,
): InteractiveCaseData {
  const { rows, truncated } = selectTimeline(state.forensicTimeline);
  return {
    caseId: state.caseId,
    caseName: caseMeta?.name ?? "",
    investigator: caseMeta?.investigator ?? "",
    updatedAt: state.updatedAt,
    incidentId: reportMeta.incidentId,
    companyName: reportMeta.companyName,
    restrictions: reportMeta.restrictions,
    findings: state.findings.map(toFindingCard),
    timeline: rows,
    truncated,
    totalEvents: state.forensicTimeline.length,
  };
}

const STYLES = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #f5f6f8; color: #1b1f24;
    font: 15px/1.6 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  main.report { max-width: 1100px; margin: 0 auto; padding: 32px 40px 64px; background: #fff;
    box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  h1 { font-size: 26px; margin: 0 0 6px; }
  h2 { font-size: 19px; margin: 28px 0 10px; padding-top: 10px; border-top: 1px solid #e6e8ec; color: #16213a; }
  .meta { color: #5a6675; font-size: 13.5px; margin: 0 0 20px; }
  .banner { background: #fff3cd; border: 1px solid #ffe69c; color: #664d03;
    padding: 10px 14px; border-radius: 6px; margin: 0 0 20px; font-size: 13.5px; }
  .banner[hidden] { display: none; }
  .controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin: 0 0 12px; }
  .controls label { font-size: 13px; color: #44506a; }
  .controls select, .controls input[type="text"], .controls input[type="range"] { font: inherit; }
  .controls select, .controls input[type="text"] { padding: 4px 8px; border: 1px solid #c7ccd4; border-radius: 4px; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 13.5px; }
  th, td { border: 1px solid #d7dbe0; padding: 6px 10px; text-align: left; vertical-align: top; }
  th { background: #f0f3f7; font-weight: 600; }
  tr:nth-child(even) td { background: #fafbfc; }
  .sev-Critical { color: #fff; background: #8b0000; font-weight: 600; padding: 1px 6px; border-radius: 3px; }
  .sev-High { color: #fff; background: #b3261e; font-weight: 600; padding: 1px 6px; border-radius: 3px; }
  .sev-Medium { color: #fff; background: #c77700; font-weight: 600; padding: 1px 6px; border-radius: 3px; }
  .sev-Low { color: #1b1f24; background: #d6e0f0; font-weight: 600; padding: 1px 6px; border-radius: 3px; }
  .sev-Info { color: #1b1f24; background: #e6e8ec; font-weight: 600; padding: 1px 6px; border-radius: 3px; }
  .finding-card { border: 1px solid #d7dbe0; border-radius: 6px; margin: 8px 0; background: #fff; }
  .finding-head { display: flex; align-items: center; gap: 10px; padding: 10px 14px; cursor: pointer; user-select: none; }
  .finding-head:hover { background: #f7f8fa; }
  .finding-head .title { font-weight: 600; flex: 1; }
  .finding-body { padding: 0 14px 12px; display: none; }
  .finding-card.open .finding-body { display: block; }
  .chevron { color: #5a6675; transition: transform .15s; }
  .finding-card.open .chevron { transform: rotate(90deg); }
  .conf-bar { width: 60px; height: 8px; border: 0; border-radius: 4px; overflow: hidden;
    vertical-align: middle; margin-left: 6px; background: #e6e8ec; appearance: none; }
  .conf-bar::-webkit-progress-bar { background: #e6e8ec; }
  .conf-bar::-webkit-progress-value { background: #24314f; }
  .conf-bar::-moz-progress-bar { background: #24314f; }
  .empty { color: #5a6675; font-style: italic; padding: 8px 0; }
  .count { color: #5a6675; font-size: 12.5px; }
`;

const SCRIPT = `
(function () {
  var DATA = window.__DFIR_CASE__;

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "class") n.className = attrs[k];
      else if (k === "text") n.textContent = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    if (children) children.forEach(function (c) {
      if (c == null) return;
      n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return n;
  }

  function sevClass(s) { return "sev-" + s; }

  function distinctSources(ev) {
    if (ev.sources && ev.sources.length) return ev.sources.join(", ");
    return ev.artifactName || "—";
  }

  var timeline = DATA.timeline;
  var findings = DATA.findings;

  // ── Banner ───────────────────────────────────────────────────────────────
  var banner = document.getElementById("size-banner");
  if (DATA.truncated) {
    banner.hidden = false;
    banner.textContent = "Warning: this case has " + DATA.totalEvents + " forensic events, more than fits in a " +
      "single portable file. The " + timeline.length + " highest-severity events are included here; the remaining " +
      (DATA.totalEvents - timeline.length) + " are in the full case. Findings are complete and unaffected.";
  }

  // ── Timeline filters ─────────────────────────────────────────────────────
  var sevFilter = document.getElementById("sev-filter");
  var srcFilter = document.getElementById("src-filter");
  var hostFilter = document.getElementById("host-filter");
  var search = document.getElementById("search");
  var tbody = document.getElementById("timeline-body");
  var count = document.getElementById("timeline-count");

  var sources = {};
  var hosts = {};
  timeline.forEach(function (ev) {
    (ev.sources || []).forEach(function (s) { sources[s] = true; });
    if (ev.asset) hosts[ev.asset] = true;
  });
  Object.keys(sources).sort().forEach(function (s) {
    srcFilter.appendChild(el("option", { value: s, text: s }));
  });
  Object.keys(hosts).sort().forEach(function (h) {
    hostFilter.appendChild(el("option", { value: h, text: h }));
  });

  function renderTimeline() {
    var sev = sevFilter.value;
    var src = srcFilter.value;
    var host = hostFilter.value;
    var q = search.value.trim().toLowerCase();
    var shown = 0;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    timeline.forEach(function (ev) {
      if (sev !== "all" && ev.severity !== sev) return;
      if (src !== "all" && !(ev.sources && ev.sources.indexOf(src) !== -1)) return;
      if (host !== "all" && ev.asset !== host) return;
      if (q) {
        var hay = (ev.description + " " + ev.id + " " + (ev.asset || "") + " " + (ev.sources || []).join(" ") + " " + (ev.mitreTechniques || []).join(" ")).toLowerCase();
        if (hay.indexOf(q) === -1) return;
      }
      shown++;
      var tr = el("tr", null, [
        el("td", null, [el("span", { class: sevClass(ev.severity), text: ev.severity })]),
        el("td", { text: ev.timestamp }),
        el("td", { text: ev.asset || "—" }),
        el("td", { text: distinctSources(ev) }),
        el("td", { text: ev.description }),
        el("td", { text: (ev.mitreTechniques || []).join(", ") || "—" }),
      ]);
      tbody.appendChild(tr);
    });
    if (shown === 0) tbody.appendChild(el("tr", null, [el("td", { colspan: "6", text: "No events match the current filters." })]));
    count.textContent = shown + " of " + timeline.length + " events shown";
  }
  sevFilter.addEventListener("change", renderTimeline);
  srcFilter.addEventListener("change", renderTimeline);
  hostFilter.addEventListener("change", renderTimeline);
  search.addEventListener("input", renderTimeline);

  // ── Confidence slider ───────────────────────────────────────────────────
  var confSlider = document.getElementById("conf-slider");
  var confValue = document.getElementById("conf-value");
  var findingsRoot = document.getElementById("findings");

  function confidence(f) { return typeof f.confidence === "number" ? f.confidence : 0; }

  function renderFindings() {
    var min = Number(confSlider.value);
    confValue.textContent = min + "+";
    while (findingsRoot.firstChild) findingsRoot.removeChild(findingsRoot.firstChild);
    var list = findings.filter(function (f) { return confidence(f) >= min; });
    if (list.length === 0) {
      findingsRoot.appendChild(el("p", { class: "empty", text: "No findings at or above the selected confidence." }));
      return;
    }
    list.forEach(function (f) {
      var card = el("div", { class: "finding-card" });
      var head = el("div", { class: "finding-head" }, [
        el("span", { class: "chevron", text: "▶" }),
        el("span", { class: sevClass(f.severity), text: f.severity }),
        el("span", { class: "title", text: f.title }),
        el("progress", { class: "conf-bar", max: "100", value: String(confidence(f)) }),
        el("span", { text: confidence(f) + "%" }),
      ]);
      head.addEventListener("click", function () { card.classList.toggle("open"); });
      var body = el("div", { class: "finding-body" }, [
        el("p", null, [el("b", { text: "ID: " }), el("span", { text: f.id })]),
        el("p", null, [el("b", { text: "First seen: " }), el("span", { text: f.firstSeen || "—" })]),
        el("p", null, [el("b", { text: "Status: " }), el("span", { text: f.status })]),
        el("p", { text: f.description }),
        f.confidenceReason ? el("p", null, [el("b", { text: "Confidence reason: " }), el("span", { text: f.confidenceReason })]) : null,
        el("p", null, [el("b", { text: "MITRE: " }), el("span", { text: (f.mitreTechniques || []).join(", ") || "—" })]),
        el("p", null, [el("b", { text: "Related IOCs: " }), el("span", { text: (f.relatedIocs || []).join(", ") || "—" })]),
      ]);
      card.appendChild(head);
      card.appendChild(body);
      findingsRoot.appendChild(card);
    });
  }
  confSlider.addEventListener("input", renderFindings);

  renderTimeline();
  renderFindings();
})();
`;

export function renderInteractiveHtmlReport(
  state: InvestigationState,
  caseMeta: CaseMeta | null = null,
  reportMeta: ReportMeta = emptyReportMeta(),
): string {
  const data = buildData(state, caseMeta, reportMeta);
  const title = data.incidentId
    ? `Interactive Report — ${data.incidentId}`
    : `Interactive Report — ${state.caseId}`;

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeHtml(title)}</title>`,
    `<style nonce="${CSP_NONCE_PLACEHOLDER}">${STYLES}</style>`,
    "</head>",
    "<body>",
    '<main class="report">',
    `<h1>${escapeHtml(title)}</h1>`,
    `<p class="meta">`,
    data.caseName ? `Case: <b>${escapeHtml(data.caseName)}</b> · ` : "",
    `Case ID: ${escapeHtml(data.caseId)}`,
    data.investigator ? ` · Investigator: ${escapeHtml(data.investigator)}` : "",
    data.companyName ? ` · ${escapeHtml(data.companyName)}` : "",
    data.restrictions ? ` · ${escapeHtml(data.restrictions)}` : "",
    ` · Updated: ${escapeHtml(data.updatedAt)}`,
    `</p>`,
    `<div id="size-banner" class="banner" hidden></div>`,
    `<h2>Findings</h2>`,
    `<div class="controls">`,
    `<label>Min confidence: <input id="conf-slider" type="range" min="0" max="100" value="0"></label>`,
    `<span id="conf-value">0+</span>`,
    `</div>`,
    `<div id="findings"></div>`,
    `<h2>Forensic Timeline</h2>`,
    `<div class="controls">`,
    `<label>Severity <select id="sev-filter"><option value="all">All</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="Info">Info</option></select></label>`,
    `<label>Source <select id="src-filter"><option value="all">All</option></select></label>`,
    `<label>Host <select id="host-filter"><option value="all">All</option></select></label>`,
    `<label>Search <input id="search" type="text" placeholder="search event text…"></label>`,
    `</div>`,
    `<p id="timeline-count" class="count"></p>`,
    `<table><thead><tr><th>Severity</th><th>Time</th><th>Host</th><th>Source</th><th>Description</th><th>MITRE</th></tr></thead><tbody id="timeline-body"></tbody></table>`,
    "</main>",
    // Both blocks carry the CSP nonce placeholder. The route swaps in the per-response value via
    // withNonce() when serving over HTTP, where script-src forbids un-nonced inline script; a
    // downloaded copy is opened from file:// with no CSP, where the leftover attribute is inert.
    `<script nonce="${CSP_NONCE_PLACEHOLDER}">window.__DFIR_CASE__ = ${safeJsonForScript(data)};</script>`,
    `<script nonce="${CSP_NONCE_PLACEHOLDER}">${SCRIPT}</script>`,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}
