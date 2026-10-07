const STATIC_FIELDS = [
  "id",
  "timestamp",
  "description",
  "message",
  "severity",
  "host.name",
  "event.source",
  "event.category",
  "event.type",
  "event.action",
  "event.outcome",
  "user.name",
  "user.domain",
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.protocol",
  "process.name",
  "process.pid",
  "process.executable",
  "process.command_line",
  "process.parent.name",
  "file.path",
  "file.name",
  "file.sha256",
  "file.md5",
  "registry.key",
  "service.name",
  "task.name",
  "mitre.technique",
  "related.finding_id",
  "ioc",
];
const OPERATORS = [
  "=",
  "!=",
  ">",
  ">=",
  "<",
  "<=",
  "contains",
  "matches",
  "exists",
  "between",
  "during",
  "AND",
  "OR",
  "NOT",
];
const PIPELINE_STAGES = [
  "group by",
  "count",
  "stats",
  "rare",
  "sort",
  "limit",
];
const DEFAULT_COLUMNS = [
  "id",
  "timestamp",
  "severity",
  "host.name",
  "description",
];

function quoteQueryValue(value) {
  return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function buildPivotQuery(kind, value) {
  const fields = {
    event: "id",
    ioc: "ioc",
    finding: "related.finding_id",
    asset: "host.name",
  };
  const field = fields[kind];
  return field ? `${field}=${quoteQueryValue(value)}` : "";
}

function currentWord(text, cursor) {
  const before = text.slice(0, cursor);
  const match = /([A-Za-z0-9_.-]*)$/.exec(before);
  return match ? match[1] : "";
}

export function autocompleteFor(text, cursor, fields = STATIC_FIELDS) {
  const word = currentWord(text, cursor).toLowerCase();
  const afterPipe = text.slice(0, cursor).lastIndexOf("|");
  const afterComparison = /(?:=|!=|>=|<=|>|<)\s*[^\s]*$/.test(
    text.slice(0, cursor),
  );
  const candidates =
    afterPipe >= 0 &&
    afterPipe > Math.max(text.lastIndexOf("AND"), text.lastIndexOf("OR"))
      ? PIPELINE_STAGES
      : afterComparison
        ? []
        : [...fields, ...OPERATORS];
  return candidates
    .filter((value) => !word || value.toLowerCase().startsWith(word))
    .slice(0, 12)
    .map((value) => ({ value, label: value }));
}

function csvCell(value) {
  let text = value == null ? "" : String(value);
  const formula = /^[=+\-@\t\r]/.test(text);
  if (formula) text = `'${text}`;
  return formula || /[",\r\n]/.test(text)
    ? `"${text.replace(/"/g, '""')}"`
    : text;
}

// Where a row's pivot button goes. An IOC row is a four-column grid with its own actions cell: a
// button appended to the row itself becomes a fifth grid child and starts a new line. Every other
// row takes the button as its last child.
export function pivotButtonHost(row) {
  return (row.matches(".ioc-row") && row.querySelector(".ioc-actions-cell")) || row;
}

export function csvFromRows(columns, rows) {
  return [
    columns.map(csvCell).join(","),
    ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(",")),
  ].join("\r\n") + "\r\n";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// The statuses savedHuntStore records. Anything else is shown as text but never becomes a class.
const RUN_STATUSES = new Set(["completed", "cancelled", "limited", "failed"]);
const HISTORY_COLUMNS = ["Time", "Analyst", "Status", "Matches", "Duration"];
// A cancelled run is recorded when the server's query unwinds, which can be after the client has
// already seen its own abort. Wait this long before reloading, so the "cancelled" row is there.
const CANCEL_RECORD_SETTLE_MS = 750;

function formatRunTime(iso) {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(String(iso ?? ""));
  return match ? `${match[1]} ${match[2]} UTC` : String(iso ?? "");
}

function formatDuration(ms) {
  const value = Number(ms) || 0;
  return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} s`;
}

function historyParams(entry) {
  const pairs = Object.entries(entry.parameters || {});
  const list = pairs.length
    ? `<ul>${pairs.map(([key, value]) => `<li><code>${escapeHtml(key)}</code> = <code>${escapeHtml(value === null ? "null" : value)}</code></li>`).join("")}</ul>`
    : "<div class='hq-help'>No parameters</div>";
  const error = entry.error ? `<div class="hq-error">${escapeHtml(entry.error)}</div>` : "";
  return `<tr class="hq-history-params"><td colspan="${HISTORY_COLUMNS.length}"><details><summary>Parameters</summary>${list}${error}</details></td></tr>`;
}

function historyRow(entry) {
  const status = RUN_STATUSES.has(entry.status) ? ` hq-run-${entry.status}` : "";
  return `<tr class="hq-history-run${status}"><td><time datetime="${escapeHtml(entry.executedAt)}">${escapeHtml(formatRunTime(entry.executedAt))}</time></td><td>${escapeHtml(entry.executedBy)}</td><td>${escapeHtml(entry.status)}</td><td title="${escapeHtml(entry.scanned)} row(s) scanned">${escapeHtml(entry.matched)}</td><td>${escapeHtml(formatDuration(entry.durationMs))}</td></tr>${historyParams(entry)}`;
}

/**
 * The execution history of one saved hunt, newest first (#1833). "" when no hunt is selected.
 * Analyst names, parameters and error text are untrusted: every value goes through escapeHtml.
 */
export function renderHuntHistory(hunt) {
  if (!hunt) return "";
  const runs = [...(Array.isArray(hunt.history) ? hunt.history : [])].sort((a, b) =>
    String(b.executedAt).localeCompare(String(a.executedAt)),
  );
  const title = "<div class='hq-history-title'>Execution history</div>";
  if (!runs.length) return `${title}<div class='hq-help'>Not run yet</div>`;
  return `${title}<table><thead><tr>${HISTORY_COLUMNS.map((column) => `<th>${column}</th>`).join("")}</tr></thead><tbody>${runs.map(historyRow).join("")}</tbody></table>`;
}

function installStyle() {
  const style = document.createElement("style");
  const runtimeStyles = document.getElementById("dfir-runtime-styles");
  if (runtimeStyles?.nonce) style.nonce = runtimeStyles.nonce;
  style.textContent = `
    #sec-hunt-workbench .hq-grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(220px,1fr);gap:12px}
    #sec-hunt-workbench textarea{width:100%;min-height:116px;box-sizing:border-box;background:var(--bg-primary);color:var(--text-bright);border:1px solid var(--border-color);border-radius:6px;padding:9px;font:12px var(--font-code);resize:vertical}
    #sec-hunt-workbench .hq-row{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:7px}
    #sec-hunt-workbench .hq-row input,#sec-hunt-workbench .hq-row select{min-width:120px}
    #sec-hunt-workbench .hq-help{font-size:11px;color:var(--text-muted);line-height:1.5}
    #sec-hunt-workbench .hq-status{font-size:12px;color:var(--text-muted);white-space:pre-wrap;margin:8px 0}
    #sec-hunt-workbench .hq-error{color:var(--badge-danger-text)}
    #sec-hunt-workbench .hq-suggestions{display:flex;gap:5px;flex-wrap:wrap;margin-top:5px}
    #sec-hunt-workbench .hq-suggestions button{font:11px var(--font-code);padding:2px 6px}
    #sec-hunt-workbench .hq-results{overflow:auto;max-height:520px;border-top:1px solid var(--border-subtle);margin-top:8px;padding-top:8px}
    #sec-hunt-workbench table{border-collapse:collapse;width:100%;font-size:12px}
    #sec-hunt-workbench th,#sec-hunt-workbench td{text-align:left;vertical-align:top;border-bottom:1px solid var(--border-subtle);padding:5px 7px}
    #sec-hunt-workbench th{position:sticky;top:0;background:var(--bg-secondary);z-index:1}
    #sec-hunt-workbench .hq-timeline-row{display:grid;grid-template-columns:28px 190px 72px minmax(220px,1fr);gap:7px;border-bottom:1px solid var(--border-subtle);padding:5px}
    #sec-hunt-workbench .hq-chart-row{display:grid;grid-template-columns:minmax(120px,1fr) 3fr 60px;gap:8px;align-items:center;margin:5px 0;font-size:12px}
    #sec-hunt-workbench .hq-bar{height:12px;background:var(--accent-solid);border-radius:3px;min-width:2px}
    #sec-hunt-workbench .hq-history{margin-top:10px;max-height:260px;overflow:auto}
    #sec-hunt-workbench .hq-history:empty{display:none}
    #sec-hunt-workbench .hq-history table{font-size:11px}
    #sec-hunt-workbench .hq-history th,#sec-hunt-workbench .hq-history td{padding:4px 5px}
    #sec-hunt-workbench .hq-history time{white-space:nowrap}
    #sec-hunt-workbench .hq-history-run td:nth-child(2){overflow-wrap:anywhere}
    #sec-hunt-workbench .hq-history-title{font-size:12px;font-weight:600;margin-bottom:4px}
    #sec-hunt-workbench .hq-history-params td{border-bottom:1px solid var(--border-subtle);padding-top:0}
    #sec-hunt-workbench .hq-history-params summary{font-size:11px;color:var(--text-muted);cursor:pointer}
    #sec-hunt-workbench .hq-history-params ul{margin:4px 0;padding-left:18px}
    #sec-hunt-workbench .hq-history-run td{border-bottom:0}
    #sec-hunt-workbench .hq-run-failed td:nth-child(3),#sec-hunt-workbench .hq-run-cancelled td:nth-child(3){color:var(--badge-danger-text)}
    .hq-pivot{font-size:10px!important;padding:1px 4px!important;margin-left:4px!important;background:transparent!important;color:var(--accent)!important;border:1px solid var(--border-color)!important}
    @media(max-width:800px){#sec-hunt-workbench .hq-grid{grid-template-columns:1fr}#sec-hunt-workbench .hq-timeline-row{grid-template-columns:28px 1fr}}
  `;
  document.head.appendChild(style);
}

function initialize() {
  const section = document.getElementById("sec-hunt-workbench");
  if (!section) return;
  installStyle();
  const query = document.getElementById("hqQuery");
  const dataset = document.getElementById("hqDataset");
  const parameters = document.getElementById("hqParameters");
  const author = document.getElementById("hqAuthor");
  const status = document.getElementById("hqStatus");
  const results = document.getElementById("hqResults");
  const suggestions = document.getElementById("hqSuggestions");
  const savedSelect = document.getElementById("hqSaved");
  const history = document.getElementById("hqHistory");
  const runButton = document.getElementById("hqRun");
  const cancelButton = document.getElementById("hqCancel");
  const nextButton = document.getElementById("hqNext");
  let fieldNames = [...STATIC_FIELDS];
  let savedHunts = [];
  let lastResult = null;
  let lastCursor = null;
  let mode = "table";
  let selected = new Set();
  let running = null;
  let executionId = null;
  let validationTimer = null;
  // The status line has many writers, and validate() answers late (#1777). Every write bumps this
  // ticket; a validate reply is shown only when nothing else wrote since that validate started.
  let statusSeq = 0;
  // Only the newest saved-hunt list may land: a slow reply for the previous case must not win.
  let loadSeq = 0;
  // The case the saved-hunt list was asked for, and the case it belongs to. History shows only
  // when the list belongs to the open case: another case's analysts and parameters never leak.
  let requestedCase = "";
  let savedCase = "";
  let cancelRequest = null;

  const caseId = () => (document.getElementById("caseId")?.value || "").trim();
  const endpoint = (suffix) =>
    `/cases/${encodeURIComponent(caseId())}/hunt-query${suffix}`;
  const selectedIds = () =>
    selected.size
      ? [...selected]
      : (lastResult?.events || []).map((event) => event.id);

  async function jsonRequest(url, options = {}) {
    const response = await fetch(url, options);
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail =
        typeof body.error === "string"
          ? body.error
          : body.error?.message || "request failed";
      const error = new Error(detail);
      error.body = body;
      throw error;
    }
    return body;
  }

  function setStatus(text, isError = false) {
    statusSeq += 1;
    status.className = isError ? "hq-status hq-error" : "hq-status";
    status.textContent = text;
  }

  function renderHistory() {
    if (!history) return;
    const current =
      savedCase === caseId()
        ? savedHunts.find((hunt) => hunt.id === savedSelect.value)
        : null;
    history.innerHTML = renderHuntHistory(current);
  }

  function reportActionError(error) {
    setStatus(error instanceof Error ? error.message : "The action failed.", true);
  }

  function parseParameters() {
    const output = {};
    for (const part of parameters.value.split(",")) {
      const [rawKey, ...rest] = part.split("=");
      const key = rawKey.trim();
      if (!key) continue;
      const raw = rest.join("=").trim();
      output[key] =
        raw === "true"
          ? true
          : raw === "false"
            ? false
            : raw === "null"
              ? null
              : raw !== "" && Number.isFinite(Number(raw))
                ? Number(raw)
                : raw;
    }
    return output;
  }

  function renderSuggestions() {
    const items = autocompleteFor(query.value, query.selectionStart, fieldNames);
    suggestions.innerHTML = items
      .map(
        (item) =>
          `<button type="button" data-hq-complete="${escapeHtml(item.value)}">${escapeHtml(item.label)}</button>`,
      )
      .join("");
  }

  function eventRow(event, timeline) {
    const checked = selected.has(event.id) ? " checked" : "";
    if (timeline) {
      return `<div class="hq-timeline-row"><input type="checkbox" data-hq-select="${escapeHtml(event.id)}"${checked}><span>${escapeHtml(event.timestamp || "(undated)")}</span><span class="sev-${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span><span><strong>${escapeHtml(event.asset || "")}</strong> ${escapeHtml(event.description)}</span></div>`;
    }
    return `<tr><td><input type="checkbox" data-hq-select="${escapeHtml(event.id)}"${checked}></td><td>${escapeHtml(event.timestamp || "")}</td><td>${escapeHtml(event.severity || "")}</td><td>${escapeHtml(event.asset || "")}</td><td>${escapeHtml(event.description || "")}</td></tr>`;
  }

  function renderChart() {
    const rows = lastResult?.rows || [];
    if (!rows.length) {
      results.innerHTML = "<div class='hq-help'>Charts are available for grouped, stats, count and rare-value results.</div>";
      return;
    }
    const valueColumn =
      lastResult.columns.find((column) =>
        rows.some((row) => typeof row[column] === "number"),
      ) || "count";
    const labelColumn =
      lastResult.columns.find((column) => column !== valueColumn) || valueColumn;
    const max = Math.max(1, ...rows.map((row) => Number(row[valueColumn]) || 0));
    results.innerHTML = rows
      .slice(0, 30)
      .map((row) => {
        const value = Number(row[valueColumn]) || 0;
        return `<div class="hq-chart-row"><span>${escapeHtml(row[labelColumn])}</span><span class="hq-bar" data-safe-style="width:${Math.max(1, (value / max) * 100)}%"></span><span>${escapeHtml(value)}</span></div>`;
      })
      .join("");
  }

  function renderResults() {
    if (!lastResult) {
      results.innerHTML = "<div class='hq-help'>Run a query to see results.</div>";
      return;
    }
    if (mode === "chart") {
      renderChart();
      return;
    }
    if (lastResult.rows?.length) {
      results.innerHTML = `<table><thead><tr>${lastResult.columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr></thead><tbody>${lastResult.rows
        .map(
          (row) =>
            `<tr>${lastResult.columns.map((column) => `<td>${escapeHtml(row[column])}</td>`).join("")}</tr>`,
        )
        .join("")}</tbody></table>`;
      return;
    }
    const events = lastResult.events || [];
    results.innerHTML =
      mode === "timeline"
        ? events.map((event) => eventRow(event, true)).join("")
        : `<table><thead><tr><th></th><th>Time</th><th>Severity</th><th>Host</th><th>Event</th></tr></thead><tbody>${events.map((event) => eventRow(event, false)).join("")}</tbody></table>`;
  }

  function updateActionState() {
    const superDataset = lastResult?.dataset === "super";
    for (const id of ["hqNotebook", "hqFindingEvidence"]) {
      const button = document.getElementById(id);
      if (button) {
        button.disabled = !lastResult || superDataset;
        button.title = superDataset
          ? "Promote individual super-timeline rows before using them in synthesis-facing evidence"
          : "";
      }
    }
    nextButton.disabled = !lastCursor;
  }

  async function validate() {
    if (!caseId() || !query.value.trim()) return;
    const ticket = ++statusSeq;
    try {
      const body = await jsonRequest(endpoint("/validate"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: query.value }),
      });
      if (ticket === statusSeq) setStatus(body.explanation);
    } catch (error) {
      if (ticket !== statusSeq) return;
      const typed = error.body?.error;
      setStatus(
        typed?.line
          ? `${typed.message} — line ${typed.line}, column ${typed.column}${typed.suggestions?.length ? `; try ${typed.suggestions.join(", ")}` : ""}`
          : error.message,
        true,
      );
    }
  }

  async function run(cursor = null) {
    clearTimeout(validationTimer);
    if (!caseId()) {
      setStatus("Open a case first.");
      return;
    }
    running?.abort();
    running = new AbortController();
    executionId = crypto.randomUUID();
    runButton.disabled = true;
    cancelButton.disabled = false;
    setStatus("Running bounded indexed query…");
    if (!cursor) selected = new Set();
    const savedHuntId = savedSelect.value || undefined;
    let cancelled = false;
    try {
      const body = await jsonRequest(endpoint("/execute"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: running.signal,
        body: JSON.stringify({
          query: query.value,
          dataset: dataset.value,
          parameters: parseParameters(),
          author: author.value || "anonymous",
          limit: 100,
          cursor: cursor || undefined,
          savedHuntId: cursor ? undefined : savedHuntId,
          executionId,
        }),
      });
      lastResult = body;
      lastCursor = body.nextCursor;
      setStatus(
        `${body.matched} match(es) on this result, ${body.scanned} row(s) scanned in ${body.durationMs} ms.\n${body.explanation}`,
      );
      renderResults();
      updateActionState();
    } catch (error) {
      cancelled = error.name === "AbortError";
      setStatus(cancelled ? "Query cancelled." : error.message, true);
    } finally {
      running = null;
      executionId = null;
      runButton.disabled = false;
      cancelButton.disabled = true;
    }
    // The server records failed runs too, so the history refreshes either way (#1833).
    if (!savedHuntId || cursor) return;
    if (cancelled) {
      await cancelRequest;
      await new Promise((resolve) => setTimeout(resolve, CANCEL_RECORD_SETTLE_MS));
    }
    await loadSaved();
  }

  // Rebuilding the options resets the select, so a Run of a saved hunt used to drop the selection
  // and Delete/Save/the next Run all lost track of the hunt (#1776). Keep it when it still exists;
  // a case change passes keep: false, because the old id does not belong to the new case.
  async function loadSaved({ keep = true } = {}) {
    const load = ++loadSeq;
    const forCase = caseId();
    requestedCase = forCase;
    if (!keep) {
      savedHunts = [];
      renderHistory();
    }
    if (!forCase) return;
    const previous = keep ? savedSelect.value : "";
    try {
      const hunts = await jsonRequest(endpoint("/saved"));
      if (load !== loadSeq) return;
      savedHunts = hunts;
      savedCase = forCase;
      savedSelect.innerHTML =
        '<option value="">Unsaved query</option>' +
        savedHunts
          .map(
            (hunt) =>
              `<option value="${escapeHtml(hunt.id)}">${escapeHtml(hunt.name)} · ${escapeHtml(hunt.dataset)}</option>`,
          )
          .join("");
      if (previous && savedHunts.some((hunt) => hunt.id === previous)) savedSelect.value = previous;
      renderHistory();
    } catch {
      if (load !== loadSeq) return;
      savedHunts = [];
      renderHistory();
    }
  }

  async function saveHunt() {
    clearTimeout(validationTimer);
    if (!caseId()) return;
    const existing = savedHunts.find((hunt) => hunt.id === savedSelect.value);
    const name =
      prompt("Saved hunt name", existing?.name || "New hunt")?.trim() || "";
    if (!name) return;
    try {
      const body = {
        name,
        query: query.value,
        dataset: dataset.value,
        author: author.value || "anonymous",
        parameters: parseParameters(),
      };
      const saved = await jsonRequest(
        endpoint(existing ? `/saved/${existing.id}` : "/saved"),
        {
          method: existing ? "PUT" : "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      await loadSaved();
      savedSelect.value = saved.id;
      renderHistory();
      setStatus(`Saved “${saved.name}”.`);
    } catch (error) {
      setStatus(error.message, true);
    }
  }

  async function deleteHunt() {
    if (!savedSelect.value) {
      setStatus("Select a saved hunt first.");
      return;
    }
    if (!confirm("Delete this saved hunt and its execution history?")) return;
    const response = await fetch(endpoint(`/saved/${encodeURIComponent(savedSelect.value)}`), {
      method: "DELETE",
    });
    if (!response.ok) throw new Error(`Delete failed (${response.status}).`);
    await loadSaved();
    setStatus("Deleted the saved hunt.");
  }

  function rowsForExport() {
    if (lastResult?.rows?.length) {
      return { columns: lastResult.columns, rows: lastResult.rows };
    }
    return {
      columns: DEFAULT_COLUMNS,
      rows: (lastResult?.events || []).map((event) => ({
        id: event.id,
        timestamp: event.timestamp,
        severity: event.severity,
        "host.name": event.asset || "",
        description: event.description,
      })),
    };
  }

  function exportCsv() {
    if (!lastResult) return;
    const data = rowsForExport();
    const blob = new Blob([csvFromRows(data.columns, data.rows)], {
      type: "text/csv;charset=utf-8",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${caseId()}-hunt-results.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  async function addNotebook() {
    if (lastResult?.dataset !== "forensic") return;
    const ids = selectedIds().slice(0, 100);
    const text = `Hunt query (${dataset.value}) returned ${lastResult?.matched || 0} match(es): ${query.value}`;
    await jsonRequest(`/cases/${encodeURIComponent(caseId())}/notebook`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        text,
        type: "note",
        author: author.value || "anonymous",
        linkedEntityIds: ids,
      }),
    });
    setStatus("Added the hunt and selected result links to the analyst notebook.");
  }

  async function attachFinding() {
    if (lastResult?.dataset !== "forensic") return;
    const findingId = prompt("Finding ID to attach selected events to")?.trim();
    if (!findingId) return;
    const body = await jsonRequest(endpoint("/finding-evidence"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        dataset: lastResult.dataset,
        findingId,
        eventIds: selectedIds(),
      }),
    });
    setStatus(`Attached ${body.addedEventIds.length} forensic event(s) to ${findingId}.`);
  }

  query.addEventListener("input", () => {
    renderSuggestions();
    clearTimeout(validationTimer);
    statusSeq += 1; // an edit makes any in-flight validate reply stale
    validationTimer = setTimeout(validate, 350);
  });
  suggestions.addEventListener("click", (event) => {
    const button = event.target.closest("[data-hq-complete]");
    if (!button) return;
    const word = currentWord(query.value, query.selectionStart);
    const start = query.selectionStart - word.length;
    query.setRangeText(
      button.dataset.hqComplete,
      start,
      query.selectionStart,
      "end",
    );
    statusSeq += 1; // a completion is a query edit too: an in-flight validate is now stale
    query.focus();
    renderSuggestions();
    // setRangeText fires no input event, so schedule the validate the input handler would have
    // (#1912) — otherwise the preview keeps the error for the text the completion just replaced.
    clearTimeout(validationTimer);
    validationTimer = setTimeout(validate, 350);
  });
  savedSelect.addEventListener("change", () => {
    const hunt = savedHunts.find((item) => item.id === savedSelect.value);
    renderHistory();
    if (!hunt) return;
    query.value = hunt.query;
    dataset.value = hunt.dataset;
    author.value = hunt.author;
    parameters.value = Object.entries(hunt.parameters)
      .map(([key, value]) => `${key}=${value ?? "null"}`)
      .join(", ");
    validate();
  });
  results.addEventListener("change", (event) => {
    const checkbox = event.target.closest("[data-hq-select]");
    if (!checkbox) return;
    if (checkbox.checked) selected.add(checkbox.dataset.hqSelect);
    else selected.delete(checkbox.dataset.hqSelect);
  });
  document.getElementById("hqExplain").addEventListener("click", validate);
  runButton.addEventListener("click", () => run());
  cancelButton.addEventListener("click", async () => {
    running?.abort();
    if (executionId) {
      cancelRequest = fetch(endpoint(`/executions/${executionId}/cancel`), {
        method: "POST",
      }).catch(() => {});
      await cancelRequest;
    }
  });
  nextButton.addEventListener("click", () => run(lastCursor));
  document.getElementById("hqSave").addEventListener("click", saveHunt);
  document.getElementById("hqDelete").addEventListener("click", () => {
    void deleteHunt().catch(reportActionError);
  });
  document.getElementById("hqExport").addEventListener("click", exportCsv);
  document.getElementById("hqNotebook").addEventListener("click", () => {
    void addNotebook().catch(reportActionError);
  });
  document.getElementById("hqFindingEvidence").addEventListener("click", () => {
    void attachFinding().catch(reportActionError);
  });
  document.querySelectorAll("[data-hq-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      mode = button.dataset.hqMode;
      renderResults();
    });
  });
  // `change` only: the case picker replays input+change on one case change, and an input
  // listener here doubled every saved-hunts request (#1962).
  const loadSavedForCase = () => loadSaved({ keep: false });
  document.getElementById("caseId")?.addEventListener("change", loadSavedForCase);

  async function loadCatalog() {
    if (!caseId()) return;
    try {
      const catalog = await jsonRequest(endpoint("/catalog"));
      fieldNames = catalog.fields.map((field) => field.name);
      document.getElementById("hqGrammar").textContent = catalog.grammar;
    } catch {
      fieldNames = [...STATIC_FIELDS];
    }
  }

  function pivot(kind, value, pivotDataset) {
    query.value = buildPivotQuery(kind, value);
    if (pivotDataset) dataset.value = pivotDataset;
    section.classList.remove("collapsed");
    section.scrollIntoView({ behavior: "smooth", block: "start" });
    query.focus();
    validate();
  }

  function addPivotButtons() {
    document
      .querySelectorAll(
        ".ev-row[data-evid],.ioc-row[data-iocid],.finding[data-fid],.asset-chip",
      )
      .forEach((row) => {
        if (row.querySelector(".hq-pivot")) return;
        let kind;
        let value;
        let pivotDataset;
        if (row.matches(".ev-row[data-evid]")) {
          kind = "event";
          value = row.dataset.evid;
          pivotDataset = row.closest("#superTimelineList")
            ? "super"
            : "forensic";
        } else if (row.matches(".ioc-row[data-iocid]")) {
          kind = "ioc";
          value = row.querySelector("[data-val]")?.dataset.val;
          pivotDataset = "forensic";
        } else if (row.matches(".finding[data-fid]")) {
          kind = "finding";
          value = row.dataset.fid;
          pivotDataset = "forensic";
        } else {
          const assetControl = row.querySelector("[data-assetid][data-name]");
          kind = "asset";
          value = assetControl?.dataset.name;
          pivotDataset = "forensic";
        }
        if (!value) return;
        const button = document.createElement("button");
        button.type = "button";
        button.className = "hq-pivot hunt-add";
        button.textContent = "⌕";
        button.title = "Pivot this entity into Hunt Workbench";
        button.addEventListener("click", (event) => {
          event.stopPropagation();
          pivot(kind, value, pivotDataset);
        });
        pivotButtonHost(row).appendChild(button);
      });
  }

  let pivotQueued = false;
  new MutationObserver(() => {
    if (pivotQueued) return;
    pivotQueued = true;
    requestAnimationFrame(() => {
      pivotQueued = false;
      addPivotButtons();
      // New-case, demo-case and import set the case box without an input/change event. The
      // dashboard re-renders after any case opens, so this is where a silent switch is noticed.
      if (caseId() !== requestedCase) {
        loadSavedForCase();
        loadCatalog();
      }
    });
  }).observe(document.body, { childList: true, subtree: true });

  author.value = localStorage.getItem("dfir.huntAuthor") || "";
  author.addEventListener("change", () =>
    localStorage.setItem("dfir.huntAuthor", author.value),
  );
  renderSuggestions();
  renderResults();
  updateActionState();
  loadCatalog();
  loadSaved();
  addPivotButtons();
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
}
