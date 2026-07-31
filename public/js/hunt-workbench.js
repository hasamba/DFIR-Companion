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

export function csvFromRows(columns, rows) {
  return [
    columns.map(csvCell).join(","),
    ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(",")),
  ].join("\r\n") + "\r\n";
}

function installStyle() {
  const style = document.createElement("style");
  style.textContent = `
    #sec-hunt-workbench .hq-grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(220px,1fr);gap:12px}
    #sec-hunt-workbench textarea{width:100%;min-height:116px;box-sizing:border-box;background:var(--bg-primary);color:var(--text-bright);border:1px solid var(--border-color);border-radius:6px;padding:9px;font:12px ui-monospace,Menlo,Consolas,monospace;resize:vertical}
    #sec-hunt-workbench .hq-row{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:7px}
    #sec-hunt-workbench .hq-row input,#sec-hunt-workbench .hq-row select{min-width:120px}
    #sec-hunt-workbench .hq-help{font-size:11px;color:var(--text-muted);line-height:1.5}
    #sec-hunt-workbench .hq-status{font-size:12px;color:var(--text-muted);white-space:pre-wrap;margin:8px 0}
    #sec-hunt-workbench .hq-error{color:var(--badge-danger-text)}
    #sec-hunt-workbench .hq-suggestions{display:flex;gap:5px;flex-wrap:wrap;margin-top:5px}
    #sec-hunt-workbench .hq-suggestions button{font:11px ui-monospace,Menlo,Consolas,monospace;padding:2px 6px}
    #sec-hunt-workbench .hq-results{overflow:auto;max-height:520px;border-top:1px solid var(--border-subtle);margin-top:8px;padding-top:8px}
    #sec-hunt-workbench table{border-collapse:collapse;width:100%;font-size:12px}
    #sec-hunt-workbench th,#sec-hunt-workbench td{text-align:left;vertical-align:top;border-bottom:1px solid var(--border-subtle);padding:5px 7px}
    #sec-hunt-workbench th{position:sticky;top:0;background:var(--bg-secondary);z-index:1}
    #sec-hunt-workbench .hq-timeline-row{display:grid;grid-template-columns:28px 190px 72px minmax(220px,1fr);gap:7px;border-bottom:1px solid var(--border-subtle);padding:5px}
    #sec-hunt-workbench .hq-chart-row{display:grid;grid-template-columns:minmax(120px,1fr) 3fr 60px;gap:8px;align-items:center;margin:5px 0;font-size:12px}
    #sec-hunt-workbench .hq-bar{height:12px;background:var(--accent-solid);border-radius:3px;min-width:2px}
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

  const caseId = () => (document.getElementById("caseId")?.value || "").trim();
  const endpoint = (suffix) =>
    `/cases/${encodeURIComponent(caseId())}/hunt-query${suffix}`;
  const escapeHtml = (value) =>
    String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
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

  function reportActionError(error) {
    status.className = "hq-status hq-error";
    status.textContent =
      error instanceof Error ? error.message : "The action failed.";
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
        return `<div class="hq-chart-row"><span>${escapeHtml(row[labelColumn])}</span><span class="hq-bar" style="width:${Math.max(1, (value / max) * 100)}%"></span><span>${escapeHtml(value)}</span></div>`;
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
    try {
      const body = await jsonRequest(endpoint("/validate"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: query.value }),
      });
      status.className = "hq-status";
      status.textContent = body.explanation;
    } catch (error) {
      const typed = error.body?.error;
      status.className = "hq-status hq-error";
      status.textContent = typed?.line
        ? `${typed.message} — line ${typed.line}, column ${typed.column}${typed.suggestions?.length ? `; try ${typed.suggestions.join(", ")}` : ""}`
        : error.message;
    }
  }

  async function run(cursor = null) {
    if (!caseId()) {
      status.textContent = "Open a case first.";
      return;
    }
    running?.abort();
    running = new AbortController();
    executionId = crypto.randomUUID();
    runButton.disabled = true;
    cancelButton.disabled = false;
    status.className = "hq-status";
    status.textContent = "Running bounded indexed query…";
    if (!cursor) selected = new Set();
    try {
      const savedHuntId = savedSelect.value || undefined;
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
      status.textContent = `${body.matched} match(es) on this result, ${body.scanned} row(s) scanned in ${body.durationMs} ms.\n${body.explanation}`;
      renderResults();
      updateActionState();
      if (savedHuntId && !cursor) await loadSaved();
    } catch (error) {
      status.className = "hq-status hq-error";
      status.textContent =
        error.name === "AbortError" ? "Query cancelled." : error.message;
    } finally {
      running = null;
      executionId = null;
      runButton.disabled = false;
      cancelButton.disabled = true;
    }
  }

  async function loadSaved() {
    if (!caseId()) return;
    try {
      savedHunts = await jsonRequest(endpoint("/saved"));
      savedSelect.innerHTML =
        '<option value="">Unsaved query</option>' +
        savedHunts
          .map(
            (hunt) =>
              `<option value="${escapeHtml(hunt.id)}">${escapeHtml(hunt.name)} · ${escapeHtml(hunt.dataset)}</option>`,
          )
          .join("");
    } catch {
      savedHunts = [];
    }
  }

  async function saveHunt() {
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
      status.textContent = `Saved “${saved.name}”.`;
    } catch (error) {
      status.className = "hq-status hq-error";
      status.textContent = error.message;
    }
  }

  async function deleteHunt() {
    if (!savedSelect.value || !confirm("Delete this saved hunt and its execution history?")) return;
    const response = await fetch(endpoint(`/saved/${encodeURIComponent(savedSelect.value)}`), {
      method: "DELETE",
    });
    if (!response.ok) throw new Error(`Delete failed (${response.status}).`);
    await loadSaved();
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
    status.textContent = "Added the hunt and selected result links to the analyst notebook.";
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
    status.textContent = `Attached ${body.addedEventIds.length} forensic event(s) to ${findingId}.`;
  }

  query.addEventListener("input", () => {
    renderSuggestions();
    clearTimeout(validationTimer);
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
    query.focus();
    renderSuggestions();
  });
  savedSelect.addEventListener("change", () => {
    const hunt = savedHunts.find((item) => item.id === savedSelect.value);
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
      await fetch(endpoint(`/executions/${executionId}/cancel`), {
        method: "POST",
      }).catch(() => {});
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
  document.getElementById("caseId")?.addEventListener("change", loadSaved);
  document.getElementById("caseId")?.addEventListener("input", loadSaved);

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
        if (row.querySelector(":scope > .hq-pivot")) return;
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
        button.className = "hq-pivot";
        button.textContent = "⌕";
        button.title = "Pivot this entity into Hunt Workbench";
        button.addEventListener("click", (event) => {
          event.stopPropagation();
          pivot(kind, value, pivotDataset);
        });
        row.appendChild(button);
      });
  }

  let pivotQueued = false;
  new MutationObserver(() => {
    if (pivotQueued) return;
    pivotQueued = true;
    requestAnimationFrame(() => {
      pivotQueued = false;
      addPivotButtons();
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
