// Text alternative for the swimlane timeline chart.
//
// #swimlaneCanvas is a <canvas>. Everything it conveys — which host, when, how severe, in what
// order — is drawn as pixels, so it is not in the accessibility tree at all: a screen reader
// reaching it finds an empty graphic and the entire visual timeline is simply missing. #386 asks
// that "graphs and charts have navigable table/text alternatives", and a real <table> is that
// alternative: it can be navigated by row and column with standard screen-reader table commands,
// which a prose summary cannot.
//
// Applied to the swimlane here. The Cytoscape graphs and the Leaflet map get theirs as #384
// reaches those components; the a11y ledger keeps that deferral honest.

/** Same corroboration suffix the visual detail panel strips, so both readings agree. */
const CORROBORATION_SUFFIX = /\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i;

/**
 * Flatten the swimlane's lanes into one row per event, in chronological order.
 *
 * Pure, so it is unit-testable under the suite's node environment.
 *
 * Sorting matters: the canvas conveys ordering through horizontal position, which a table cannot
 * reproduce. Lane-by-lane order would present the same events in an order that implies a different
 * sequence of the attack, which is worse than offering no table at all.
 *
 * @param {Array<{label?: string, events?: Array<Record<string, unknown>>}>} lanes
 * @returns {Array<{lane: string, timestamp: string, severity: string, description: string}>}
 */
export function laneRows(lanes) {
  const rows = [];
  for (const lane of lanes || []) {
    for (const ev of lane.events || []) {
      rows.push({
        lane: String(lane.label || ""),
        timestamp: String(ev.timestamp || ""),
        severity: String(ev.severity || ""),
        description: String(ev.description || "").replace(CORROBORATION_SUFFIX, ""),
      });
    }
  }
  rows.sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
  return rows;
}

/**
 * Project rows onto an ordered column list. Pure.
 * @param {Array<Record<string, unknown>>} rows
 * @param {string[]} columns
 * @returns {{ columns: string[], rows: string[][] }}
 */
export function buildTableModel(rows, columns) {
  return {
    columns: [...columns],
    rows: (rows || []).map((row) => columns.map((c) => (row[c] === undefined ? "" : String(row[c])))),
  };
}

/**
 * Render the model into `host` as a real table behind a disclosure toggle.
 * @param {HTMLElement} host
 * @param {{ columns: string[], rows: string[][] }} model
 * @param {string} caption
 */
export function renderTableAlternative(host, model, caption) {
  if (!host) return;

  // REBUILD ONLY WHEN THE DATA CHANGED.
  //
  // The canvas is redrawn on hover, pan, zoom, resize and a timer, and this runs after each draw.
  // Rebuilding unconditionally tore out the DOM every time, which silently destroyed keyboard
  // focus if the user was on the disclosure control and slammed the table shut if they had opened
  // it — so the table was, in practice, unusable by the people it exists for.
  const signature = `${model.columns.join("|")}#${model.rows.length}#${model.rows.map((r) => r.join("|")).join("~")}`;
  if (host.dataset.tableSignature === signature) return;
  host.dataset.tableSignature = signature;

  // Survive a genuine data change without collapsing a table the user deliberately opened.
  const wasOpen = host.querySelector("details")?.open === true;

  host.textContent = "";
  if (model.rows.length === 0) return;

  const details = document.createElement("details");
  details.className = "chart-table-alt";
  details.open = wasOpen;

  const summary = document.createElement("summary");
  summary.textContent = `View as table (${model.rows.length} events)`;
  details.appendChild(summary);

  const table = document.createElement("table");
  const cap = document.createElement("caption");
  cap.textContent = caption;
  table.appendChild(cap);

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const col of model.columns) {
    const th = document.createElement("th");
    th.scope = "col";
    th.textContent = col;
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  for (const row of model.rows) {
    const tr = document.createElement("tr");
    for (const cell of row) {
      const td = document.createElement("td");
      td.textContent = cell;
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  details.appendChild(table);
  host.appendChild(details);
}

const COLUMNS = ["lane", "timestamp", "severity", "description"];

/**
 * Rebuild the swimlane's table alternative. Called by dashboard.html after it draws the canvas,
 * with the same lane data the canvas was drawn from — deriving it from a second query could drift
 * from what is actually on screen.
 * @param {Array<{label?: string, events?: Array<Record<string, unknown>>}>} lanes
 */
function renderSwimlaneTable(lanes) {
  renderTableAlternative(
    document.getElementById("swimlaneTableAlt"),
    buildTableModel(laneRows(lanes), COLUMNS),
    "Swimlane timeline events, in chronological order",
  );
}

function wire() {
  // dashboard.html's swimlane code is a classic inline script, so it cannot import this module.
  // The global is the bridge, matching how command-palette.js publishes window.DfirPalette.
  window.DfirChartTable = { renderSwimlaneTable };
}

// Guarded so the pure exports above can be imported in node (Vitest) with no DOM present.
if (typeof document !== "undefined" && typeof window !== "undefined") wire();
