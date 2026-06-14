import type { Adapter } from "./types.js";
import { asArray, getPath, isObject, unflattenDotted, zipColumnsRows } from "./extractUtils.js";

// Velociraptor GUI (default `/app/index.html` on :8889). The table widgets fetch rows from the API
// at `/api/v1/GetTable` (and `GetHuntResults`), whose envelope is `{ columns: string[], rows: [...] }`
// — each row a { cell: [...] } wrapper or a raw array. We zip columns onto cells to recover the
// VQL row objects the rest of the companion's Velociraptor importer already understands.
export const velociraptorAdapter: Adapter = {
  id: "velociraptor",
  label: "Velociraptor",

  matchUrl(url: URL): boolean {
    if (/velociraptor/i.test(url.hostname)) return true;
    if (/^\/app\/index\.html/i.test(url.pathname)) return true;
    if (url.port === "8889" && /^\/(app|api)\b/i.test(url.pathname)) return true;
    return false;
  },

  apiPatterns: [
    "/api/v1/GetTable",
    "/api/v1/GetHuntResults",
    "/api/v1/GetClientFlows",
  ],

  extractRows(_url: string, body: unknown): unknown[] | null {
    let rows: unknown[] | null = null;
    const zipped = zipColumnsRows(body);
    if (zipped && zipped.length) {
      // Un-flatten the GUI's dotted column names (Detection.Name → Detection: { Name }) so the
      // companion's importer reads the detection verdict + nested time/host keys.
      rows = zipped.map((r) => (isObject(r) ? unflattenDotted(r) : r));
    } else if (Array.isArray(body)) {
      rows = body.length ? body : null; // some endpoints return an array directly
    } else if (isObject(body)) {
      rows = asArray(getPath(body, "items"));
    }
    if (!rows) return null;
    // The GUI drives its own internal tables (notebook selector, column value-count facets) through
    // the SAME GetTable API, so they get intercepted too and would shadow the results grid the
    // analyst is actually reading. Skip them — they're UI chrome / stats, not artifact evidence.
    if (isInternalTable(rows)) return null;
    return rows;
  },

  tableSelector: "table",

  sourceLabel: velociraptorSourceLabel,
};

// A Velociraptor artifact name: ≥3 dot-separated identifier segments (Windows.Hayabusa.Rules,
// DetectRaptor.Windows.Detection.Applications). Specific enough not to match a search box or a count.
const ARTIFACT_RE = /^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*){2,}$/;

// Best-effort SOURCE LABEL for a captured table, so each pushed row can record the artifact/notebook
// it came from and the analyst can navigate back. The results tab picks the artifact in a combo box
// WITHOUT changing the address bar, so no single signal is reliable — try, in order:
//   1. the GetTable request's `artifact=` query param (the server is told which artifact to fetch)
//   2. a row's own `_Source`/`Artifact` (notebook VQL `source(artifact=…)`, or an artifact-map)
//   3. the combo-box artifact name read from the page's <input> values (results tab)
//   4. the notebook id from the page hash (#/…/notebooks/N.xxx)
// Pure (the DOM <input> values are passed in) → unit-tested.
export function velociraptorSourceLabel(opts: {
  apiUrl?: string; pageUrl?: string; domInputs?: readonly string[]; rows?: readonly unknown[];
}): string {
  const { apiUrl = "", pageUrl = "", domInputs = [], rows = [] } = opts;
  const param = /[?&]artifact=([^&]+)/i.exec(apiUrl);
  if (param) { try { const a = decodeURIComponent(param[1]).trim(); if (a) return a; } catch { /* bad escape */ } }
  for (const r of rows) {
    if (r && typeof r === "object") {
      const s = (r as Record<string, unknown>)._Source ?? (r as Record<string, unknown>).Artifact;
      if (typeof s === "string" && s.trim()) return s.trim();
    }
  }
  for (const v of domInputs) { const t = (v || "").trim(); if (ARTIFACT_RE.test(t)) return t; }
  const nb = /#\/(?:fullscreen\/)?notebooks\/(N\.[A-Za-z0-9]+)/.exec(pageUrl);
  if (nb) return `notebook ${nb[1]}`;
  return "";
}

// Recognize Velociraptor's GUI-internal GetTable responses (never artifact evidence) — the GUI
// renders all of these through the SAME GetTable API as result grids, so they get intercepted and
// would shadow the results the analyst is viewing:
//   • flow / collection list — { State, FlowId, Artifacts[], Created, Mb, Rows, _Flow, … } per row
//     (the "collected artifacts" table that's ALWAYS shown above a flow's results)
//   • hunt list — { HuntId, … }
//   • notebook-selector list — { NotebookId, Name, Collaborators, … }
//   • column value-count facet — { value, idx, c } (the column filter/stats dropdown)
function isInternalTable(rows: unknown[]): boolean {
  const first = rows.find((r) => isObject(r)) as Record<string, unknown> | undefined;
  if (!first) return false;
  if ("FlowId" in first || "_Flow" in first || "_ArtifactsWithResults" in first || "HuntId" in first) return true;
  if ("NotebookId" in first || "Collaborators" in first) return true;
  if ("value" in first && "c" in first && Object.keys(first).length <= 3) return true;
  return false;
}
