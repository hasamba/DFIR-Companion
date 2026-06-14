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
    // The GUI renders its own internal tables (notebook selector, hunt list) through the SAME
    // GetTable API, so they get intercepted too. Skip the notebook-selector list — it's metadata,
    // not artifact results, and would otherwise shadow the table the analyst is actually reading.
    if (isNotebookList(rows)) return null;
    return rows;
  },

  tableSelector: "table",
};

// The notebook-selector list — { NotebookId, Name, Collaborators, … } per row — is Velociraptor's
// own UI chrome, never artifact evidence.
function isNotebookList(rows: unknown[]): boolean {
  const first = rows.find((r) => isObject(r)) as Record<string, unknown> | undefined;
  return !!first && ("NotebookId" in first || "Collaborators" in first);
}
