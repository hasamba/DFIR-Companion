import type { Adapter } from "./types.js";
import { asArray, getPath, isObject, zipColumnsRows } from "./extractUtils.js";

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
    const zipped = zipColumnsRows(body);
    if (zipped && zipped.length) return zipped;
    // Some endpoints return an array directly, or { items: [...] }.
    if (Array.isArray(body)) return body.length ? body : null;
    if (isObject(body)) return asArray(getPath(body, "items"));
    return null;
  },

  tableSelector: "table",
};
