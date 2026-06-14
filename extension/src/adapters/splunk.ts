import type { Adapter } from "./types.js";
import { asArray, getPath, isObject } from "./extractUtils.js";

// Splunk Web. The search UI fetches job results as JSON from
// `…/services/search/v2/jobs/<sid>/results` (often proxied through `/<locale>/splunkd/__raw/…`).
// The results envelope is `{ preview, init_offset, results: [ {field: value, …}, … ], fields }`.
export const splunkAdapter: Adapter = {
  id: "splunk",
  label: "Splunk",

  matchUrl(url: URL): boolean {
    if (/splunk/i.test(url.hostname)) return true;
    // Splunk Web serves the app UI under /<locale>/app/<app>/… (e.g. /en-US/app/search/search).
    if (/^\/[a-z]{2}-[a-z]{2}\/(app|account|manager)\//i.test(url.pathname)) return true;
    if (url.port === "8000" && /\/(app|splunkd)\b/i.test(url.pathname)) return true;
    return false;
  },

  apiPatterns: [
    "/services/search/.*/results",
    "/splunkd/__raw/.*/results",
    "/search/jobs/.*/results",
  ],

  extractRows(_url: string, body: unknown): unknown[] | null {
    if (!isObject(body)) return null;
    // The standard `output_mode=json` envelope: results already objects.
    const results = asArray(getPath(body, "results"));
    if (results) return results;
    // `output_mode=json_rows` variant: { fields: [{name}|name], rows: [[cell, …]] } — zip them.
    const fields = body.fields;
    const rows = body.rows;
    if (Array.isArray(fields) && Array.isArray(rows) && rows.length) {
      const names = fields.map((f) => (isObject(f) && typeof f.name === "string" ? f.name : String(f)));
      return rows.map((row) => {
        const cells = Array.isArray(row) ? row : [row];
        const obj: Record<string, unknown> = {};
        names.forEach((n, i) => { obj[n] = cells[i]; });
        return obj;
      });
    }
    return null;
  },

  tableSelector: "table.results-table-master, table[data-test='results-table'], table",
};
