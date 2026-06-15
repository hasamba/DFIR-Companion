import type { Adapter } from "./types.js";
import { asArray, getPath, isObject } from "./extractUtils.js";

// Elastic / Kibana. Discover, the Security app, and dashboards run searches through the
// Elasticsearch `_search` API (directly, or via Kibana's `/internal/search` / `/internal/bsearch`
// proxy). The response carries `hits.hits[]`, each `{ _index, _id, _source: {…} }`; Kibana's
// bsearch nests it under `result.rawResponse`. We flatten each hit to its `_source` (keeping the
// `_id`/`_index` as metadata) so the companion sees one object per document.
export const elasticAdapter: Adapter = {
  id: "elastic",
  label: "Elastic / Kibana",

  matchUrl(url: URL): boolean {
    if (/(kibana|elastic)/i.test(url.hostname)) return true;
    // Kibana page paths only (API paths like /_search are handled by apiPatterns, not matchUrl).
    if (/^\/app\/(discover|kibana|dashboards|security|fleet)/i.test(url.pathname)) return true;
    if ((url.port === "5601" || url.port === "9200") && url.pathname !== "/") return true;
    return false;
  },

  apiPatterns: [
    "/_search",
    "/_async_search",
    "/internal/search",
    "/internal/bsearch",
  ],

  extractRows(_url: string, body: unknown): unknown[] | null {
    if (!isObject(body)) return null;
    // Plain ES response, or Kibana bsearch wrapper (result.rawResponse.hits.hits).
    const hits = asArray(getPath(body, "hits.hits")) ?? asArray(getPath(body, "result.rawResponse.hits.hits"))
      ?? asArray(getPath(body, "rawResponse.hits.hits"));
    if (!hits) return null;
    return hits.map((hit) => {
      if (!isObject(hit)) return hit;
      const src = hit._source;
      if (isObject(src)) {
        // Carry the document id/index alongside the source fields, without clobbering them.
        return { _id: hit._id, _index: hit._index, ...src };
      }
      return hit;
    });
  },

  tableSelector: "table",
};
