import type { Adapter } from "./types.js";
import { asArray, getPath, isObject } from "./extractUtils.js";

// Security Onion Console (SOC) — the native Alerts / Hunt UI. SOC is a Vue SPA using hash routing
// (createWebHashHistory), so its views live at https://<manager>/#/hunt , #/alerts , #/dashboards —
// hence matchUrl reads url.hash (robust to any host / reverse-proxy prefix). These three are the
// EVENT-bearing views (they query GET /api/events/, returning an EventSearchResults envelope:
// { events: [{ id, source, timestamp, score, payload }], metrics, … }). We deliberately do NOT match
// #/detections (the rule CATALOG — Sigma rule definitions, mostly disabled, not events) or #/cases
// (case management) — pushing those pollutes the forensic timeline with non-events. `payload` is the
// flattened ECS document (dotted keys). We flatten each event to its payload — exactly like the
// Elastic adapter flattens hits.hits[]._source — and IGNORE `metrics` (groupby buckets carry only
// {keys, count}, no forensic detail). API + hash routing verified identical on securityonion-soc
// 2.4/main and 3/main, so this covers SO 2.4 and 3.x.
export const securityOnionAdapter: Adapter = {
  id: "securityonion",
  label: "Security Onion",

  matchUrl(url: URL): boolean {
    return /^#\/(alerts|hunt|dashboards)\b/i.test(url.hash);
  },

  // Fallback for SOC pages matchUrl misses — e.g. the app's initial load before the hash router
  // has picked a view, or a reverse-proxied deployment. SOC titles every page "Security Onion".
  matchDom(doc: Document): boolean {
    return /security onion/i.test(doc.title);
  },

  apiPatterns: ["/api/events/"],

  extractRows(_url: string, body: unknown): unknown[] | null {
    if (!isObject(body)) return null;
    const events = asArray(getPath(body, "events"));
    if (!events || events.length === 0) return null; // metrics-only / empty → nothing to push
    return events.map((rec) => {
      if (!isObject(rec)) return rec;
      const payload = isObject(rec.payload) ? rec.payload : {};
      // Flatten to the ECS payload, carrying the doc id/index as metadata (mirrors elastic).
      const row: Record<string, unknown> = { _id: rec.id, _index: rec.source, ...payload };
      // Carry the record's own timestamp only when the payload has no time field of its own.
      if (row["@timestamp"] === undefined && row["timestamp"] === undefined && rec.timestamp) {
        row.timestamp = rec.timestamp;
      }
      return row;
    });
  },

  // Attribute each pushed row to the SOC view it came from (stamped as _Source for navigate-back).
  sourceLabel(opts: { apiUrl: string; pageUrl: string; domInputs: readonly string[]; domHeadings: readonly string[]; rows: readonly unknown[] }): string {
    const m = /#\/(alerts|hunt|dashboards)\b/i.exec(opts.pageUrl);
    if (!m) return "";
    const view = m[1].toLowerCase();
    return `Security Onion ${view.charAt(0).toUpperCase()}${view.slice(1)}`;
  },

  tableSelector: "table",
};
