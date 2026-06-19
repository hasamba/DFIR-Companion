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
    if (/\/(app|splunkd)\b/i.test(url.pathname) && (url.port === "8000" || url.port === "7000")) return true;
    return false;
  },

  // Splunk results arrive via several URL patterns depending on version and deployment.
  // The v2 API (Splunk 9.x) uses /v2/jobs/<sid>/events (not /results); older builds use
  // /jobs/<sid>/results.  __raw is the direct REST pass-through; __proxy is an alternate path.
  // results_preview fires while a search is still running (Smart Mode).
  // All matched case-insensitively; `.*` and `[^/?]+` cross `/` as needed.
  apiPatterns: [
    "/splunkd/__raw/.*/v2/jobs/[^/?]+/events",
    "/splunkd/__raw/.*/v2/jobs/[^/?]+/results",
    "/splunkd/__raw/.*/results",
    "/splunkd/__proxy/.*/results",
    "/v2/jobs/[^/?]+/events",
    "/v2/jobs/[^/?]+/results",
    "/api/search/jobs/[^/?]+/results",
    "/services/search/jobs/[^/?]+/results",
    "/search/jobs/[^/?]+/results",
    "/search/jobs/.*/results_preview",
  ],

  extractRows(_url: string, body: unknown): unknown[] | null {
    if (!isObject(body)) return null;
    // The standard `output_mode=json` envelope: results already objects.
    const results = asArray(getPath(body, "results"));
    if (results) return results.map(enrichSplunkRow);
    // `output_mode=json_rows` variant: { fields: [{name}|name], rows: [[cell, …]] } — zip them.
    const fields = body.fields;
    const rows = body.rows;
    if (Array.isArray(fields) && Array.isArray(rows) && rows.length) {
      const names = fields.map((f) => (isObject(f) && typeof f.name === "string" ? f.name : String(f)));
      return rows.map((row) => {
        const cells = Array.isArray(row) ? row : [row];
        const obj: Record<string, unknown> = {};
        names.forEach((n, i) => { obj[n] = cells[i]; });
        return enrichSplunkRow(obj);
      });
    }
    return null;
  },

  tableSelector: "table.results-table-master, table[data-test='results-table'], table",

  // Splunk list-view DOM scrape: the table has only [i, Time, Event] columns, where "Event" is the
  // raw event text with Splunk's selected-field key=value pairs appended at the end.
  // Parse those pairs into proper field objects so Hayabusa/SIEM fields are preserved.
  processScrapedRows(rows: unknown[]): unknown[] {
    if (!Array.isArray(rows) || !rows.length) return rows;
    const first = rows[0];
    if (!isObject(first)) return rows;
    const keys = Object.keys(first);
    // Only applies when we have an "Event" column but no structured field names.
    if (!keys.includes("Event")) return rows;
    if (keys.some((k) => ["RuleTitle", "Level", "Channel", "EventID", "Timestamp"].includes(k))) return rows;
    return rows.map((row) => {
      if (!isObject(row)) return row;
      const r = row as Record<string, unknown>;
      const eventText = String(r.Event ?? "");
      const parsed = extractSplunkKvPairs(eventText);
      if (!Object.keys(parsed).length) return row;
      // The Hayabusa Timestamp (ISO with tz offset) is the first quoted CSV field in the raw event.
      if (!parsed.Timestamp) {
        const firstQuoted = eventText.match(/^"([^"]+)"/);
        if (firstQuoted && /^\d{4}-\d{2}-\d{2}/.test(firstQuoted[1])) {
          parsed.Timestamp = firstQuoted[1];
        }
      }
      // Preserve _time from Splunk's Time column as ultimate fallback for non-Hayabusa sources.
      if (r.Time != null && !parsed._time && !parsed.Timestamp) parsed._time = String(r.Time);
      return parsed;
    });
  },
};

// Enrich a row from Splunk's results API with Hayabusa fields that the custom-csv sourcetype
// often fails to extract:
//   Timestamp — Splunk's _time (ISO 8601 UTC) when the original CSV Timestamp column is absent.
//   Details   — Splunk's CSV extractor drops complex quoted fields (commas inside a quoted cell).
//               _raw always carries the full original indexed line, so we recover Details from it.
//               Modern Hayabusa uses ¦ (U+00A6 BROKEN BAR); older versions use | with surrounding
//               spaces. CallTrace entries use | WITHOUT spaces ("dll+addr|dll+addr"), so the space
//               requirement `\s[¦|]\s` avoids false-positives inside CallTrace values.
//               Two formats of _raw are handled:
//               • CSV-quoted:  ..., "Key: val ¦ Key: val", ...  → extract the quoted field
//               • Unquoted:   the whole _raw contains " ¦ " / " | " (no surrounding quotes)
function enrichSplunkRow(row: unknown): unknown {
  if (!isObject(row)) return row;
  let r = row as Record<string, unknown>;

  if (!r.Timestamp && !r.timestamp && r._time) {
    r = { ...r, Timestamp: String(r._time) };
  }

  if (!r.Details && r._raw) {
    // The /v2/jobs/<sid>/events endpoint returns _raw as an OBJECT
    // { value, trunc, tokens, segment_tree } whose `value` is the indexed line; the
    // /results endpoint returns _raw as a plain string. Normalize both to the raw line —
    // String(object) would yield "[object Object]" and the separator regex would never match.
    const raw =
      isObject(r._raw) && typeof (r._raw as Record<string, unknown>).value === "string"
        ? String((r._raw as Record<string, unknown>).value)
        : String(r._raw);
    // Try CSV-quoted Details field first (most common: _raw is the full original CSV line).
    const quoted = raw.match(/"([^"]*\s[¦|]\s[^"]*)"/);
    if (quoted) {
      r = { ...r, Details: quoted[1] };
    } else if (/\s[¦|]\s/.test(raw)) {
      // _raw is itself the Details string (Splunk stored it unquoted), or the separator
      // appears without surrounding quotes — use the whole value.
      r = { ...r, Details: raw };
    }
  }

  return r;
}

// Extract Splunk selected-field KEY = VALUE pairs from a raw Splunk list-view event string.
// The selected fields are appended after the raw event payload, formatted as `KEY = VALUE` with
// spaces around `=`. We take only the suffix after the last `"` (end of any quoted CSV payload),
// then find each key's position and slice the value between it and the next key.
function extractSplunkKvPairs(text: string): Record<string, unknown> {
  const lastQuote = text.lastIndexOf('"');
  const suffix = lastQuote >= 0 ? text.slice(lastQuote + 1) : text;

  const result: Record<string, unknown> = {};
  // Require spaces around `=` to avoid matching `key=value` inside raw event text.
  const keyRe = /(\w[\w.]*)\s+=\s+/g;
  const positions: Array<{ key: string; start: number; valStart: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = keyRe.exec(suffix)) !== null) {
    positions.push({ key: m[1], start: m.index, valStart: m.index + m[0].length });
  }
  for (let i = 0; i < positions.length; i++) {
    const { key, valStart } = positions[i];
    const nextStart = i + 1 < positions.length ? positions[i + 1].start : suffix.length;
    const value = suffix.slice(valStart, nextStart).trim();
    if (key && value) result[key] = value;
  }
  return result;
}
