import type { Adapter } from "./types.js";
import { isObject } from "./extractUtils.js";

// SO-CRATES (dougburks/so-crates) — a standalone single-page app for analyzing one artifact at a
// time: a PCAP → Suricata IDS alerts (+ YARA matches on carved files), a binary → YARA file alerts,
// a log file → Sigma detections (Zircolite). The SPA is always served as `socrates.html` (default
// :8000, the demo :9888); the chosen analysis is the `?file=<md5>` (legacy `?pcap=`) query param.
// Two data feeds, each returning a JSON ARRAY:
//   GET /api/events        → eve.json objects (event_type: alert | filealerts | dns | http | …)
//   GET /api/sigma-alerts  → Sigma alert objects ({ rule_title, rule_id, severity, level, … })
// A single analysis populates only one feed (network+YARA share /api/events; Sigma is its own
// feed), so the capture glue's "last non-empty extraction wins" naturally lands on the right one.
export const socratesAdapter: Adapter = {
  id: "socrates",
  label: "SO-CRATES",

  matchUrl(url: URL): boolean {
    return /\/socrates\.html$/i.test(url.pathname);
  },

  apiPatterns: ["/api/events", "/api/sigma-alerts"],

  // Both endpoints return a JSON array of record objects. Return the object rows; null otherwise.
  extractRows(_url: string, body: unknown): unknown[] | null {
    if (!Array.isArray(body) || body.length === 0) return null;
    const rows = body.filter(isObject);
    return rows.length ? rows : null;
  },

  // Stamp every pushed row with _Source "SO-CRATES" — navigate-back provenance AND the detection
  // signal the companion's isSocrates() claims (placed before isVelociraptor's catch-all _Source).
  sourceLabel(_opts: { apiUrl: string; pageUrl: string; domInputs: readonly string[]; domHeadings: readonly string[]; rows: readonly unknown[] }): string {
    return "SO-CRATES";
  },

  tableSelector: "table", // DOM-scrape fallback: the visible results table at the page bottom
};
