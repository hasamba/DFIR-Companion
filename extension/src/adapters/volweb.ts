import type { Adapter } from "./types.js";
import { asArray, isObject } from "./extractUtils.js";

// VolWeb (https://github.com/k1nd0ne/VolWeb) — a Django + React memory-forensics platform (a
// Volatility3 front end). Its analysis pages are the case/evidence detail views (/cases/:id,
// /evidences/:id); the data API is GET /api/evidence/<id>/plugin/<plugin_name>/ (and the
// equivalent .../plugin/<plugin_name>/artefacts/ unfiltered variant, same response shape),
// returning { name, artefacts: [...] } — the volatility3 plugin's result rows (pslist, netscan,
// filescan, etc.). VolWeb has no distinctive port (served via nginx on 80/443), so matchUrl falls
// back to the case/evidence detail path when the hostname isn't self-evidently branded — the same
// approach the Security Onion adapter already uses.
export const volwebAdapter: Adapter = {
  id: "volweb",
  label: "VolWeb",

  matchUrl(url: URL): boolean {
    if (/volweb/i.test(url.hostname)) return true;
    if (/^\/(cases|evidences)\/\d+/i.test(url.pathname)) return true;
    return false;
  },

  // Fallback for a reverse-proxied VolWeb whose hostname/path matchUrl can't recognize. The React
  // front end titles every page "VolWeb".
  matchDom(doc: Document): boolean {
    return /volweb/i.test(doc.title);
  },

  apiPatterns: ["/api/evidence/\\d+/plugin/[^/]+/"],

  extractRows(_url: string, body: unknown): unknown[] | null {
    if (!isObject(body)) return null;
    return asArray(body.artefacts);
  },

  sourceLabel: volwebSourceLabel,
};

const PLUGIN_NAME_RE = /\/plugin\/([^/]+)\//i;

// Derive the source label from the volatility3 plugin name embedded in the API URL (e.g.
// "windows.pslist.PsList"). Pure — unit-tested.
export function volwebSourceLabel(opts: { apiUrl?: string }): string {
  const { apiUrl = "" } = opts;
  const m = PLUGIN_NAME_RE.exec(apiUrl);
  if (!m) return "";
  try { return decodeURIComponent(m[1]); } catch { return m[1]; }
}
