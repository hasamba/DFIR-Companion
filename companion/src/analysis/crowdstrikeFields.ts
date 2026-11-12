// Shared field readers for the CrowdStrike Falcon importer (#2592): the source label, the
// placeholder-aware field read and the event-name read, used by crowdstrikeMap.ts,
// crowdstrikeCanonical.ts and crowdstrikeImport.ts.

import { oneLine, str } from "./siemImport.js";
import type { Severity } from "./stateTypes.js";

type Row = Record<string, unknown>;

export const CROWDSTRIKE_SOURCE = "CrowdStrike Falcon";

/** A field as a trimmed one-line string ("" when absent, an object, or a placeholder). */
export function field(rec: Row, key: string): string {
  const v = rec[key];
  if (v === undefined || v === null || typeof v === "object") return "";
  const s = oneLine(str(v));
  return s === "-" || s === "N/A" ? "" : s;
}

/** The event name: `#event_simpleName` (LogScale) when non-blank, else `event_simpleName` (FDR). */
export function eventName(rec: Row): string {
  return field(rec, "#event_simpleName") || field(rec, "event_simpleName");
}

export function portNum(raw: string): number | undefined {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : undefined;
}

// Falcon severity → ours. Shared by sensor detection rows (DetectionSummaryEvent) and API alerts.
// The name wins; a bare number 1–5 maps 1:1 (1 Info … 5 Critical); a number above 5 is the API's
// 0–100 scale. Anything unreadable → Info: no invented verdict.
const SEVERITY_BY_NAME: Record<string, Severity> = {
  informational: "Info",
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};
const SEVERITY_BY_NUMBER: Severity[] = ["Info", "Info", "Low", "Medium", "High", "Critical"];
export function falconSeverity(nameRaw: string, numRaw: string): Severity {
  const byName = SEVERITY_BY_NAME[nameRaw.trim().toLowerCase()];
  if (byName) return byName;
  const n = Number(numRaw);
  if (!numRaw || !Number.isFinite(n) || n < 0) return "Info";
  if (Number.isInteger(n) && n >= 1 && n <= 5) return SEVERITY_BY_NUMBER[n];
  if (n <= 5 || n > 100) return "Info";
  return n >= 80 ? "Critical" : n >= 60 ? "High" : n >= 40 ? "Medium" : n >= 20 ? "Low" : "Info";
}
