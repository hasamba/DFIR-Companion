// Shared field readers for the CrowdStrike Falcon importer (#2592): the source label, the
// placeholder-aware field read and the event-name read, used by crowdstrikeMap.ts,
// crowdstrikeCanonical.ts and crowdstrikeImport.ts.

import { oneLine, str } from "./siemImport.js";

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
