// RFC 3164 / BSD month-name timestamp parsing, shared (via siemImport's re-export) by the
// plain-syslog and Cisco ASA importers — the same byte-identical parser used to live in each. The
// month table also serves siemImport's Kibana-export parser and combinedLogImport's Apache dates.

// Three-letter English month → "MM".
export const MONTHS: Record<string, string> = {
  Jan: "01",
  Feb: "02",
  Mar: "03",
  Apr: "04",
  May: "05",
  Jun: "06",
  Jul: "07",
  Aug: "08",
  Sep: "09",
  Oct: "10",
  Nov: "11",
  Dec: "12",
};

// RFC 3164 / BSD "MMM DD HH:MM:SS" — the year-less timestamp shared by plain syslog and Cisco ASA
// exports. Stamped at `year` (the caller's assumed year); the mergeDelta year-clamp re-anchors it
// once dated evidence lands. "" when unparseable.
export function parseBsdTime(ts: string, year: number): string {
  const m = ts.trim().match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (!m) return "";
  const [, mon, dd, hh, mi, ss] = m;
  const month = MONTHS[mon];
  if (!month) return "";
  const t = Date.parse(`${year}-${month}-${dd.padStart(2, "0")}T${hh}:${mi}:${ss}Z`);
  return Number.isNaN(t) ? "" : new Date(t).toISOString();
}
