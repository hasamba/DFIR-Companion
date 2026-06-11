import type { ForensicEvent, Finding, IOC } from "./stateTypes.js";

function ci(s: string | undefined | null, q: string): boolean {
  return (s || "").toLowerCase().includes(q);
}

/** Whether a forensic event matches a search term (case-insensitive). */
export function eventMatchesSearch(event: ForensicEvent, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return (
    ci(event.description, q) ||
    ci(event.asset, q) ||
    (event.mitreTechniques || []).some(t => ci(t, q)) ||
    (event.sources || []).some(s => ci(s, q))
  );
}

/** Whether a finding matches a search term (case-insensitive). */
export function findingMatchesSearch(finding: Finding, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return (
    ci(finding.title, q) ||
    ci(finding.description, q) ||
    (finding.mitreTechniques || []).some(t => ci(t, q))
  );
}

/** Whether an IOC matches a search term (case-insensitive). */
export function iocMatchesSearch(ioc: IOC, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return ci(ioc.value, q) || ci(ioc.type, q);
}

/**
 * Whether a forensic event falls within an optional time range.
 * `from` and `to` are ISO UTC strings (or null/undefined = unbounded).
 */
export function eventMatchesTimeRange(
  event: ForensicEvent,
  from: string | null | undefined,
  to: string | null | undefined,
): boolean {
  if (!from && !to) return true;
  const ts = event.timestamp;
  if (!ts) return true;
  const t = Date.parse(ts);
  if (isNaN(t)) return true;
  if (from) { const f = Date.parse(from); if (!isNaN(f) && t < f) return false; }
  if (to)   { const u = Date.parse(to);   if (!isNaN(u) && t > u) return false; }
  return true;
}
