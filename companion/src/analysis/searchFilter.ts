import type { ForensicEvent, Finding, IOC } from "./stateTypes.js";

function ci(s: string | undefined | null, q: string): boolean {
  return (s || "").toLowerCase().includes(q);
}

/** Whether a forensic event matches a lower-cased search term. */
export function eventMatchesSearch(event: ForensicEvent, term: string): boolean {
  if (!term) return true;
  return (
    ci(event.description, term) ||
    ci(event.asset, term) ||
    (event.mitreTechniques || []).some(t => ci(t, term)) ||
    (event.sources || []).some(s => ci(s, term))
  );
}

/** Whether a finding matches a lower-cased search term. */
export function findingMatchesSearch(finding: Finding, term: string): boolean {
  if (!term) return true;
  return (
    ci(finding.title, term) ||
    ci(finding.description, term) ||
    (finding.mitreTechniques || []).some(t => ci(t, term))
  );
}

/** Whether an IOC matches a lower-cased search term. */
export function iocMatchesSearch(ioc: IOC, term: string): boolean {
  if (!term) return true;
  return ci(ioc.value, term) || ci(ioc.type, term);
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
