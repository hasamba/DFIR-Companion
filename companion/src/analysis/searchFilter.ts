import type { ForensicEvent, Finding, IOC } from "./stateTypes.js";

function ci(s: string | undefined | null, q: string): boolean {
  return (s || "").toLowerCase().includes(q);
}

/**
 * Parts of the canonical envelope that describe the MAPPING rather than the event.
 *
 * These carry field names and tool names as their values — rawFieldMap is literally
 * { "process.commandLine": ["commandLine"] } — so flattening them would make "commandLine",
 * "timestamp" or "legacy-upgrade" match every event that merely HAS such a field, and the analyst's
 * first search would return the whole case. They are provenance for auditing, not evidence to hunt.
 */
const CANONICAL_METADATA_KEYS = new Set([
  "rawFieldMap",
  "derivationMap",
  "confidenceMap",
  "producer",
  "fieldProvenance",
  "evidence",
  "schemaVersion",
  // Enum-valued describers of the TIME, not the time itself: "millisecond", "recorded", "utc".
  // time.observed and time.normalized stay searchable — an analyst does search a timestamp — but
  // these three would make one typed word match every event in the case.
  "precision",
  "clockConfidence",
  "timezone",
]);

/**
 * Every scalar VALUE reachable inside the canonical envelope, flattened for substring matching.
 *
 * Values only — never keys. Numbers are included because ports, PIDs and logon types are things
 * people search for ("4444", "4625").
 */
function canonicalValues(value: unknown, out: string[], depth = 0): void {
  if (value == null || depth > 8) return;
  if (typeof value === "string" || typeof value === "number") {
    out.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) canonicalValues(item, out, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (CANONICAL_METADATA_KEYS.has(key)) continue;
      canonicalValues(item, out, depth + 1);
    }
  }
}

/**
 * Every searchable VALUE on an event, lowercased, as separate strings (#928).
 *
 * The matcher this replaced read four fields — description, asset, mitre, sources — so a search for
 * a command line, a hash, a file path or the raw EVTX message found nothing even though the event
 * carried it. `message` in particular is the full untruncated text (`description` is the summary),
 * and it is where encoded PowerShell and script blocks actually live.
 *
 * A LIST, not one joined string. Joining let a term straddle two values — "svchost started  wks1"
 * matched a description and an asset that are not adjacent in any record — and nothing in storage
 * can reproduce that, so the same term matched in memory and missed on the server. A value is
 * searchable; a boundary between two of them is not.
 *
 * Deliberately NOT used by the exclude filter: see eventMatchesExclude.
 */
export function eventSearchParts(event: ForensicEvent): string[] {
  const parts: string[] = [
    event.description,
    event.message,
    event.asset,
    event.path,
    event.processName,
    event.parentName,
    event.artifactName,
    event.commandLine,
    event.sha256,
    event.md5,
    // The RECOVERED PLAINTEXT of an obfuscated command (#97). The timeline shows it in the event
    // details, so an analyst who has read it there will search for it — and encoded PowerShell is
    // the exact case #928 exists for. It lives only here: the deobfuscation pass does not copy it
    // into the canonical envelope, so leaving it out meant the one readable form of the evidence
    // was the one form that could not be found. `method` and `iocs` stay out: a classifier and a
    // list of internal ids, not evidence.
    event.deobfuscated?.decoded,
    ...(event.sources ?? []),
    ...(event.mitreTechniques ?? []),
  ].filter((value): value is string => typeof value === "string" && value.length > 0);
  canonicalValues(event.canonical, parts);
  return parts.map((value) => value.toLowerCase());
}

/** Whether a forensic event matches a search term (case-insensitive substring of any one value). */
export function eventMatchesSearch(event: ForensicEvent, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return eventSearchParts(event).some((part) => part.includes(q));
}

/**
 * The pre-#928 four-field match, kept as the EXCLUDE predicate only.
 *
 * Search and exclude used to share one predicate, so widening search would silently widen every
 * exclude chip an analyst has already saved: a term typed to hide noisy descriptions would start
 * hiding any event whose raw message or canonical metadata happened to contain it. Search finding
 * MORE is the point of #928; exclude hiding more is evidence loss the analyst never asked for, and
 * in DFIR that is the failure that matters. They are separate predicates now for that reason.
 */
function eventMatchesNarrow(event: ForensicEvent, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return (
    ci(event.description, q) ||
    ci(event.asset, q) ||
    (event.mitreTechniques || []).some((t) => ci(t, q)) ||
    (event.sources || []).some((s) => ci(s, q))
  );
}

/** Whether a finding matches a search term (case-insensitive). */
export function findingMatchesSearch(finding: Finding, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return (
    ci(finding.title, q) ||
    ci(finding.description, q) ||
    (finding.mitreTechniques || []).some((t) => ci(t, q))
  );
}

/**
 * Whether an IOC matches a search term (case-insensitive).
 *
 * `note` is the human annotation split out of `value` by #177 ("10.10.20.15 (DC01)" → value
 * "10.10.20.15", note "DC01"), so before #928 searching the host label an analyst themselves wrote
 * found nothing. `aliasValues` carries values folded on by a merge, which the analyst still knows
 * the IOC by.
 */
export function iocMatchesSearch(ioc: IOC, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return (
    ci(ioc.value, q) ||
    ci(ioc.type, q) ||
    ci(ioc.note, q) ||
    (ioc.aliasValues || []).some((value) => ci(value, q))
  );
}

/** The pre-#928 value+type match, kept as the IOC EXCLUDE predicate only (see eventMatchesNarrow). */
function iocMatchesNarrow(ioc: IOC, term: string): boolean {
  if (!term) return true;
  const q = term.toLowerCase();
  return ci(ioc.value, q) || ci(ioc.type, q);
}

/**
 * Whether a forensic event matches ANY of a set of exclude terms (case-insensitive substring).
 * Matches on the NARROW field set — see eventMatchesNarrow for why it did not widen with search.
 */
export function eventMatchesExclude(event: ForensicEvent, terms: readonly string[]): boolean {
  return terms.some((t) => t && eventMatchesNarrow(event, t));
}

/** Whether a finding matches ANY of a set of exclude terms (case-insensitive substring). */
export function findingMatchesExclude(finding: Finding, terms: readonly string[]): boolean {
  return terms.some((t) => t && findingMatchesSearch(finding, t));
}

/** Whether an IOC matches ANY of a set of exclude terms. Narrow, matching eventMatchesExclude. */
export function iocMatchesExclude(ioc: IOC, terms: readonly string[]): boolean {
  return terms.some((t) => t && iocMatchesNarrow(ioc, t));
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
  if (from) {
    const f = Date.parse(from);
    if (!isNaN(f) && t < f) return false;
  }
  if (to) {
    const u = Date.parse(to);
    if (!isNaN(u) && t > u) return false;
  }
  return true;
}
