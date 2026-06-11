// IOC corroboration — for each IOC, the distinct set of TOOLS that observed that indicator.
// IOCs are deduped to one row per value (mergeDelta), but they don't carry sources themselves;
// the forensic EVENTS do (`sources`, tagged with the real tool name per import). So we derive
// corroboration by matching each IOC's value against the events: the same hash/IP/domain seen by
// e.g. both THOR and Velociraptor → "2 sources confirm". Pure + derived on read (like the asset
// graph / attack phases), so it never mutates persisted state.
//
// Matching is an INDEXED EXACT-TOKEN match (not substring): structured event fields
// (sha256/md5/srcIp/dstIp/path) plus indicator-shaped tokens extracted from the description are
// indexed once, then each IOC value is looked up. Exact-token equality avoids FALSE corroboration
// (e.g. "10.0.0.1" must not match inside "10.0.0.10"), which matters in DFIR — over-claiming that
// two tools agree is worse than missing a match. O(events·tokens + iocs), so it scales to the
// hundreds/thousands of IOCs a real case produces.

import type { ForensicEvent, IOC } from "./stateTypes.js";

const UNKNOWN_SOURCE = "unknown source";

// Indicator-shaped run of characters: covers IPs, domains, URLs, hashes, emails, and Win/Unix
// paths (so a full path token can match a path IOC). 3+ chars to skip trivial noise.
const TOKEN_RE = /[\w.@:/\\-]{3,}/g;

function realSources(e: ForensicEvent): string[] {
  return (e.sources ?? []).filter((s) => s && s !== UNKNOWN_SOURCE);
}

// Build value→sources index across all events, then look up each IOC value. Returns a map of
// iocId → sorted distinct source names, ONLY for IOCs that at least one sourced event references.
export function deriveIocSources(iocs: readonly IOC[], events: readonly ForensicEvent[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (iocs.length === 0 || events.length === 0) return out;

  const index = new Map<string, Set<string>>();
  const add = (raw: string | undefined, sources: string[]): void => {
    if (!raw) return;
    const key = raw.trim().toLowerCase();
    if (key.length < 3) return;
    let set = index.get(key);
    if (!set) { set = new Set<string>(); index.set(key, set); }
    for (const s of sources) set.add(s);
  };

  for (const e of events) {
    const sources = realSources(e);
    if (sources.length === 0) continue;
    add(e.sha256, sources);
    add(e.md5, sources);
    add(e.srcIp, sources);
    add(e.dstIp, sources);
    add(e.path, sources);
    const tokens = (e.description || "").match(TOKEN_RE);
    if (tokens) for (const t of tokens) add(t, sources);
  }

  for (const ioc of iocs) {
    const v = ioc.value.trim().toLowerCase();
    if (v.length < 3) continue;
    const set = index.get(v);
    if (set && set.size > 0) out[ioc.id] = [...set].sort();
  }
  return out;
}

// Convenience for callers that want only the corroborated IOCs (2+ distinct tools).
export function corroboratedIocSources(iocs: readonly IOC[], events: readonly ForensicEvent[]): Record<string, string[]> {
  const all = deriveIocSources(iocs, events);
  const out: Record<string, string[]> = {};
  for (const [id, sources] of Object.entries(all)) if (sources.length >= 2) out[id] = sources;
  return out;
}
