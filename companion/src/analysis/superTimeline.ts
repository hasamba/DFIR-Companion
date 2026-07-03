// Pure logic for the super-timeline: a Timesketch-style complete record of every imported event
// (a copy of the forensic timeline PLUS raw host-triage artifacts routed there exclusively). Bounded
// by a cap; filtered by time/origin/label; never synthesized by AI. I/O lives in superTimelineStore.ts.

import type { ForensicEvent } from "./stateTypes.js";

export type SuperLabelMap = Record<string, string[]>;

// Pseudo-facet for events with no affected host, so the host filter can control them too (and "None"
// truly empties the timeline) — mirrors the forensic source filter's "(no source)".
export const NO_HOST_FACET = "(no host)";

export interface SuperQuery {
  from?: string;        // ISO lower bound (inclusive)
  to?: string;          // ISO upper bound (inclusive)
  origins?: string[];   // keep only these origins (empty/undefined = all)
  exclude?: string[];   // drop these origins (the dashboard's unchecked boxes) — so unchecking ALL yields 0
  excludeHosts?: string[]; // drop these hosts (the dashboard's unchecked host boxes); use NO_HOST_FACET for undated-host rows
  labels?: string[];    // keep only events carrying at least one of these labels
  taggedOnly?: boolean; // keep only events carrying at least one tag/label (any)
  offset?: number;
  limit?: number;
}

export interface SuperQueryResult {
  events: ForensicEvent[];
  total: number;                 // full match count before pagination
  origins: string[];             // distinct origins across the matched set (facet, sorted)
  hosts: string[];               // distinct hosts across the time window (facet, sorted; incl. NO_HOST_FACET)
  labelsAvailable: string[];     // distinct labels across the matched set (facet, sorted)
}

// The origin facet: the specific artifact when known, else the first tool in `sources`, else "Unknown".
export function superOriginOf(event: ForensicEvent): string {
  return event.artifactName || event.sources?.[0] || "Unknown";
}

// The host facet: the affected asset, or the "(no host)" pseudo-facet when the event has none.
export function superHostOf(event: ForensicEvent): string {
  return event.asset || NO_HOST_FACET;
}

// Append incoming events, dropping any whose id already exists (a re-import of the same rows must not
// double the super-timeline). Preserves order: existing first, then genuinely-new incoming.
export function dedupeAppend(existing: ForensicEvent[], incoming: ForensicEvent[]): ForensicEvent[] {
  const seen = new Set(existing.map((e) => e.id));
  const fresh = incoming.filter((e) => !seen.has(e.id));
  return [...existing, ...fresh];
}

// Bound the store: keep the `max` newest events by timestamp (undated events sort as oldest and are
// dropped first when over the cap). No-op when under the cap.
export function capEvents(events: ForensicEvent[], max: number): ForensicEvent[] {
  if (events.length <= max) return events;
  const ms = (e: ForensicEvent): number => { const t = Date.parse(e.timestamp); return Number.isNaN(t) ? -Infinity : t; };
  return [...events].sort((a, b) => ms(b) - ms(a)).slice(0, max);
}

// Filter + paginate + facet. Undated events are kept under a time filter (can't be proven out of range).
export function querySuper(events: ForensicEvent[], labelMap: SuperLabelMap, q: SuperQuery): SuperQueryResult {
  const fromMs = q.from ? Date.parse(q.from) : NaN;
  const toMs = q.to ? Date.parse(q.to) : NaN;
  const originSet = q.origins && q.origins.length ? new Set(q.origins) : null;
  const excludeSet = q.exclude && q.exclude.length ? new Set(q.exclude) : null;
  const excludeHostSet = q.excludeHosts && q.excludeHosts.length ? new Set(q.excludeHosts) : null;
  const labelSet = q.labels && q.labels.length ? new Set(q.labels) : null;

  const inTime = (e: ForensicEvent): boolean => {
    const t = Date.parse(e.timestamp);
    if (Number.isNaN(t)) return true;   // undated kept — can't be proven out of range
    if (!Number.isNaN(fromMs) && t < fromMs) return false;
    if (!Number.isNaN(toMs) && t > toMs) return false;
    return true;
  };

  // Facets (the checklist options) reflect the whole TIME window, INDEPENDENT of the current
  // origin/label selection — so unchecking an origin only filters the results, it never removes the
  // option from the checklist (you can always re-check it). Only the time window changes what's
  // available. Computing facets off the origin/label-filtered set was the bug: filtering to one origin
  // collapsed the list to just that origin.
  const inWindow = events.filter(inTime);
  const origins = [...new Set(inWindow.map(superOriginOf))].sort();
  const hosts = [...new Set(inWindow.map(superHostOf))].sort();
  const labelsAvailable = [...new Set(inWindow.flatMap((e) => labelMap[e.id] ?? []))].sort();

  // Results apply the origin + host + label filters on top of the time window.
  const matched = inWindow.filter((e) => {
    const origin = superOriginOf(e);
    if (originSet && !originSet.has(origin)) return false;
    if (excludeSet && excludeSet.has(origin)) return false;   // unchecked in the dashboard → hidden
    if (excludeHostSet && excludeHostSet.has(superHostOf(e))) return false;   // unchecked host → hidden
    if (labelSet) {
      const evLabels = labelMap[e.id] ?? [];
      if (!evLabels.some((l) => labelSet.has(l))) return false;
    }
    // "Tagged only": keep only events carrying at least one tag/label (any).
    if (q.taggedOnly && !(labelMap[e.id] ?? []).length) return false;
    return true;
  });

  const sorted = [...matched].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));

  const offset = Math.max(0, Math.floor(q.offset ?? 0));
  const limit = q.limit != null ? Math.max(0, Math.floor(q.limit)) : sorted.length;
  const page = sorted.slice(offset, offset + limit);

  return { events: page, total: matched.length, origins, hosts, labelsAvailable };
}
