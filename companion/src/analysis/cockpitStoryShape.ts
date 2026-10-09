import { extractAccounts } from "./assetGraph.js";
import { canonicalHostName, resolveHost, type HostAliasIndex } from "./hostAlias.js";
import type { ForensicEvent } from "./stateTypes.js";

// The story's shape line (#1493): when the staged activity starts and ends, how long the attacker
// dwelt, and which hosts and accounts the chain touched, in the order it touched them. Derived from
// the SAME staged events the stage cards use (non-Info, tactic-mapped) — an Info row or an untagged
// row outside that window never widens the span. Forensic timeline only (CLAUDE.md §7).

// Hosts and accounts shown before the "(+N)"; the totals still count every distinct one.
export const STORY_SHAPE_LIMIT = 8;

export interface CockpitStoryShape {
  firstAt: string | null;
  lastAt: string | null;
  dwellMs: number | null;
  hosts: string[];
  hostsTotal: number;
  accounts: string[];
  accountsTotal: number;
}

export function parseTime(value: string | undefined): number | null {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

// Timestamped events first, oldest first; undated events keep their timeline order at the end so
// they count and can be filtered to, but never decide a first-seen time.
export function chronological(events: readonly ForensicEvent[]): ForensicEvent[] {
  return events
    .map((event, index) => ({ event, index, time: parseTime(event.timestamp) }))
    .sort((a, b) => {
      if (a.time === null || b.time === null)
        return Number(a.time === null) - Number(b.time === null) || a.index - b.index;
      return a.time - b.time || a.index - b.index;
    })
    .map((item) => item.event);
}

interface Dated {
  at: string;
  time: number;
}

// The latest instant an event covers: its endTimestamp when an aggregated row carries one that is
// later than its start, otherwise its timestamp. An unparseable end never counts.
function eventEnd(event: ForensicEvent): Dated | null {
  const start = parseTime(event.timestamp);
  const end = parseTime(event.endTimestamp);
  if (end !== null && (start === null || end > start)) return { at: event.endTimestamp ?? "", time: end };
  return start === null ? null : { at: event.timestamp, time: start };
}

function span(ordered: readonly ForensicEvent[]): Pick<CockpitStoryShape, "firstAt" | "lastAt" | "dwellMs"> {
  const first = ordered.find((event) => parseTime(event.timestamp) !== null);
  const firstTime = parseTime(first?.timestamp);
  let last: Dated | null = null;
  for (const event of ordered) {
    const end = eventEnd(event);
    if (end && (!last || end.time > last.time)) last = end;
  }
  if (!first || firstTime === null || !last) return { firstAt: null, lastAt: null, dwellMs: null };
  return { firstAt: first.timestamp, lastAt: last.at, dwellMs: last.time - firstTime };
}

// Distinct values in the order their first event appears; `ordered` is chronological, so this is
// first-touch order with undated events' values last. `keyOf` decides what counts as the same
// value; the first-seen spelling is the one kept.
function firstTouch(
  ordered: readonly ForensicEvent[],
  valuesOf: (event: ForensicEvent) => string[],
  keyOf: (value: string) => string = (value) => value,
): string[] {
  const seen = new Map<string, string>();
  for (const event of ordered)
    for (const value of valuesOf(event)) if (!seen.has(keyOf(value))) seen.set(keyOf(value), value);
  return [...seen.values()];
}

// The host name the story shows for a raw asset spelling (#2066). Without an alias index it is the
// spelling as written. With one, a spelling that an analyst "Same host" merge or the fleet snapshot
// redirected shows the canonical name the analyst picked; an unredirected spelling keeps its own.
// Only evidence-linked aliases fold — never a short name onto an FQDN by first label (hostAlias.ts).
export function storyHostName(raw: string, aliasIndex?: HostAliasIndex): string {
  const host = raw.trim();
  if (!aliasIndex || !host) return host;
  const resolved = resolveHost(aliasIndex, host);
  return resolved === canonicalHostName(host) ? host : resolved;
}

function hostsOf(aliasIndex?: HostAliasIndex): (event: ForensicEvent) => string[] {
  return (event) => {
    const host = storyHostName(event.asset ?? "", aliasIndex);
    return host ? [host] : [];
  };
}

// What counts as one host. Case never matters ("DC01" is "dc01"); with an alias index every
// spelling the index links counts as its canonical name.
function hostKey(aliasIndex?: HostAliasIndex): (host: string) => string {
  return aliasIndex ? (host) => resolveHost(aliasIndex, host) : (host) => host.toLowerCase();
}

function accountsOf(event: ForensicEvent): string[] {
  return extractAccounts(event.description ?? "");
}

export function deriveStoryShape(
  events: readonly ForensicEvent[],
  aliasIndex?: HostAliasIndex,
): CockpitStoryShape {
  const ordered = chronological(events);
  // One host per identity, shown as first seen (or by the merged name — see storyHostName).
  const hosts = firstTouch(ordered, hostsOf(aliasIndex), hostKey(aliasIndex));
  const accounts = firstTouch(ordered, accountsOf);
  return {
    ...span(ordered),
    hosts: hosts.slice(0, STORY_SHAPE_LIMIT),
    hostsTotal: hosts.length,
    accounts: accounts.slice(0, STORY_SHAPE_LIMIT),
    accountsTotal: accounts.length,
  };
}
