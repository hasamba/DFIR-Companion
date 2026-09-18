// #996 (cross-upload half of the query → connection lead): a sensor-vantage DNS answer
// (`canonical.dns.vantage === "sensor"` — Zeek `dns.log` / Suricata `dns`) joined to ANY
// connection-shaped event anywhere in the case — Sysmon 3, WFP 5156, Zeek `conn.log`, Suricata
// flow all write the identical `canonical.network.source/destination.address` shape — sharing the
// DNS row's own `client` as the connection's source and a returned address as its destination.
//
// DIRECTIONAL, NOT AN UNORDERED PAIR — matches `dnsConnJoin.ts`'s own same-upload convention
// (`pairKey(sensor, c.src, c.dst)` against `pairKey(sensor, d.client, address)`) exactly: the
// client must be the connection's SOURCE and the returned address its DESTINATION. A connection
// recorded the other way round (the resolved address as source, the client as destination) is a
// DIFFERENT real event — something connecting TO the client — not "the client connecting to the
// answer," and is deliberately never matched here.
//
// NO HOST-IDENTITY RESOLUTION, UNLIKE THE OTHER TWO #996 CROSS-UPLOAD JOINS. A sensor row's
// `client` (Zeek `id.orig_h` / Suricata `src_ip`) and every connection producer's own addresses
// are already plain IPs on both sides — nothing to bridge through `hostBinding.ts`.
//
// READ-TIME, ROUTE-LEVEL, NEVER A MERGE-TIME PASS — same contract as `proxyWorkstationChain.ts` /
// `dnsResolverEndpointJoin.ts`: reads `state.forensicTimeline` as already persisted, recomputed on
// every call, never wired into stateMerge.ts.
//
// AGGREGATION IS A REAL, DISCLOSED LOSS OF PRECISION HERE — unlike the two SAME-upload joins this
// module deliberately does NOT reuse (`dnsConnJoin.ts` / `siemDnsConnJoin.ts`, which run at MERGE
// TIME over the raw un-aggregated per-record stream, per #996's own original prerequisite). A
// persisted `ForensicEvent` may represent several real, separate occurrences folded into one row
// (`count`/`endTimestamp`, generic to every importer, not DNS-specific) by the time this join runs.
// This module cannot recover which folded occurrence produced a match — only that a connection
// exists somewhere in [`timestamp`, `endTimestamp ?? timestamp`] + the window. Every result carries
// the row's own occurrence span so the analyst can judge the fold's width, not just a caveat
// sentence. `ttl` (when a sensor row carries one) is NOT used to size the window even so — it is a
// FOLDED min/max range across every occurrence this row represents (canonicalDns.ts's own doc
// comment), not one address's one real TTL; using it would overclaim precision the aggregated
// record no longer carries. The fixed window (`DNS_FIXED_WINDOW_S`, reused from `dnsConnJoin.ts`)
// is used uniformly, worded as fixed.
//
// A SHARED ADDRESS IS NOT A SHARED HOST. NAT, DHCP reuse over time, a VPN/proxy exit, or
// load-balanced infrastructure can put two DIFFERENT real machines behind the same address at
// different times. A match here means the SAME address pair appears on both sides — never a
// proven same-host or same-process connection. Said in-band on every result, never only here.
//
// A DEDICATED STATE TYPE, NOT `DnsLeadState`. The same-upload enum's other members
// ("other clients connected...", "connection records exceed the index", …) don't apply to a
// whole-case scan, and a near-duplicate string would invite exactly the confusion a shared type
// risks. `DnsGapBand`/`gapBand` ARE reused — that vocabulary is genuinely general-purpose, not
// upload-scoped.

import { canonicalIp, isIdentifyingIp } from "./hostBinding.js";
import { DNS_FIXED_WINDOW_S, DNS_WINDOW_SLACK_S, gapBand } from "./canonicalDns.js";
import type { DnsGapBand } from "./canonicalDns.js";
import type { ForensicEvent } from "./stateTypes.js";

export type CrossUploadDnsConnState =
  | "connected inside the window"
  | "first connection after the window"
  | "earlier connections only"
  | "no connection found in this case"
  | "DNS row time not placeable";

const AGGREGATION_WIDTH_CAVEAT =
  "this row may represent several folded query occurrences (see `occurrences`) — the window spans " +
  "from the first to the last, so it can be wide when many were folded together; a match says an " +
  "address pair appeared somewhere in that span, not which specific occurrence produced it";
const SHARED_ADDRESS_CAVEAT =
  "a shared IP (NAT, DHCP reuse over time, a VPN or proxy exit, load-balanced infrastructure) can " +
  "put two DIFFERENT real machines behind the same address at different times — a match here means " +
  "the same address pair appeared on both sides, never a proven same-host or same-process connection";

export interface CrossUploadDnsConnLead {
  eventId: string;
  client: string;
  query: string;
  address: string;
  state: CrossUploadDnsConnState;
  band?: DnsGapBand;
  connectionEventId?: string;
  occurrences: { count: number; firstSeen: string; lastSeen: string };
  windowSeconds: number;
  caveats: string[];
}

function isSensorDnsRow(e: ForensicEvent): boolean {
  return e.canonical?.dns?.vantage === "sensor" && isIdentifyingIp(e.canonical.dns.client ?? "");
}

function isConnCandidate(e: ForensicEvent): boolean {
  const src = e.canonical?.network?.source?.address;
  const dst = e.canonical?.network?.destination?.address;
  return !!src && !!dst && isIdentifyingIp(src) && isIdentifyingIp(dst);
}

/** `srcIp|dstIp` → matching connection events, sorted by their own (first-occurrence) timestamp. */
function indexConns(events: readonly ForensicEvent[]): Map<string, ForensicEvent[]> {
  const bySrcDst = new Map<string, ForensicEvent[]>();
  for (const e of events) {
    if (!isConnCandidate(e)) continue;
    const key = `${canonicalIp(e.canonical!.network!.source!.address!)}|${canonicalIp(e.canonical!.network!.destination!.address!)}`;
    const list = bySrcDst.get(key) ?? [];
    list.push(e);
    bySrcDst.set(key, list);
  }
  // Numeric, not string, comparison — two ISO timestamps that differ only in whether they carry
  // milliseconds ("…00Z" vs "…00.500Z") sort wrong under `localeCompare` ("." sorts before "Z"),
  // exactly the class of bug `dnsConnJoin.ts`'s own same-upload join avoids by keeping `ts` numeric
  // throughout rather than ever comparing ISO strings directly.
  for (const list of bySrcDst.values())
    list.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  return bySrcDst;
}

function leadFor(
  d: ForensicEvent,
  address: string,
  candidates: readonly ForensicEvent[] | undefined,
  windowSeconds: number,
): { state: CrossUploadDnsConnState; band?: DnsGapBand; connectionEventId?: string } {
  const matches = candidates ?? [];
  if (!matches.length) return { state: "no connection found in this case" };

  const first = Date.parse(d.timestamp);
  const last = Date.parse(d.endTimestamp ?? d.timestamp);
  // A malformed persisted timestamp (Date.parse -> NaN) must never silently fall through to a
  // conservative-looking "no connection"/"earlier connections only" via a NaN comparison — named
  // explicitly, mirroring dnsConnJoin.ts's own "connection records not placeable" for the same
  // condition on the same-upload side (#1250).
  if (!Number.isFinite(first) || !Number.isFinite(last)) return { state: "DNS row time not placeable" };

  // A connection candidate can ALSO be a folded row (`count` > 1) — the same aggregation-honesty
  // problem the DNS side has, on the other side of the join. Searched by its own LAST occurrence
  // (`connLast`), not its first: a connection whose fold started before `first` but reached into or
  // past it is not "earlier connections only" — some occurrence within that fold could plausibly be
  // the one that followed this query. A candidate whose OWN time is unparseable is excluded rather
  // than silently losing every NaN comparison (#1250) — a wrong "earlier connections only" verdict
  // is worse than a candidate not participating at all.
  const placeableMatches = matches.filter((c) => Number.isFinite(Date.parse(c.endTimestamp ?? c.timestamp)));
  if (!placeableMatches.length) return { state: "no connection found in this case" };
  const atOrAfter = placeableMatches.find((c) => Date.parse(c.endTimestamp ?? c.timestamp) >= first);
  if (atOrAfter) {
    const connFirst = Date.parse(atOrAfter.timestamp);
    // Gap measured between the two folds' closest edges: zero when they overlap at all (connFirst
    // <= last, guaranteed reachable since atOrAfter's own LAST occurrence already cleared `first`),
    // else the distance from the DNS fold's last occurrence to the connection fold's first. Same
    // quantity drives both the state decision and the displayed band, on purpose — a `first`-only or
    // `last`-only anchor on just one side could make `state` and `band` disagree.
    const gapMs = Math.max(0, connFirst - last);
    const state: CrossUploadDnsConnState =
      gapMs <= (windowSeconds + DNS_WINDOW_SLACK_S) * 1000
        ? "connected inside the window"
        : "first connection after the window";
    return { state, band: gapBand(gapMs), connectionEventId: atOrAfter.id };
  }
  // Every match's own LAST occurrence is still before `first` — truly earlier, not just folded.
  return {
    state: "earlier connections only",
    connectionEventId: placeableMatches[placeableMatches.length - 1].id,
  };
}

export function resolveCrossUploadDnsConnLeads(
  events: readonly ForensicEvent[],
  windowSeconds: number = DNS_FIXED_WINDOW_S,
): CrossUploadDnsConnLead[] {
  const connIndex = indexConns(events);
  const results: CrossUploadDnsConnLead[] = [];

  for (const e of events) {
    if (!isSensorDnsRow(e)) continue;
    const client = canonicalIp(e.canonical!.dns!.client!);
    const query = e.canonical!.dns!.query;
    const occurrences = {
      count: e.count ?? 1,
      firstSeen: e.timestamp,
      lastSeen: e.endTimestamp ?? e.timestamp,
    };

    for (const v of e.canonical!.dns!.returned) {
      if (v.kind !== "address" || !isIdentifyingIp(v.value)) continue;
      const address = canonicalIp(v.value);
      const { state, band, connectionEventId } = leadFor(
        e,
        address,
        connIndex.get(`${client}|${address}`),
        windowSeconds,
      );
      results.push({
        eventId: e.id,
        client,
        query,
        address,
        state,
        ...(band ? { band } : {}),
        ...(connectionEventId ? { connectionEventId } : {}),
        occurrences,
        windowSeconds,
        caveats: connectionEventId ? [AGGREGATION_WIDTH_CAVEAT, SHARED_ADDRESS_CAVEAT] : [],
      });
    }
  }

  return results;
}
