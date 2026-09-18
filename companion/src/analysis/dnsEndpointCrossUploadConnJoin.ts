// #996 (the last query → connection pair): a Windows endpoint's own DNS query
// (`canonical.dns.vantage === "endpoint"` — Sysmon 22 / DNS-Client) matched to a connection
// recorded in a SEPARATE upload. Assembles three already-shipped, already-reviewed #996 pieces
// rather than new machinery: the endpoint side needs no host resolution — `ForensicEvent.asset`
// already names the querying host directly — but the connection side does, since a connection in a
// different upload only carries a bare source IP. Bridged the same way `dnsResolverEndpointJoin.ts`
// and `proxyWorkstationChain.ts` already bridge one: `hostBinding.ts`'s index (#1158), built from
// 4624 logons across the WHOLE case. The window/aggregation-fold logic is `dnsCrossUploadConnJoin.ts`'s
// (#1248) own, reused via its exported `CrossUploadDnsConnState` rather than a fourth near-duplicate
// state type — the output vocabulary is identical once a connection candidate is found.
//
// READ-TIME, ROUTE-LEVEL, NEVER A MERGE-TIME PASS — same contract as every #996 report-time join
// this session shipped: reads `state.forensicTimeline` as already persisted, recomputed on every
// call, never wired into stateMerge.ts.
//
// AN AMBIGUOUSLY-RESOLVED CONNECTION NEVER CONFIRMS MORE THAN ONE HOST. The two host-resolving
// precedents both surface ambiguity as their OWN top-level outcome ("ambiguous", naming every
// candidate host) because they don't yet know which host an IP names. This module already knows
// the host — the DNS row said so directly — so it asks a sharper question: is THIS connection's own
// resolution unambiguous? A connection is only indexed under a host when its own source IP resolves
// to EXACTLY one distinct host; an ambiguous connection (resolves to two or more real hosts) is
// never claimed as evidence for any of them; a real early plan for this module would have let one
// real connection appear as "connected" for every ambiguous candidate host, over-claiming evidence
// that was never that specific — caught in plan review, fixed before writing this code.
//
// "NO CONNECTION FOUND" IS NOT THE SAME FACT AS "A CONNECTION EXISTS FOR SOMEONE ELSE." When this
// host's own lookup misses, a separate, host-independent check says whether a connection to that
// destination exists ANYWHERE in the case at all (matched to a different host, or itself
// unresolved) — surfaced as a caveat, not silently absorbed into a bare "no connection found."
//
// STALENESS IS SHOWN, NOT ASSUMED AWAY BY A TIGHTER DEFAULT. `hostToleranceMs` reuses the same 6h
// default / 30d max `dnsResolverEndpointJoin.ts` and `proxyWorkstationChain.ts` already answer the
// same "how stale is this logon sample" question with — a fourth, different number for the same
// question would be its own inconsistency. Every match instead carries the binding's own
// `bindingSampleTime`, so an analyst judges staleness from the real evidence, not a baked-in number.
//
// TRUST BOUNDARY, CONNECTION SOURCE (#1313, the same gate as #1265). A connection's source address
// becomes a HOST NAME here — "this host connected to the answer" — through the very
// `resolveIpAtTime` call `proxyWorkstationChain.ts` fail-closes on `network.source.provenance ===
// "edge-observed"`. This module applies the same gate for the same reason: only a writer whose own
// recorder edge observed the peer may put a host's name on a connection. The flag is fail-closed:
// absent (a connection persisted before #1265, or a flat-`srcIp` importer — Cisco ASA, Security
// Onion, memory netscan — upgraded at load by canonicalEvent.ts, which cannot know the provenance)
// reads as NOT edge-observed and the connection is never indexed under any host. DISCLOSED COST,
// as #1265 disclosed it for the proxy chain: re-opening a case whose connections predate #1265
// loses 100% of this join's host attribution for those connections. The connection itself is not
// dropped — it still counts as "a connection to this address exists elsewhere in the case" (the
// host-independent check above), because it is real evidence that SOMEONE reached the address;
// what it can no longer do is name WHO.

import { buildHostBindingIndex, canonicalIp, isIdentifyingIp, resolveIpAtTime } from "./hostBinding.js";
import type { HostBinding, HostBindingIndex, IpExclusionReason } from "./hostBinding.js";
import { resolveHost } from "./hostAlias.js";
import type { HostAliasIndex } from "./hostAlias.js";
import { DNS_FIXED_WINDOW_S, DNS_WINDOW_SLACK_S, gapBand } from "./canonicalDns.js";
import type { DnsGapBand } from "./canonicalDns.js";
import type { CrossUploadDnsConnState } from "./dnsCrossUploadConnJoin.js";
import type { ForensicEvent } from "./stateTypes.js";

const FORWARDING_TOPOLOGY_CAVEAT =
  "a resolved host names whichever machine's own logon evidence shares the connection's source " +
  "address at that time — if this case's own sensor sits behind a forwarding hop, the recorded " +
  "source could be that hop, not the real originating endpoint";
const DHCP_LEASE_CAVEAT =
  "no DHCP-lease evidence exists in this codebase — the address could have been reassigned to a " +
  "different host between the logon sample and the connection; the tolerance window is a heuristic, never a guarantee";
const AGGREGATION_WIDTH_CAVEAT =
  "this row may represent several folded query occurrences (see `occurrences`) — the window spans " +
  "from the first to the last, so it can be wide when many were folded together";
const OTHER_HOST_CAVEAT =
  "a connection to this address exists elsewhere in the case, from a source IP that did not " +
  "resolve unambiguously to this host — not counted as evidence for it, but real evidence in the case";

export interface EndpointCrossUploadDnsConnLead {
  eventId: string;
  host: string;
  query: string;
  address: string;
  state: CrossUploadDnsConnState;
  band?: DnsGapBand;
  connectionEventId?: string;
  bindingSampleTime?: string;
  occurrences: { count: number; firstSeen: string; lastSeen: string };
  hostToleranceMs: number;
  windowSeconds: number;
  caveats: string[];
}

function isEndpointDnsRow(e: ForensicEvent): boolean {
  return e.canonical?.dns?.vantage === "endpoint" && !!e.asset;
}

function isConnCandidate(e: ForensicEvent): boolean {
  const src = e.canonical?.network?.source?.address;
  const dst = e.canonical?.network?.destination?.address;
  return !!src && !!dst && isIdentifyingIp(src) && isIdentifyingIp(dst);
}

/** #1313: the source address may name a host only when its writer stamped it edge-observed
 * (#1265) — fail-closed, exactly as proxyWorkstationChain.ts reads the same flag. */
function isHostAttributable(e: ForensicEvent): boolean {
  return e.canonical?.network?.source?.provenance === "edge-observed";
}

interface HostedConn {
  event: ForensicEvent;
  binding: HostBinding;
}

function indexConns(
  events: readonly ForensicEvent[],
  bindingIndex: HostBindingIndex,
  hostToleranceMs: number,
): { matched: Map<string, HostedConn[]>; byDest: Map<string, ForensicEvent[]> } {
  const matched = new Map<string, HostedConn[]>(); // `${host}|${dst}` — unambiguous matches only
  const byDest = new Map<string, ForensicEvent[]>(); // `${dst}` — every candidate, any host

  for (const e of events) {
    if (!isConnCandidate(e)) continue;
    const src = e.canonical!.network!.source!.address!;
    const dst = canonicalIp(e.canonical!.network!.destination!.address!);

    const destList = byDest.get(dst) ?? [];
    destList.push(e);
    byDest.set(dst, destList);

    // Real evidence that the address was reached (indexed above); never evidence of WHO reached it
    // unless the writer itself vouched for the source — see TRUST BOUNDARY in the header.
    if (!isHostAttributable(e)) continue;
    const bindings = resolveIpAtTime(bindingIndex, src, e.timestamp, hostToleranceMs);
    const distinctHosts = new Set(bindings.map((b) => b.host));
    if (distinctHosts.size !== 1) continue; // ambiguous or unresolved — confirms no one
    const [host] = distinctHosts;
    const key = `${host}|${dst}`;
    const list = matched.get(key) ?? [];
    list.push({ event: e, binding: bindings[bindings.length - 1] });
    matched.set(key, list);
  }

  for (const list of matched.values())
    list.sort((a, b) => Date.parse(a.event.timestamp) - Date.parse(b.event.timestamp));
  return { matched, byDest };
}

function leadFor(
  d: ForensicEvent,
  host: string,
  address: string,
  matched: Map<string, HostedConn[]>,
  byDest: Map<string, ForensicEvent[]>,
  windowSeconds: number,
): {
  state: CrossUploadDnsConnState;
  band?: DnsGapBand;
  connectionEventId?: string;
  bindingSampleTime?: string;
  otherHostCaveat?: boolean;
} {
  const first = Date.parse(d.timestamp);
  const last = Date.parse(d.endTimestamp ?? d.timestamp);
  // A malformed persisted timestamp (Date.parse -> NaN) must never silently fall through to a
  // conservative-looking "no connection"/"earlier connections only" via a NaN comparison — named
  // explicitly, the same fix as the sibling file dnsCrossUploadConnJoin.ts (#1250, #1257).
  if (!Number.isFinite(first) || !Number.isFinite(last)) return { state: "DNS row time not placeable" };

  // A candidate whose OWN time is unparseable is excluded rather than silently losing every NaN
  // comparison (#1257) — a wrong "earlier connections only" verdict is worse than not participating.
  const candidates = (matched.get(`${host}|${address}`) ?? []).filter((c) =>
    Number.isFinite(Date.parse(c.event.endTimestamp ?? c.event.timestamp)),
  );

  if (candidates.length) {
    // Same fold-aware search #1248's own code review established: by the connection's own LAST
    // occurrence, not its first — a folded connection reaching into the window is still a match.
    const atOrAfter = candidates.find((c) => Date.parse(c.event.endTimestamp ?? c.event.timestamp) >= first);
    if (atOrAfter) {
      const connFirst = Date.parse(atOrAfter.event.timestamp);
      const gapMs = Math.max(0, connFirst - last);
      const state: CrossUploadDnsConnState =
        gapMs <= (windowSeconds + DNS_WINDOW_SLACK_S) * 1000
          ? "connected inside the window"
          : "first connection after the window";
      return {
        state,
        band: gapBand(gapMs),
        connectionEventId: atOrAfter.event.id,
        bindingSampleTime: atOrAfter.binding.sampleTime,
      };
    }
    // Every candidate is entirely before the query. The MOST RELEVANT one is whichever's own fold
    // reaches latest — not whichever started latest: a long-running connection that started early
    // can still end closer to the query than a short one that started later. `candidates` is sorted
    // by START, so picking the last element would pick the latter by mistake when folds overlap.
    const closest = candidates.reduce((best, c) =>
      Date.parse(c.event.endTimestamp ?? c.event.timestamp) >
      Date.parse(best.event.endTimestamp ?? best.event.timestamp)
        ? c
        : best,
    );
    return {
      state: "earlier connections only",
      connectionEventId: closest.event.id,
      bindingSampleTime: closest.binding.sampleTime,
    };
  }

  return { state: "no connection found in this case", otherHostCaveat: !!byDest.get(address)?.length };
}

/** `excluded` (#1345): the caller-owned sink `buildHostBindingIndex` counts rejected logon samples
 * into, by reason — the only signal that a "no connection found" lead below lost its connection to a
 * gated binding, not to absent evidence. */
export function resolveEndpointCrossUploadDnsConnLeads(
  events: readonly ForensicEvent[],
  aliasIndex: HostAliasIndex,
  hostToleranceMs: number,
  windowSeconds: number = DNS_FIXED_WINDOW_S,
  excluded?: Map<IpExclusionReason, number>,
): EndpointCrossUploadDnsConnLead[] {
  const bindingIndex = buildHostBindingIndex(events, aliasIndex, excluded);
  const { matched, byDest } = indexConns(events, bindingIndex, hostToleranceMs);
  const results: EndpointCrossUploadDnsConnLead[] = [];

  for (const e of events) {
    if (!isEndpointDnsRow(e)) continue;
    const host = resolveHost(aliasIndex, e.asset!);
    const query = e.canonical!.dns!.query;
    const occurrences = {
      count: e.count ?? 1,
      firstSeen: e.timestamp,
      lastSeen: e.endTimestamp ?? e.timestamp,
    };

    for (const v of e.canonical!.dns!.returned) {
      if (v.kind !== "address" || !isIdentifyingIp(v.value)) continue;
      const address = canonicalIp(v.value);
      const { state, band, connectionEventId, bindingSampleTime, otherHostCaveat } = leadFor(
        e,
        host,
        address,
        matched,
        byDest,
        windowSeconds,
      );
      const caveats = connectionEventId
        ? [FORWARDING_TOPOLOGY_CAVEAT, DHCP_LEASE_CAVEAT, AGGREGATION_WIDTH_CAVEAT]
        : otherHostCaveat
          ? [OTHER_HOST_CAVEAT]
          : [];
      results.push({
        eventId: e.id,
        host,
        query,
        address,
        state,
        ...(band ? { band } : {}),
        ...(connectionEventId ? { connectionEventId } : {}),
        ...(bindingSampleTime ? { bindingSampleTime } : {}),
        occurrences,
        hostToleranceMs,
        windowSeconds,
        caveats,
      });
    }
  }

  return results;
}
