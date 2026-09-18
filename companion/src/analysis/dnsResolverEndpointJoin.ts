// #996 (resolver ↔ endpoint half of the DNS-answer-to-connection join): a DNS Server Analytical
// log row (dnsServerRecord.ts, #1222 — `canonical.dns.vantage === "resolver"`) joined to the
// ENDPOINT's own DNS record for the same query (dnsRecord.ts — `vantage === "endpoint"`, Sysmon 22
// / DNS-Client), only through a shared identity both records establish: the resolver's own
// `client` address resolved to a host via hostBinding.ts's index (#1158), then that host's own
// endpoint-vantage record for the SAME query, near the SAME time.
//
// READ-TIME, ROUTE-LEVEL, NEVER A MERGE-TIME PASS — same contract as proxyWorkstationChain.ts
// (#993), which this module is modeled on directly: reads `state.forensicTimeline` as already
// persisted, recomputed on every call, never wired into stateMerge.ts.
//
// TWO TOLERANCES, NOT ONE — a real, deliberate departure from the proxyWorkstationChain.ts
// precedent it's otherwise modeled on. `hostToleranceMs` bounds how stale a logon sample may be and
// still name the host at the resolver row's client IP (the same kind of question the precedent
// asks, so it reuses the precedent's own 6h/30d bounds). `queryToleranceMs` bounds how far apart a
// real query and its OWN endpoint-side log line may be — a much tighter window: the two records
// describe the SAME real-world DNS transaction, seconds apart in practice, so a multi-hour window
// here would let an unrelated later query on the same host false-match as "confirmed."
//
// "NOT CONFIRMED" IS NEVER A NEGATIVE FACT — #996's own guardrail: "a cache hit at the endpoint's
// stub never reaches the resolver log and the join must say so." The inverse holds too: a stub
// resolver that answered from its OWN cache never sent the query onward, so the DNS server's log
// (and therefore this join) has nothing to confirm against — indistinguishable from the query
// simply never having been imported. Said in-band on every result (`caveats`), never only here.
//
// EXACT QUERY-NAME MATCH ONLY. Both `dnsRecord.ts`'s endpoint overlay and `dnsServerRecord.ts`'s
// resolver overlay canonicalize a valid name through the SAME exported `asciiName`/
// `isValidQueryName` — including stripping a trailing root dot before conversion — so identical
// real names always produce byte-identical `canonical.dns.query` strings on both sides; this is a
// shared-function guarantee, not an assumption. What it does NOT cover: a resolver that logs the
// name as originally asked while the endpoint's own stub logs an intermediate CNAME hop (or the
// reverse) describes the same real lookup under two different names — no chain-awareness exists in
// either DNS envelope today, so that pairing is missed, disclosed rather than fixed here.
//
// INDEXED, NOT SCANNED PER ROW. Endpoint-vantage rows are indexed once by `host|query` before the
// per-resolver-row loop — mirrors `buildHostBindingIndex`'s own one-time-build shape, so this is
// O(events) total, never O(resolver rows × events).

import { buildHostBindingIndex, resolveIpAtTime, type HostBinding } from "./hostBinding.js";
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";
import type { ForensicEvent } from "./stateTypes.js";

export type ResolverEndpointOutcome = "no-match" | "matched" | "ambiguous";
export type ResolverEndpointConfirmation = "found" | "not confirmed at the endpoint";

const CACHE_HIT_CAVEAT =
  '"not confirmed at the endpoint" is not a negative fact: a stub resolver that answered this ' +
  "query from its own cache never sent it to this DNS server, so no endpoint-side record is " +
  "expected to exist either way — this join cannot distinguish a cache hit from the query simply " +
  "not being in this case";
const FORWARDING_TOPOLOGY_CAVEAT =
  "a resolved host names whichever machine's own logon evidence shares the resolver row's client " +
  "address at that time — if this DNS server is itself a forwarding target behind another " +
  "resolver (a branch relay, a local caching forwarder), the recorded client could be that " +
  "forwarder, not the real originating endpoint";
const DHCP_LEASE_CAVEAT =
  "no DHCP-lease evidence exists in this codebase — the address could have been reassigned to a " +
  "different host between the logon sample and this event; the tolerance window is a heuristic, never a guarantee";
const CHAIN_NAME_CAVEAT =
  "the query name is matched exactly — a resolver record and an endpoint record that describe the " +
  "same real lookup under two different names (an intermediate CNAME hop logged on one side and " +
  "not the other) will not be paired";

export interface ResolverEndpointMatch {
  eventId: string;
  client: string;
  query: string;
  outcome: ResolverEndpointOutcome;
  hosts: {
    host: string;
    sampleTime: string;
    evidenceEventIds: string[];
    endpointQuery: ResolverEndpointConfirmation;
    endpointEventIds: string[];
  }[];
  locators: { source: string; locator: string }[];
  hostToleranceMs: number;
  queryToleranceMs: number;
  caveats: string[];
}

function isResolverRow(e: ForensicEvent): boolean {
  return e.canonical?.dns?.vantage === "resolver" && !!e.canonical?.dns?.client;
}

function isEndpointDnsRow(e: ForensicEvent): boolean {
  return e.canonical?.dns?.vantage === "endpoint" && !!e.canonical?.dns?.query && !!e.asset;
}

/** Every raw record on an event, aggregated rows included — mirrors proxyWorkstationChain.ts's own helper. */
function locatorsOf(e: ForensicEvent): { source: string; locator: string }[] {
  return (e.canonical?.evidence?.rawRecords ?? []).map((r) => ({ source: r.source, locator: r.locator }));
}

/** `host|query` → the endpoint-vantage rows that could confirm a resolver row's query at that host. */
function indexEndpointDns(
  events: readonly ForensicEvent[],
  aliasIndex: HostAliasIndex,
): Map<string, ForensicEvent[]> {
  const byHostQuery = new Map<string, ForensicEvent[]>();
  for (const e of events) {
    if (!isEndpointDnsRow(e)) continue;
    const key = `${resolveHost(aliasIndex, e.asset!)}|${e.canonical!.dns!.query}`;
    const list = byHostQuery.get(key) ?? [];
    list.push(e);
    byHostQuery.set(key, list);
  }
  return byHostQuery;
}

function confirmationFor(
  candidates: readonly ForensicEvent[] | undefined,
  atIso: string,
  queryToleranceMs: number,
): { confirmation: ResolverEndpointConfirmation; eventIds: string[] } {
  const at = Date.parse(atIso);
  const within = (candidates ?? []).filter((e) => {
    const t = Date.parse(e.timestamp);
    return Number.isFinite(at) && Number.isFinite(t) && Math.abs(t - at) <= queryToleranceMs;
  });
  return within.length
    ? { confirmation: "found", eventIds: within.map((e) => e.id) }
    : { confirmation: "not confirmed at the endpoint", eventIds: [] };
}

export function resolveResolverEndpointIdentity(
  events: readonly ForensicEvent[],
  aliasIndex: HostAliasIndex,
  hostToleranceMs: number,
  queryToleranceMs: number,
): ResolverEndpointMatch[] {
  const bindingIndex = buildHostBindingIndex(events, aliasIndex);
  const endpointIndex = indexEndpointDns(events, aliasIndex);
  const results: ResolverEndpointMatch[] = [];

  for (const e of events) {
    if (!isResolverRow(e)) continue;
    const client = e.canonical!.dns!.client!;
    const query = e.canonical!.dns!.query;

    const bindings = resolveIpAtTime(bindingIndex, client, e.timestamp, hostToleranceMs);
    const byHost = new Map<string, HostBinding[]>();
    for (const b of bindings) byHost.set(b.host, [...(byHost.get(b.host) ?? []), b]);

    const hosts = [...byHost.entries()]
      .map(([host, hostBindings]) => {
        const sorted = [...hostBindings].sort((a, b) => a.sampleTime.localeCompare(b.sampleTime));
        const { confirmation, eventIds } = confirmationFor(
          endpointIndex.get(`${host}|${query}`),
          e.timestamp,
          queryToleranceMs,
        );
        return {
          host,
          sampleTime: sorted[sorted.length - 1].sampleTime,
          evidenceEventIds: [...new Set(hostBindings.map((b) => b.evidenceEventId))],
          endpointQuery: confirmation,
          endpointEventIds: eventIds,
        };
      })
      .sort((a, b) => (a.host < b.host ? -1 : a.host > b.host ? 1 : 0));

    // CACHE_HIT_CAVEAT applies to a no-match row at least as strongly as a match: a stub
    // resolver answering from its own cache is exactly what a bare "no host resolved" outcome
    // looks like. The other three caveats describe a resolved host binding and don't apply
    // when there is no host (#1244).
    const caveats: string[] = [CACHE_HIT_CAVEAT];
    if (hosts.length) caveats.push(FORWARDING_TOPOLOGY_CAVEAT, DHCP_LEASE_CAVEAT, CHAIN_NAME_CAVEAT);

    results.push({
      eventId: e.id,
      client,
      query,
      outcome: hosts.length === 0 ? "no-match" : hosts.length === 1 ? "matched" : "ambiguous",
      hosts,
      locators: locatorsOf(e),
      hostToleranceMs,
      queryToleranceMs,
      caveats,
    });
  }

  return results;
}
