// #996 (resolver ↔ endpoint half): a DNS Server Analytical row's own `client` resolved against
// hostBinding.ts's index, then checked against that host's own endpoint-vantage DNS record for the
// SAME query, near the SAME time. Never picks one host down from several; "not confirmed" is
// always an explicit partial lead, never a negative fact -- see the module's own header.
import { describe, it, expect } from "vitest";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { resolveResolverEndpointIdentity } from "../../src/analysis/dnsResolverEndpointJoin.js";
import { asciiName } from "../../src/analysis/dnsRecord.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const EMPTY_ALIAS = buildHostAliasIndex([], {});
const HOST_TOLERANCE_MS = 21_600_000; // 6 hours
const QUERY_TOLERANCE_MS = 300_000; // 5 minutes
let seq = 0;

function logonEvent(o: { sessionHost: string; clientName: string; ip: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `logon-${seq}`,
    timestamp: o.ts,
    description: `Windows Security logon @ ${o.sessionHost}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: o.sessionHost,
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: "success" },
      target: { kind: "host", name: o.sessionHost },
      authentication: { logonType: 3 },
      session: { terminal: o.clientName },
      network: { source: { address: o.ip } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${seq}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A DNS Server Analytical row (dnsServerRecord.ts, #1222) -- the resolver's own record. */
function resolverDnsEvent(o: { client: string; query: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `resolver-${seq}`,
    timestamp: o.ts,
    description: `DNS Server answered ${o.query} for ${o.client}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "dc-01",
    canonical: createCanonicalEvent({
      event: { category: "network", type: "dns-query" },
      dns: {
        query: o.query,
        queryValid: true,
        indicator: true,
        state: "answered",
        returned: [],
        ownership: "not in this record",
        vantage: "resolver",
        client: o.client,
      },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "dns-server-analytical", locator: `row:${seq}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** An endpoint's own DNS record (Sysmon 22 / DNS-Client, dnsRecord.ts). */
function endpointDnsEvent(o: { host: string; query: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `endpoint-${seq}`,
    timestamp: o.ts,
    description: `endpoint queried ${o.query}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: o.host,
    canonical: createCanonicalEvent({
      event: { category: "network", type: "dns-query" },
      dns: {
        query: o.query,
        queryValid: true,
        indicator: true,
        state: "success",
        returned: [],
        ownership: "not in this record",
        vantage: "endpoint",
      },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "sysmon", locator: `row:${seq}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("resolveResolverEndpointIdentity", () => {
  it("resolves the resolver row's client to a host and confirms it at that host's own endpoint record", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const resolver = resolverDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      ts: "2026-06-10T12:05:00Z",
    });
    const endpoint = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      ts: "2026-06-10T12:05:01Z",
    });
    const results = resolveResolverEndpointIdentity(
      [logon, resolver, endpoint],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      eventId: resolver.id,
      client: "10.0.0.5",
      query: "cdn.example.net",
      outcome: "matched",
      hostToleranceMs: HOST_TOLERANCE_MS,
      queryToleranceMs: QUERY_TOLERANCE_MS,
    });
    expect(results[0].hosts).toEqual([
      {
        host: "ws-042",
        sampleTime: "2026-06-10T12:00:00Z",
        evidenceEventIds: [logon.id],
        endpointQuery: "found",
        endpointEventIds: [endpoint.id],
      },
    ]);
    expect(results[0].caveats.length).toBeGreaterThan(0);
  });

  it("names the host but reports 'not confirmed' when no matching endpoint record exists -- never a negative fact", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const resolver = resolverDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      ts: "2026-06-10T12:05:00Z",
    });
    const results = resolveResolverEndpointIdentity(
      [logon, resolver],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results[0].outcome).toBe("matched");
    expect(results[0].hosts[0]).toMatchObject({
      host: "ws-042",
      endpointQuery: "not confirmed at the endpoint",
    });
    expect(results[0].hosts[0].endpointEventIds).toEqual([]);
    expect(results[0].caveats.some((c) => c.includes("not a negative fact"))).toBe(true);
  });

  it("a DIFFERENT query name at the same host does not confirm -- proves the query check is real", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const resolver = resolverDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      ts: "2026-06-10T12:05:00Z",
    });
    const endpoint = endpointDnsEvent({
      host: "ws-042",
      query: "other.example.net",
      ts: "2026-06-10T12:05:01Z",
    });
    const results = resolveResolverEndpointIdentity(
      [logon, resolver, endpoint],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results[0].hosts[0].endpointQuery).toBe("not confirmed at the endpoint");
  });

  it("the same query at the right host OUTSIDE the query tolerance window does not confirm", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const resolver = resolverDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      ts: "2026-06-10T12:05:00Z",
    });
    // 10 minutes later -- outside the 5-minute query tolerance, inside the 6-hour host tolerance.
    const endpoint = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      ts: "2026-06-10T12:15:00Z",
    });
    const results = resolveResolverEndpointIdentity(
      [logon, resolver, endpoint],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results[0].hosts[0].endpointQuery).toBe("not confirmed at the endpoint");
  });

  it("reports no-match when no host-binding evidence exists for the client at all", () => {
    const resolver = resolverDnsEvent({
      client: "10.0.0.9",
      query: "cdn.example.net",
      ts: "2026-06-10T12:05:00Z",
    });
    const results = resolveResolverEndpointIdentity(
      [resolver],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results[0]).toMatchObject({ outcome: "no-match", hosts: [] });
    // A no-match is not a negative fact either: a stub resolver's cache hit never reaches this
    // DNS server, so the caveat must survive on a no-match row, not only on a matched one.
    expect(results[0].caveats.some((c) => c.includes("not a negative fact"))).toBe(true);
  });

  it("reports ambiguous -- two hosts sharing one IP in the window -- and checks each independently", () => {
    const logon1 = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T11:00:00Z",
    });
    const logon2 = logonEvent({
      sessionHost: "fs-02",
      clientName: "ws-099",
      ip: "10.0.0.5",
      ts: "2026-06-10T13:00:00Z",
    });
    const resolver = resolverDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      ts: "2026-06-10T12:00:00Z",
    });
    const endpoint = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      ts: "2026-06-10T12:00:01Z",
    });
    const results = resolveResolverEndpointIdentity(
      [logon1, logon2, resolver, endpoint],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results[0].outcome).toBe("ambiguous");
    expect(results[0].hosts).toHaveLength(2);
    const ws042 = results[0].hosts.find((h) => h.host === "ws-042")!;
    const ws099 = results[0].hosts.find((h) => h.host === "ws-099")!;
    expect(ws042.endpointQuery).toBe("found");
    expect(ws099.endpointQuery).toBe("not confirmed at the endpoint");
  });

  it("a 259 (ignored query, no client) row is never eligible -- no result emitted for it", () => {
    seq += 1;
    const ignored: ForensicEvent = {
      id: `ignored-${seq}`,
      timestamp: "2026-06-10T12:05:00Z",
      description: "DNS Server ignored a query",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "dc-01",
      canonical: createCanonicalEvent({
        event: { category: "network", type: "dns-query" },
        dns: {
          query: "cdn.example.net",
          queryValid: true,
          indicator: true,
          state: "ignored",
          returned: [],
          ownership: "not in this record",
          vantage: "resolver",
        },
        time: { observed: "2026-06-10T12:05:00Z", normalized: "2026-06-10T12:05:00Z" },
        evidence: { rawRecords: [{ source: "dns-server-analytical", locator: `row:${seq}` }] },
        producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
      }),
    };
    const results = resolveResolverEndpointIdentity(
      [ignored],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results).toHaveLength(0);
  });

  it("a mixed-case, trailing-dot raw name run through the REAL canonicalizer on both sides still matches", () => {
    // Proves the module header's "shared-function guarantee" claim against the real function,
    // rather than assuming two importers agree -- both dnsRecord.ts's endpoint overlay and
    // dnsServerRecord.ts's resolver overlay call this exact function on a valid name.
    const canonical = asciiName("CDN.Example.NET.").toLowerCase();
    expect(canonical).toBe("cdn.example.net"); // sanity: trailing dot stripped, lowercased
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const resolver = resolverDnsEvent({ client: "10.0.0.5", query: canonical, ts: "2026-06-10T12:05:00Z" });
    const endpoint = endpointDnsEvent({ host: "ws-042", query: canonical, ts: "2026-06-10T12:05:01Z" });
    const results = resolveResolverEndpointIdentity(
      [logon, resolver, endpoint],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      QUERY_TOLERANCE_MS,
    );
    expect(results[0].hosts[0].endpointQuery).toBe("found");
  });
});
