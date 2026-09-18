// #996 (the last query -> connection pair): a Windows endpoint's own DNS query matched to a
// connection recorded in a SEPARATE upload, via hostBinding.ts's index on the connection's source
// IP. An ambiguously-resolved connection never confirms more than one host; "no connection found"
// and "a connection exists for a different host" stay distinguishable -- see the module's own header.
import { describe, it, expect } from "vitest";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { resolveEndpointCrossUploadDnsConnLeads } from "../../src/analysis/dnsEndpointCrossUploadConnJoin.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const EMPTY_ALIAS = buildHostAliasIndex([], {});
const HOST_TOLERANCE_MS = 21_600_000; // 6 hours
const WINDOW_SECONDS = 300; // 5 minutes
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

/** An endpoint's own DNS query (Sysmon 22 / DNS-Client, dnsRecord.ts). */
function endpointDnsEvent(o: {
  host: string;
  query: string;
  address: string;
  ts: string;
  endTs?: string;
  count?: number;
}): ForensicEvent {
  seq += 1;
  return {
    id: `endpoint-${seq}`,
    timestamp: o.ts,
    ...(o.endTs ? { endTimestamp: o.endTs } : {}),
    ...(o.count ? { count: o.count } : {}),
    description: `${o.host} queried ${o.query}`,
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
        returned: [{ value: o.address, kind: "address" }],
        ownership: "not in this record",
        vantage: "endpoint",
      },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "sysmon", locator: `row:${seq}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A connection-shaped event in a SEPARATE upload -- any of the four canonical.network producers.
 * Stamped `provenance: "edge-observed"` by default, the way every live connection writer does
 * (#1265); `unstamped: true` models a legacy connection (pre-#1265 envelope, or a flat-`srcIp`
 * importer upgraded at load) whose source address the join must never resolve to a host (#1313). */
function connEvent(o: {
  src: string;
  dst: string;
  ts: string;
  endTs?: string;
  count?: number;
  unstamped?: boolean;
}): ForensicEvent {
  seq += 1;
  return {
    id: `conn-${seq}`,
    timestamp: o.ts,
    ...(o.endTs ? { endTimestamp: o.endTs } : {}),
    ...(o.count ? { count: o.count } : {}),
    description: `${o.src} -> ${o.dst}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "connection" },
      network: {
        source: { address: o.src, ...(o.unstamped ? {} : { provenance: "edge-observed" as const }) },
        destination: { address: o.dst, port: 443 },
      },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "zeek-conn", locator: `row:${seq}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("resolveEndpointCrossUploadDnsConnLeads", () => {
  it("matches a known host's DNS query to a connection whose source IP resolves to that SAME host", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:05:02Z" });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, conn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      eventId: dns.id,
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      state: "connected inside the window",
      connectionEventId: conn.id,
      bindingSampleTime: "2026-06-10T12:00:00Z",
    });
    expect(results[0].caveats.length).toBeGreaterThan(0);
  });

  // #1257: the same NaN-comparison gap tracked separately for the sibling file
  // dnsCrossUploadConnJoin.ts (#1250) — a malformed persisted timestamp made Date.parse return
  // NaN, and a NaN comparison silently classified the lead as a miss, indistinguishable from a
  // genuine one. Named explicitly instead.
  it("names the DNS row's own time as not placeable, rather than a silent NaN-driven miss", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const dns = {
      ...endpointDnsEvent({
        host: "ws-042",
        query: "cdn.example.net",
        address: "203.0.113.5",
        ts: "2026-06-10T12:05:00Z",
      }),
      timestamp: "not-a-real-timestamp",
    };
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:05:02Z" });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, conn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0]).toMatchObject({ state: "DNS row time not placeable" });
    expect(results[0].connectionEventId).toBeUndefined();
  });

  it("excludes a connection candidate whose own time is unparseable, rather than letting it win or lose a NaN comparison", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    const badConn = {
      ...connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:05:02Z" }),
      timestamp: "not-a-real-timestamp",
    };
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, badConn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0].state).toBe("no connection found in this case");
  });

  // #1313: the same fail-closed gate proxyWorkstationChain.ts applies (#1265) -- this join resolves
  // the connection's source address to a HOST NAME through the same resolveIpAtTime call, so an
  // address no writer stamped as edge-observed must never name a host. The connection is still
  // real evidence that SOMEONE reached the address, so it keeps feeding the other-host caveat.
  it("never resolves an UNSTAMPED connection source to a host, even when logon evidence would match it", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    const legacyConn = connEvent({
      src: "10.0.0.5",
      dst: "203.0.113.5",
      ts: "2026-06-10T12:05:02Z",
      unstamped: true,
    });
    expect(legacyConn.canonical?.network?.source?.provenance).toBeUndefined();
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, legacyConn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results).toHaveLength(1);
    expect(results[0].state).toBe("no connection found in this case");
    expect(results[0].connectionEventId).toBeUndefined();
    expect(results[0].bindingSampleTime).toBeUndefined();
    expect(results[0].caveats.some((c) => c.includes("a connection to this address exists elsewhere"))).toBe(
      true,
    );
  });

  it("does not match when the connection's source IP resolves to a DIFFERENT host", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-099",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:05:02Z" });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, conn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0].state).toBe("no connection found in this case");
    expect(results[0].connectionEventId).toBeUndefined();
    // A connection to this address DOES exist in the case -- just not for OUR host -- a different
    // fact from no evidence anywhere, disclosed via caveat rather than silently collapsed.
    expect(results[0].caveats.some((c) => c.includes("a connection to this address exists elsewhere"))).toBe(
      true,
    );
  });

  it("reports a bare 'no connection found' with no other-host caveat when nothing matches at all", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0]).toMatchObject({ state: "no connection found in this case", caveats: [] });
  });

  it("an AMBIGUOUSLY-resolved connection confirms NO host, even one it might belong to -- never over-claims", () => {
    // The connecting IP has logon evidence for TWO different hosts in the window -- ws-042 and
    // ws-099 -- so the resolution is ambiguous. This connection must not "confirm" either host's
    // DNS query, even though ws-042 really did query for this exact address.
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
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:05:02Z" });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon1, logon2, dns, conn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0].state).toBe("no connection found in this case");
    expect(results[0].connectionEventId).toBeUndefined();
    // Still disclosed -- a connection to this address DOES exist in the case, ambiguously resolved.
    expect(results[0].caveats.some((c) => c.includes("a connection to this address exists elsewhere"))).toBe(
      true,
    );
  });

  it("a folded connection whose fold reaches into the window is not 'earlier connections only'", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    const conn = connEvent({
      src: "10.0.0.5",
      dst: "203.0.113.5",
      ts: "2026-06-10T12:03:00Z",
      endTs: "2026-06-10T12:05:30Z",
      count: 3,
    });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, conn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0]).toMatchObject({ state: "connected inside the window", connectionEventId: conn.id });
  });

  it("a resolver-vantage or sensor-vantage DNS row is never eligible -- only endpoint vantage", () => {
    seq += 1;
    const resolverRow: ForensicEvent = {
      id: `resolver-${seq}`,
      timestamp: "2026-06-10T12:05:00Z",
      description: "DNS Server answered",
      severity: "Info",
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
          state: "answered",
          returned: [],
          ownership: "not in this record",
          vantage: "resolver",
          client: "10.0.0.5",
        },
        time: { observed: "2026-06-10T12:05:00Z", normalized: "2026-06-10T12:05:00Z" },
        evidence: { rawRecords: [{ source: "dns-server-analytical", locator: `row:${seq}` }] },
        producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
      }),
    };
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [resolverRow],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results).toEqual([]);
  });

  it("reports 'earlier connections only' picking the connection whose fold reaches CLOSEST to the query, not whichever started latest", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T09:00:00Z",
    });
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    // A starts EARLIER but its own fold reaches LATER (closer to the query) than B, which starts
    // later but ends sooner. The relevant connection is A, not "whichever is last in start order".
    const connA = connEvent({
      src: "10.0.0.5",
      dst: "203.0.113.5",
      ts: "2026-06-10T10:00:00Z",
      endTs: "2026-06-10T10:30:00Z",
    });
    const connB = connEvent({
      src: "10.0.0.5",
      dst: "203.0.113.5",
      ts: "2026-06-10T10:15:00Z",
      endTs: "2026-06-10T10:16:00Z",
    });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, connA, connB],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0]).toMatchObject({ state: "earlier connections only", connectionEventId: connA.id });
  });

  it("an unresolved source IP (no logon evidence anywhere) still surfaces the other-host caveat when a connection to the address exists", () => {
    const dns = endpointDnsEvent({
      host: "ws-042",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:05:00Z",
    });
    // No logon fixture at all -- the connection's source IP has zero host-binding evidence.
    const conn = connEvent({ src: "10.0.0.9", dst: "203.0.113.5", ts: "2026-06-10T12:05:02Z" });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [dns, conn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results[0]).toMatchObject({ state: "no connection found in this case" });
    expect(results[0].caveats.some((c) => c.includes("a connection to this address exists elsewhere"))).toBe(
      true,
    );
  });

  it("a DNS row with multiple returned addresses produces one independently-evaluated result per address", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    seq += 1;
    const dns: ForensicEvent = {
      id: `endpoint-${seq}`,
      timestamp: "2026-06-10T12:05:00Z",
      description: "ws-042 queried cdn.example.net",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "ws-042",
      canonical: createCanonicalEvent({
        event: { category: "network", type: "dns-query" },
        dns: {
          query: "cdn.example.net",
          queryValid: true,
          indicator: true,
          state: "success",
          returned: [
            { value: "203.0.113.5", kind: "address" },
            { value: "203.0.113.6", kind: "address" },
          ],
          ownership: "not in this record",
          vantage: "endpoint",
        },
        time: { observed: "2026-06-10T12:05:00Z", normalized: "2026-06-10T12:05:00Z" },
        evidence: { rawRecords: [{ source: "sysmon", locator: `row:${seq}` }] },
        producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
      }),
    };
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:05:02Z" });
    const results = resolveEndpointCrossUploadDnsConnLeads(
      [logon, dns, conn],
      EMPTY_ALIAS,
      HOST_TOLERANCE_MS,
      WINDOW_SECONDS,
    );
    expect(results).toHaveLength(2);
    const first = results.find((r) => r.address === "203.0.113.5")!;
    const second = results.find((r) => r.address === "203.0.113.6")!;
    expect(first.state).toBe("connected inside the window");
    expect(second.state).toBe("no connection found in this case");
  });
});
