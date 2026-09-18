// #996 (cross-upload half of the query -> connection lead): a sensor-vantage DNS answer joined
// to ANY connection-shaped event anywhere in the case, by shared IP pair. No host resolution --
// both sides are already plain IPs. Aggregation (`count`/`endTimestamp`) is a real, disclosed
// precision loss this report-time join must live with -- see the module's own header.
import { describe, it, expect } from "vitest";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { resolveCrossUploadDnsConnLeads } from "../../src/analysis/dnsCrossUploadConnJoin.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;

/** A sensor-vantage DNS answer (Zeek dns.log / Suricata dns) -- always a plain IP client. */
function sensorDnsEvent(o: {
  client: string;
  query: string;
  address: string;
  ts: string;
  endTs?: string;
  count?: number;
}): ForensicEvent {
  seq += 1;
  return {
    id: `dns-${seq}`,
    timestamp: o.ts,
    ...(o.endTs ? { endTimestamp: o.endTs } : {}),
    ...(o.count ? { count: o.count } : {}),
    description: `${o.client} asked for ${o.query}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "dns-answer" },
      dns: {
        query: o.query,
        queryValid: true,
        indicator: true,
        state: "answered by the peer",
        returned: [{ value: o.address, kind: "address" }],
        ownership: "not in this record",
        vantage: "sensor",
        client: o.client,
      },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "zeek-dns", locator: `row:${seq}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A connection-shaped event -- any of Sysmon 3 / WFP 5156 / Zeek conn.log / Suricata flow write
 * this same canonical.network shape; `tool` only labels the fixture for the test's own reading. */
function connEvent(o: {
  src: string;
  dst: string;
  ts: string;
  endTs?: string;
  count?: number;
  tool?: string;
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
      network: { source: { address: o.src }, destination: { address: o.dst, port: 443 } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: o.tool ?? "zeek-conn", locator: `row:${seq}` }] },
      producer: { importer: o.tool ?? "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("resolveCrossUploadDnsConnLeads", () => {
  it("connects inside the window when a matching connection starts after the answer", () => {
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:00:02Z" });
    const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      eventId: dns.id,
      client: "10.0.0.5",
      address: "203.0.113.5",
      state: "connected inside the window",
      connectionEventId: conn.id,
      windowSeconds: 300,
    });
    expect(results[0].caveats.length).toBeGreaterThan(0);
  });

  it("reports first connection after the window when the gap exceeds it", () => {
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:10:00Z" });
    const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
    expect(results[0].state).toBe("first connection after the window");
  });

  it("reports earlier connections only when every match started before the answer", () => {
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T11:00:00Z" });
    const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
    expect(results[0]).toMatchObject({ state: "earlier connections only", connectionEventId: conn.id });
  });

  it("reports no connection found in this case when nothing matches at all", () => {
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const results = resolveCrossUploadDnsConnLeads([dns], 300);
    expect(results[0]).toMatchObject({ state: "no connection found in this case" });
    expect(results[0].connectionEventId).toBeUndefined();
    expect(results[0].caveats).toEqual([]);
  });

  // #1250: a malformed persisted timestamp made Date.parse return NaN, and a NaN comparison
  // silently classified the lead as "no connection"/"earlier connections only" -- indistinguishable
  // from a genuine miss. Named explicitly instead.
  it("names the DNS row's own time as not placeable, rather than a silent NaN-driven miss", () => {
    const dns = {
      ...sensorDnsEvent({
        client: "10.0.0.5",
        query: "cdn.example.net",
        address: "203.0.113.5",
        ts: "2026-06-10T12:00:00Z",
      }),
      timestamp: "not-a-real-timestamp",
    };
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:00:02Z" });
    const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
    expect(results[0]).toMatchObject({ state: "DNS row time not placeable" });
    expect(results[0].connectionEventId).toBeUndefined();
  });

  it("excludes a connection candidate whose own time is unparseable, rather than letting it win or lose a NaN comparison", () => {
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const badConn = {
      ...connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:00:02Z" }),
      timestamp: "not-a-real-timestamp",
    };
    const results = resolveCrossUploadDnsConnLeads([dns, badConn], 300);
    expect(results[0]).toMatchObject({ state: "no connection found in this case" });
  });

  it("a folded row's window genuinely spans to the last occurrence, not just the first", () => {
    // first occurrence 12:00, last (folded) occurrence 12:20 -- a connection at 12:21 is inside
    // the window relative to the LAST occurrence even though it is 21 minutes after the FIRST.
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
      endTs: "2026-06-10T12:20:00Z",
      count: 5,
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:21:00Z" });
    const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
    expect(results[0].state).toBe("connected inside the window");
    expect(results[0].occurrences).toEqual({
      count: 5,
      firstSeen: "2026-06-10T12:00:00Z",
      lastSeen: "2026-06-10T12:20:00Z",
    });
  });

  it("matches regardless of which importer produced the connection row", () => {
    for (const tool of ["sysmon", "wfp5156", "zeek-conn", "suricata-flow"]) {
      const dns = sensorDnsEvent({
        client: "10.0.0.5",
        query: "cdn.example.net",
        address: "203.0.113.5",
        ts: "2026-06-10T12:00:00Z",
      });
      const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:00:02Z", tool });
      const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
      expect(results[0].state).toBe("connected inside the window");
    }
  });

  it("an endpoint-vantage or resolver-vantage DNS row is never eligible -- only sensor vantage joins here", () => {
    seq += 1;
    const endpointRow: ForensicEvent = {
      id: `endpoint-${seq}`,
      timestamp: "2026-06-10T12:00:00Z",
      description: "endpoint queried cdn.example.net",
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
          returned: [{ value: "203.0.113.5", kind: "address" }],
          ownership: "not in this record",
          vantage: "endpoint",
        },
        time: { observed: "2026-06-10T12:00:00Z", normalized: "2026-06-10T12:00:00Z" },
        evidence: { rawRecords: [{ source: "sysmon", locator: `row:${seq}` }] },
        producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
      }),
    };
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:00:02Z" });
    const results = resolveCrossUploadDnsConnLeads([endpointRow, conn], 300);
    expect(results).toEqual([]);
  });

  it("an IPv4-mapped IPv6 spelling on one side still matches the dotted-quad spelling on the other", () => {
    const dns = sensorDnsEvent({
      client: "::ffff:10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const conn = connEvent({ src: "10.0.0.5", dst: "203.0.113.5", ts: "2026-06-10T12:00:02Z" });
    const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
    expect(results[0].state).toBe("connected inside the window");
  });

  it("a loopback or empty client is never eligible -- noise, not identity", () => {
    const dns = sensorDnsEvent({
      client: "127.0.0.1",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const results = resolveCrossUploadDnsConnLeads([dns], 300);
    expect(results).toEqual([]);
  });

  it("a folded connection whose fold reaches into the window is not 'earlier connections only'", () => {
    // The connection's own FIRST occurrence (11:58) is before the DNS answer (12:00), but its own
    // LAST occurrence (12:00:30) reaches past it -- some occurrence within that fold could plausibly
    // be the one that followed this query. Missing this was a real bug caught in code review.
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const conn = connEvent({
      src: "10.0.0.5",
      dst: "203.0.113.5",
      ts: "2026-06-10T11:58:00Z",
      endTs: "2026-06-10T12:00:30Z",
      count: 3,
    });
    const results = resolveCrossUploadDnsConnLeads([dns, conn], 300);
    expect(results[0]).toMatchObject({ state: "connected inside the window", connectionEventId: conn.id });
  });

  it("the join is directional -- client as source, resolved address as destination, matching the same-upload precedent -- a reversed pair does not match", () => {
    const dns = sensorDnsEvent({
      client: "10.0.0.5",
      query: "cdn.example.net",
      address: "203.0.113.5",
      ts: "2026-06-10T12:00:00Z",
    });
    // Reversed: the resolved address as SOURCE, the client as DESTINATION -- a different real-world
    // event (something connecting TO the client), not "the client connecting to the answer".
    const reversed = connEvent({ src: "203.0.113.5", dst: "10.0.0.5", ts: "2026-06-10T12:00:02Z" });
    const results = resolveCrossUploadDnsConnLeads([dns, reversed], 300);
    expect(results[0].state).toBe("no connection found in this case");
  });
});
