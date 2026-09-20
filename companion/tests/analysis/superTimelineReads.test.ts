// #1444: the routes that used to load the WHOLE super-timeline now stream it through a `reads`
// predicate and keep only the rows their analysis can use. Each predicate is exported next to the
// analysis it guards, and this file pins the contract that makes the filter safe: the analysis
// gives the same answer on the filtered list as on the full one. A predicate that drops a row the
// analysis reads would change a panel silently — that is the failure this file exists to catch.
import { describe, it, expect } from "vitest";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { buildTlsCaseGraph, tlsCaseGraphReads } from "../../src/analysis/tlsCaseGraph.js";
import {
  resolveProxyHostIdentity,
  proxyHostIdentityReads,
} from "../../src/analysis/proxyWorkstationChain.js";
import {
  resolveResolverEndpointIdentity,
  resolverEndpointIdentityReads,
} from "../../src/analysis/dnsResolverEndpointJoin.js";
import type { TlsGraphBlock } from "../../src/analysis/canonicalTls.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const EMPTY_ALIAS = buildHostAliasIndex([], {});
const T0 = "2026-06-01T10:00:00.000Z";
const T1 = "2026-06-01T10:01:00.000Z";
let seq = 0;

const base = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: `e${++seq}`,
  timestamp: T0,
  description: "row",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

/** The bulk of a capped case: MFT / USN file rows the identity and TLS analyses never read. */
const fileRow = (i: number): ForensicEvent =>
  base({
    description: `file observed C:\\Windows\\System32\\f${i}.dll`,
    path: `C:\\Windows\\System32\\f${i}.dll`,
    asset: "ws-01",
    canonical: createCanonicalEvent({
      event: { category: "file", type: "observation" },
      target: { kind: "host", name: "ws-01" },
      file: { path: `C:\\Windows\\System32\\f${i}.dll`, name: `f${i}.dll` },
      time: { observed: T0, normalized: T0 },
      evidence: { rawRecords: [{ source: "mft", locator: `row:${i}` }] },
      producer: { importer: "velociraptor", parserVersion: "1", mappingVersion: "1" },
    }),
  });

const logon = (o: { sessionHost: string; clientName: string; ip: string; ts: string }): ForensicEvent =>
  base({
    timestamp: o.ts,
    severity: "Low",
    asset: o.sessionHost,
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: "success" },
      target: { kind: "host", name: o.sessionHost },
      authentication: { logonType: 3 },
      session: { terminal: o.clientName },
      network: { source: { address: o.ip, provenance: "edge-observed" } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${seq}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  });

const webRow = (ip: string, ts: string): ForensicEvent =>
  base({
    timestamp: ts,
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      network: { source: { address: ip, provenance: "edge-observed" } },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "zeek-http", locator: `row:${seq}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  });

const resolverRow = (client: string, query: string, ts: string): ForensicEvent =>
  base({
    timestamp: ts,
    asset: "dc-01",
    canonical: createCanonicalEvent({
      event: { category: "network", type: "dns-query" },
      dns: {
        query,
        queryValid: true,
        indicator: true,
        state: "answered",
        returned: [],
        ownership: "not in this record",
        vantage: "resolver",
        client,
      },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "dns-server-analytical", locator: `row:${seq}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  });

const endpointDnsRow = (host: string, query: string, ts: string): ForensicEvent =>
  base({
    timestamp: ts,
    asset: host,
    canonical: createCanonicalEvent({
      event: { category: "network", type: "dns-query" },
      dns: {
        query,
        queryValid: true,
        indicator: true,
        state: "success",
        returned: [],
        ownership: "not in this record",
        vantage: "endpoint",
      },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "sysmon", locator: `row:${seq}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  });

const tlsRow = (fp: string): ForensicEvent => {
  const block: TlsGraphBlock = {
    node: { kind: "certificate", id: fp, alg: "sha256" },
    sensor: { name: "sensor-a" },
    names: { count: 1, listed: ["a.example.net"] },
    servers: { count: 1, listed: ["203.0.113.9:443"] },
    clientAddresses: { count: 1, listed: ["10.0.0.5"] },
    first: T0,
    last: T1,
    sessions: 3,
    leads: [],
    coverage: { sessionsRead: 3, sessionsTotal: 3, certificatesRead: 1, certificatesTotal: 1 },
    basis: "records in this upload only; no contact with any observed infrastructure",
  };
  return base({
    sources: ["Zeek"],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "tls-graph" },
      tlsGraph: block,
      time: { observed: T0, normalized: T0 },
      evidence: { rawRecords: [{ source: "zeek-ssl", locator: `row:${seq}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  });
};

const noise = Array.from({ length: 50 }, (_, i) => fileRow(i));

describe("superTimelineStore consumers read only what their predicate keeps (#1444)", () => {
  it("tlsCaseGraphReads: the graph over the filtered rows equals the graph over every row", () => {
    const all = [...noise, tlsRow("aa".repeat(32)), ...noise, tlsRow("bb".repeat(32))];
    const kept = all.filter(tlsCaseGraphReads);
    expect(kept).toHaveLength(2);
    expect(buildTlsCaseGraph(kept)).toEqual(buildTlsCaseGraph(all));
    expect(buildTlsCaseGraph(kept).nodes.length).toBeGreaterThan(0);
  });

  it("proxyHostIdentityReads: identity matches over the filtered rows equal the full-list matches", () => {
    const all = [
      ...noise,
      logon({ sessionHost: "fs-01", clientName: "WS-07", ip: "10.1.2.3", ts: T0 }),
      ...noise,
      webRow("10.1.2.3", T1),
    ];
    const kept = all.filter(proxyHostIdentityReads);
    expect(kept).toHaveLength(2);
    const full = resolveProxyHostIdentity(all, EMPTY_ALIAS, 3_600_000);
    expect(full.length).toBeGreaterThan(0);
    expect(resolveProxyHostIdentity(kept, EMPTY_ALIAS, 3_600_000)).toEqual(full);
  });

  it("resolverEndpointIdentityReads: resolver↔endpoint matches over the filtered rows equal the full-list matches", () => {
    const all = [
      ...noise,
      logon({ sessionHost: "fs-01", clientName: "WS-07", ip: "10.1.2.3", ts: T0 }),
      resolverRow("10.1.2.3", "evil.example", T1),
      ...noise,
      endpointDnsRow("WS-07", "evil.example", T1),
    ];
    const kept = all.filter(resolverEndpointIdentityReads);
    expect(kept).toHaveLength(3);
    const full = resolveResolverEndpointIdentity(all, EMPTY_ALIAS, 21_600_000, 300_000);
    expect(full.length).toBeGreaterThan(0);
    expect(resolveResolverEndpointIdentity(kept, EMPTY_ALIAS, 21_600_000, 300_000)).toEqual(full);
  });
});
