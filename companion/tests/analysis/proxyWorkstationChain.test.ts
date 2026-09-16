// #993 (proxy -> workstation half, part of #933 item 1): a web/proxy-log event's own
// network.source.address resolved against hostBinding.ts's own host-identity index (#1156) --
// zero, one, or an explicitly ambiguous set of candidate hosts, never picked down to one by any
// heuristic. Never claims "the workstation" unconditionally -- see the module's own header.
import { describe, it, expect } from "vitest";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { resolveProxyHostIdentity } from "../../src/analysis/proxyWorkstationChain.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const EMPTY_ALIAS = buildHostAliasIndex([], {});
let seq = 0;

function logonEvent(o: { sessionHost: string; clientName?: string; ip?: string; ts: string }): ForensicEvent {
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
      ...(o.clientName ? { session: { terminal: o.clientName } } : {}),
      ...(o.ip ? { network: { source: { address: o.ip } } } : {}),
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${seq}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A web-chain-shaped event carrying canonical.network.source.address (the #1032 chain envelope's
 * own `web` block detail isn't needed here -- eligibility never reads it). */
function webChainEvent(o: { ip: string; ts: string; locator?: string }): ForensicEvent {
  seq += 1;
  return {
    id: `web-${seq}`,
    timestamp: o.ts,
    description: `GET / from ${o.ip}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      network: { source: { address: o.ip } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "zeek-http", locator: o.locator ?? `row:${seq}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A Squid/combined-access-log-shaped event: carries network.source.address but NO canonical.web
 * -- must still be eligible for the IP join (combinedLogImport.ts:491's own real behavior). */
function combinedLogEvent(o: { ip: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `combined-${seq}`,
    timestamp: o.ts,
    description: `${o.ip} - - [request]`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      network: { source: { address: o.ip } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "combined-access-log", locator: `row:${seq}` }] },
      producer: { importer: "combined-log", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("resolveProxyHostIdentity", () => {
  it("matches a web-chain request's own source IP to the client host a 4624 logon names", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const web = webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:05:00Z" });
    const results = resolveProxyHostIdentity([logon, web], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      eventId: web.id,
      address: "10.0.0.5",
      outcome: "matched",
      toleranceMs: 21_600_000,
    });
    expect(results[0].hosts).toEqual([{ host: "ws-042", evidenceEventIds: [logon.id] }]);
  });

  it("also matches a combined-access-log (Squid) row -- eligibility is network.source.address, never canonical.web", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const combined = combinedLogEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:05:00Z" });
    const results = resolveProxyHostIdentity([logon, combined], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("matched");
    expect(results[0].hosts).toEqual([{ host: "ws-042", evidenceEventIds: [logon.id] }]);
  });

  it("reports no-match explicitly when no host-binding evidence exists in the window", () => {
    const events = [webChainEvent({ ip: "10.0.0.9", ts: "2026-06-10T12:05:00Z" })];
    const results = resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ outcome: "no-match", hosts: [], address: "10.0.0.9" });
  });

  it("does NOT report ambiguous when the SAME host logged on more than once in the window (ordinary re-auth)", () => {
    const logon1 = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T11:00:00Z",
    });
    const logon2 = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T11:30:00Z",
    });
    const web = webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" });
    const results = resolveProxyHostIdentity([logon1, logon2, web], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("matched");
    expect(results[0].hosts).toHaveLength(1);
    expect(results[0].hosts[0].host).toBe("ws-042");
    expect(results[0].hosts[0].evidenceEventIds.sort()).toEqual([logon1.id, logon2.id].sort());
  });

  it("reports ambiguous -- two workstations behind one proxy address -- and names both, never picking one", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T11:00:00Z" }),
      logonEvent({ sessionHost: "fs-02", clientName: "ws-099", ip: "10.0.0.5", ts: "2026-06-10T13:00:00Z" }),
      webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const results = resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("ambiguous");
    expect(results[0].hosts.map((h) => h.host).sort()).toEqual(["ws-042", "ws-099"]);
  });

  it("never joins outside the declared tolerance window", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-01T00:00:00Z" }),
      webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const results = resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("no-match");
  });

  it("never emits an entry for a logon event itself, even though it also carries network.source.address", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    expect(resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000)).toEqual([]);
  });

  it("surfaces every rawRecords locator on an aggregated web-chain row, not just one", () => {
    seq += 100; // avoid id collision with other tests' sequential ids
    const event: ForensicEvent = {
      id: "agg-1",
      timestamp: "2026-06-10T12:00:00Z",
      description: "GET / from 10.0.0.5 (x2)",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      count: 2,
      canonical: createCanonicalEvent({
        event: { category: "network", type: "web-request" },
        network: { source: { address: "10.0.0.5" } },
        time: { observed: "2026-06-10T12:00:00Z", normalized: "2026-06-10T12:00:00Z" },
        evidence: {
          rawRecords: [
            { source: "zeek-http", locator: "row:1" },
            { source: "zeek-http", locator: "row:2" },
          ],
        },
        producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
      }),
    };
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T11:59:00Z",
    });
    const results = resolveProxyHostIdentity([logon, event], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].locators).toEqual(["row:1", "row:2"]);
  });

  it("ignores an event with no network.source.address at all", () => {
    seq += 1;
    const noAddress: ForensicEvent = {
      id: "no-addr",
      timestamp: "2026-06-10T12:00:00Z",
      description: "unrelated",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    };
    expect(resolveProxyHostIdentity([noAddress], EMPTY_ALIAS, 21_600_000)).toEqual([]);
  });
});
