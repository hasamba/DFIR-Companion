// #996 (the last query -> connection pair): GET /cases/:id/endpoint-dns-connection-cross-upload-matches.
// Real StateStore-backed events, real hostBinding.ts + dnsEndpointCrossUploadConnJoin.ts resolution
// end-to-end.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { InvestigationState, ForensicEvent } from "../../src/analysis/stateTypes.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-endpoint-cross-upload-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

// `stamped: false` builds the logon a case imported before d0b613fa (#1310) still holds — a persisted
// canonical event is never re-derived, so it carries no `provenance` and #1342's gate drops it.
function logonEvent(
  id: string,
  host: string,
  client: string,
  ip: string,
  ts: string,
  stamped = true,
): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `logon @ ${host}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: host,
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: "success" },
      target: { kind: "host", name: host },
      authentication: { logonType: 3 },
      session: { terminal: client },
      // #1292: the stamp every real 4624 writer carries
      network: { source: { address: ip, ...(stamped ? { provenance: "edge-observed" as const } : {}) } },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${id}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function endpointDnsEvent(
  id: string,
  host: string,
  query: string,
  address: string,
  ts: string,
): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `${host} queried ${query}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: host,
    canonical: createCanonicalEvent({
      event: { category: "network", type: "dns-query" },
      dns: {
        query,
        queryValid: true,
        indicator: true,
        state: "success",
        returned: [{ value: address, kind: "address" }],
        ownership: "not in this record",
        vantage: "endpoint",
      },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "sysmon", locator: `row:${id}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

// Stamped edge-observed the way the live Zeek writer (networkImport.ts) stamps it (#1265): the join
// resolves the source to a host only when its writer vouched for it (#1313).
function connEvent(id: string, src: string, dst: string, ts: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `${src} -> ${dst}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "connection" },
      network: {
        source: { address: src, provenance: "edge-observed" },
        destination: { address: dst, port: 443 },
      },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "zeek-conn", locator: `row:${id}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function stateWith(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("c1"), forensicTimeline: events, updatedAt: new Date().toISOString() };
}

describe("GET /cases/:id/endpoint-dns-connection-cross-upload-matches", () => {
  it("returns 501 when the state store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-endpoint-cross-upload-bare-"));
    const store = new CaseStore(root);
    const bareApp = createApp(store, {});
    await request(bareApp)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(bareApp).get("/cases/c1/endpoint-dns-connection-cross-upload-matches");
    expect(res.status).toBe(501);
  });

  it("resolves a known host's DNS query to a connection from a separate upload", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "ws-042", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        endpointDnsEvent("d1", "ws-042", "cdn.example.net", "203.0.113.5", "2026-06-10T12:05:00Z"),
        connEvent("c1conn", "10.0.0.5", "203.0.113.5", "2026-06-10T12:05:02Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/endpoint-dns-connection-cross-upload-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toHaveLength(1);
    expect(res.body.matches[0]).toMatchObject({
      eventId: "d1",
      host: "ws-042",
      state: "connected inside the window",
      connectionEventId: "c1conn",
    });
    expect(res.body.excludedLogonSamples).toEqual({}); // #1345: a stamped logon is never counted out
  });

  // #1345: since #1342 an unstamped logon (every 4624 persisted before d0b613fa) silently leaves the
  // IP->host index, so the connection's source resolves to no host and the lead that used to say
  // "connected inside the window" says "no connection found in this case". The route now discloses
  // the gated count to the analyst — the only signal that a re-import is needed.
  it("discloses a logon the provenance gate excluded instead of a bare no-connection lead", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "ws-042", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z", false),
        endpointDnsEvent("d1", "ws-042", "cdn.example.net", "203.0.113.5", "2026-06-10T12:05:00Z"),
        connEvent("c1conn", "10.0.0.5", "203.0.113.5", "2026-06-10T12:05:02Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/endpoint-dns-connection-cross-upload-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches[0]).toMatchObject({ eventId: "d1", state: "no connection found in this case" });
    expect(res.body.matches[0].connectionEventId).toBeUndefined();
    expect(res.body.excludedLogonSamples).toEqual({ "not-edge-observed": 1 });
  });

  it("uses the default 300s window when none is given, and does not confirm past it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "ws-042", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        endpointDnsEvent("d1", "ws-042", "cdn.example.net", "203.0.113.5", "2026-06-10T12:05:00Z"),
        connEvent("c1conn", "10.0.0.5", "203.0.113.5", "2026-06-10T12:15:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/endpoint-dns-connection-cross-upload-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches[0].state).toBe("first connection after the window");
  });

  it("accepts overriding ?hostToleranceMs= and ?windowSeconds= query params", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "ws-042", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        endpointDnsEvent("d1", "ws-042", "cdn.example.net", "203.0.113.5", "2026-06-10T12:05:00Z"),
        connEvent("c1conn", "10.0.0.5", "203.0.113.5", "2026-06-10T12:15:00Z"),
      ]),
    );
    const res = await request(app).get(
      "/cases/c1/endpoint-dns-connection-cross-upload-matches?windowSeconds=900",
    );
    expect(res.status).toBe(200);
    expect(res.body.matches[0].state).toBe("connected inside the window");
    expect(res.body.matches[0].windowSeconds).toBe(900);
  });

  it("400s a malformed tolerance instead of silently clamping it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get(
      "/cases/c1/endpoint-dns-connection-cross-upload-matches?hostToleranceMs=-5",
    );
    expect(res.status).toBe(400);
    const res2 = await request(app).get(
      "/cases/c1/endpoint-dns-connection-cross-upload-matches?windowSeconds=notanumber",
    );
    expect(res2.status).toBe(400);
  });

  it("400s a windowSeconds past its documented ceiling instead of silently accepting it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get(
      "/cases/c1/endpoint-dns-connection-cross-upload-matches?windowSeconds=99999999",
    );
    expect(res.status).toBe(400);
  });

  it("returns an empty match list for a well-formed but nonexistent case, never a 500", async () => {
    const { app } = await makeApp();
    const res = await request(app).get(
      "/cases/nonexistent-case/endpoint-dns-connection-cross-upload-matches",
    );
    expect(res.status).toBe(200);
    expect(res.body.matches).toEqual([]);
  });
});
