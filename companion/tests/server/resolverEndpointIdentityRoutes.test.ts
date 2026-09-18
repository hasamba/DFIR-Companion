// #996 (resolver -> endpoint half): GET /cases/:id/resolver-endpoint-matches. Real
// StateStore-backed events, real hostBinding.ts + dnsResolverEndpointJoin.ts resolution end-to-end.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createApp } from "../../src/server.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { InvestigationState, ForensicEvent } from "../../src/analysis/stateTypes.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-resolver-endpoint-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

async function makeAppWithSuperTimeline() {
  const root = await mkdtemp(join(tmpdir(), "dfir-resolver-endpoint-super-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const app = createApp(store, { stateStore, superTimelineStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore };
}

function logonEvent(id: string, host: string, client: string, ip: string, ts: string): ForensicEvent {
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
      network: { source: { address: ip, provenance: "edge-observed" } }, // #1292: the stamp every real 4624 writer carries
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${id}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function resolverEvent(id: string, client: string, query: string, ts: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `DNS Server answered ${query} for ${client}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
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
      evidence: { rawRecords: [{ source: "dns-server-analytical", locator: `row:${id}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function endpointDnsEvent(id: string, host: string, query: string, ts: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `endpoint queried ${query}`,
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
        returned: [],
        ownership: "not in this record",
        vantage: "endpoint",
      },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "sysmon", locator: `row:${id}` }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function stateWith(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("c1"), forensicTimeline: events, updatedAt: new Date().toISOString() };
}

describe("GET /cases/:id/resolver-endpoint-matches", () => {
  it("returns 501 when the state store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-resolver-endpoint-bare-"));
    const store = new CaseStore(root);
    const bareApp = createApp(store, {});
    await request(bareApp)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(bareApp).get("/cases/c1/resolver-endpoint-matches");
    expect(res.status).toBe(501);
  });

  it("resolves a resolver row's client to a host and confirms it at the endpoint", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        resolverEvent("r1", "10.0.0.5", "cdn.example.net", "2026-06-10T12:05:00Z"),
        endpointDnsEvent("e1", "ws-042", "cdn.example.net", "2026-06-10T12:05:01Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/resolver-endpoint-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toHaveLength(1);
    expect(res.body.matches[0]).toMatchObject({ eventId: "r1", outcome: "matched" });
    expect(res.body.matches[0].hosts).toEqual([
      {
        host: "ws-042",
        sampleTime: "2026-06-10T12:00:00Z",
        evidenceEventIds: ["l1"],
        endpointQuery: "found",
        endpointEventIds: ["e1"],
      },
    ]);
  });

  it("uses the default 5-minute query tolerance when none is given, and does not confirm past it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        resolverEvent("r1", "10.0.0.5", "cdn.example.net", "2026-06-10T12:05:00Z"),
        // 10 minutes later -- outside the 5-minute default query tolerance.
        endpointDnsEvent("e1", "ws-042", "cdn.example.net", "2026-06-10T12:15:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/resolver-endpoint-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches[0].hosts[0].endpointQuery).toBe("not confirmed at the endpoint");
    expect(res.body.matches[0].queryToleranceMs).toBe(300_000);
  });

  it("accepts overriding ?hostToleranceMs= and ?queryToleranceMs= query params", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        resolverEvent("r1", "10.0.0.5", "cdn.example.net", "2026-06-10T12:05:00Z"),
        endpointDnsEvent("e1", "ws-042", "cdn.example.net", "2026-06-10T12:15:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/resolver-endpoint-matches?queryToleranceMs=1200000");
    expect(res.status).toBe(200);
    expect(res.body.matches[0].hosts[0].endpointQuery).toBe("found");
    expect(res.body.matches[0].queryToleranceMs).toBe(1_200_000);
  });

  it("400s a malformed tolerance instead of silently clamping it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get("/cases/c1/resolver-endpoint-matches?hostToleranceMs=-5");
    expect(res.status).toBe(400);
    const res2 = await request(app).get("/cases/c1/resolver-endpoint-matches?queryToleranceMs=notanumber");
    expect(res2.status).toBe(400);
  });

  it("400s a queryToleranceMs past its documented ceiling instead of silently accepting it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get("/cases/c1/resolver-endpoint-matches?queryToleranceMs=999999999999");
    expect(res.status).toBe(400);
  });

  it("returns an empty match list for a well-formed but nonexistent case, never a 500", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/nonexistent-case/resolver-endpoint-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toEqual([]);
  });

  // #1277: dab20efe added the forensic ∪ super-timeline union read (#1243) but neither route's own
  // suite proved it. The resolver row and its endpoint confirmation live ONLY in the super-timeline
  // (as they would under the severity gate, which routes Info/Low rows there) — if the route ever
  // regressed to reading state.forensicTimeline alone, both would vanish and no match would appear.
  it("resolves and confirms a resolver row that lives only in the super-timeline, not the forensic timeline", async () => {
    const { app, stateStore, superTimelineStore } = await makeAppWithSuperTimeline();
    await stateStore.save(
      stateWith([logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z")]),
    );
    await superTimelineStore.append("c1", [
      resolverEvent("r1", "10.0.0.5", "cdn.example.net", "2026-06-10T12:05:00Z"),
      endpointDnsEvent("e1", "ws-042", "cdn.example.net", "2026-06-10T12:05:01Z"),
    ]);

    const res = await request(app).get("/cases/c1/resolver-endpoint-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toHaveLength(1);
    expect(res.body.matches[0]).toMatchObject({ eventId: "r1", outcome: "matched" });
    expect(res.body.matches[0].hosts).toEqual([
      {
        host: "ws-042",
        sampleTime: "2026-06-10T12:00:00Z",
        evidenceEventIds: ["l1"],
        endpointQuery: "found",
        endpointEventIds: ["e1"],
      },
    ]);
  });
});
