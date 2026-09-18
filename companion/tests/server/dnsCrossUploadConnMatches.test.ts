// #996 (cross-upload query -> connection half): GET /cases/:id/dns-connection-cross-upload-matches.
// Real StateStore-backed events, real dnsCrossUploadConnJoin.ts resolution end-to-end.
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
  const root = await mkdtemp(join(tmpdir(), "dfir-dns-cross-upload-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

function sensorDnsEvent(
  id: string,
  client: string,
  query: string,
  address: string,
  ts: string,
): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `${client} asked for ${query}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "dns-answer" },
      dns: {
        query,
        queryValid: true,
        indicator: true,
        state: "answered by the peer",
        returned: [{ value: address, kind: "address" }],
        ownership: "not in this record",
        vantage: "sensor",
        client,
      },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "zeek-dns", locator: `row:${id}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

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
      network: { source: { address: src }, destination: { address: dst, port: 443 } },
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "zeek-conn", locator: `row:${id}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function stateWith(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("c1"), forensicTimeline: events, updatedAt: new Date().toISOString() };
}

describe("GET /cases/:id/dns-connection-cross-upload-matches", () => {
  it("returns 501 when the state store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-dns-cross-upload-bare-"));
    const store = new CaseStore(root);
    const bareApp = createApp(store, {});
    await request(bareApp)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(bareApp).get("/cases/c1/dns-connection-cross-upload-matches");
    expect(res.status).toBe(501);
  });

  it("resolves a sensor DNS answer to a connection from a separate upload", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        sensorDnsEvent("d1", "10.0.0.5", "cdn.example.net", "203.0.113.5", "2026-06-10T12:00:00Z"),
        connEvent("c1conn", "10.0.0.5", "203.0.113.5", "2026-06-10T12:00:02Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/dns-connection-cross-upload-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toHaveLength(1);
    expect(res.body.matches[0]).toMatchObject({
      eventId: "d1",
      state: "connected inside the window",
      connectionEventId: "c1conn",
      windowSeconds: 300,
    });
  });

  it("uses the default 300s window when none is given, and does not confirm past it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        sensorDnsEvent("d1", "10.0.0.5", "cdn.example.net", "203.0.113.5", "2026-06-10T12:00:00Z"),
        connEvent("c1conn", "10.0.0.5", "203.0.113.5", "2026-06-10T12:10:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/dns-connection-cross-upload-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches[0].state).toBe("first connection after the window");
  });

  it("accepts an overriding ?windowSeconds= query param", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        sensorDnsEvent("d1", "10.0.0.5", "cdn.example.net", "203.0.113.5", "2026-06-10T12:00:00Z"),
        connEvent("c1conn", "10.0.0.5", "203.0.113.5", "2026-06-10T12:10:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/dns-connection-cross-upload-matches?windowSeconds=900");
    expect(res.status).toBe(200);
    expect(res.body.matches[0].state).toBe("connected inside the window");
    expect(res.body.matches[0].windowSeconds).toBe(900);
  });

  it("400s a malformed windowSeconds instead of silently clamping it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get("/cases/c1/dns-connection-cross-upload-matches?windowSeconds=-5");
    expect(res.status).toBe(400);
    const res2 = await request(app).get(
      "/cases/c1/dns-connection-cross-upload-matches?windowSeconds=notanumber",
    );
    expect(res2.status).toBe(400);
  });

  it("400s a windowSeconds past its documented ceiling instead of silently accepting it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get(
      "/cases/c1/dns-connection-cross-upload-matches?windowSeconds=99999999",
    );
    expect(res.status).toBe(400);
  });

  it("returns an empty match list for a well-formed but nonexistent case, never a 500", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/nonexistent-case/dns-connection-cross-upload-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toEqual([]);
  });
});
