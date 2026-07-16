import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const LOGON_DESC = (acct: string, host: string, type: number, failed = false) =>
  `Windows Security ${failed ? "Failed logon (EID 4625)" : "Successful logon (EID 4624)"} - ${acct} - LogonType=${type} - IpAddress=10.0.0.5 @ ${host}`;

const ev = (id: string, description: string, asset: string): ForensicEvent => ({
  id, description, asset,
  timestamp: "2026-06-10T12:00:00Z", severity: "Low",
  mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
});

// Harness mirrors tests/server/superTimeline.test.ts (real CaseStore + StateStore + a deterministic
// runtime pipeline with NO AI provider), but seeds the SuperTimelineStore DIRECTLY via append() —
// the login-graph routes are pure reads over the raw super-timeline, no import round-trip needed.
async function harness(opts: { withStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-logingraph-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore,
    ...(opts.withStore === false ? {} : { superTimelineStore }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, superTimelineStore };
}

describe("GET /cases/:id/login-graph", () => {
  it("501s when the super-timeline store is not configured", async () => {
    const { app } = await harness({ withStore: false });
    expect((await request(app).get("/cases/c1/login-graph")).status).toBe(501);
  });

  it("returns the documented shape, honors maxEdges, stamps generatedAt", async () => {
    const { app, superTimelineStore } = await harness();
    await superTimelineStore.append("c1", [
      ev("e1", LOGON_DESC("CORP\\jdoe", "SRV-01", 2), "SRV-01"),
      ev("e2", LOGON_DESC("CORP\\jdoe", "SRV-01", 2), "SRV-01"),   // distinct id → same edge, count 2
      ev("e3", LOGON_DESC("CORP\\bob", "SRV-02", 10), "SRV-02"),
    ]);
    const res = await request(app).get("/cases/c1/login-graph");
    expect(res.status).toBe(200);
    expect(res.body.edges.length).toBe(2);
    expect(res.body.totalEdges).toBe(2);
    expect(res.body.truncated).toBe(false);
    expect(typeof res.body.generatedAt).toBe("string");
    const capped = await request(app).get("/cases/c1/login-graph?maxEdges=1");
    expect(capped.body.edges.length).toBe(1);
    expect(capped.body.truncated).toBe(true);
  });

  it("returns an empty graph (200, not error) for a case with no logon rows", async () => {
    const { app } = await harness();
    const res = await request(app).get("/cases/c1/login-graph");
    expect(res.status).toBe(200);
    expect(res.body.nodes).toEqual([]);
    expect(res.body.edges).toEqual([]);
  });
});

describe("GET /cases/:id/login-graph/edge-events", () => {
  it("400s without account+host; returns matching events with total", async () => {
    const { app, superTimelineStore } = await harness();
    await superTimelineStore.append("c1", [
      ev("e1", LOGON_DESC("CORP\\jdoe", "SRV-01", 2), "SRV-01"),
      ev("e2", LOGON_DESC("CORP\\jdoe", "SRV-01", 3), "SRV-01"),
    ]);
    expect((await request(app).get("/cases/c1/login-graph/edge-events")).status).toBe(400);
    const res = await request(app).get(
      "/cases/c1/login-graph/edge-events?account=CORP%5Cjdoe&host=SRV-01&type=Interactive&outcome=success");
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.events[0].id).toBe("e1");
    expect(res.body.events[0].sourceIp).toBe("10.0.0.5");
  });
});
