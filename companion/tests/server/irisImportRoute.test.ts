import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";

// A lightweight stand-in for the IRIS client — only the read methods the import path calls.
function mockIris(over: Partial<Record<string, unknown>> = {}): IrisClient {
  const base = {
    async ping() {},
    async listCases() { return [{ caseId: 7, caseName: "Ransomware FS01" }]; },
    async findCaseByName(name: string) { return name === "Ransomware FS01" ? { caseId: 7, caseName: name } : null; },
    async getRawAssets() { return [{ asset_id: 1, asset_name: "DC01", asset_compromise_status_id: 1 }]; },
    async getRawIocs() { return [{ ioc_id: 1, ioc_value: "8.8.8.8", ioc_type: "ip-dst" }]; },
    async getRawTimeline() {
      return [{
        event_id: 1, event_title: "C2 beacon", event_content: "C2 beacon\nAsset: DC01",
        event_date: "2026-06-04T13:00:00.000000", event_tz: "+00:00", event_color: "#f97316", event_tags: "high,T1071",
      }];
    },
    ...over,
  };
  return base as unknown as IrisClient;
}

async function makeApp(opts: { irisClient?: IrisClient; rebuildIrisClient?: () => IrisClient | undefined } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-iris-import-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, irisClient: opts.irisClient, rebuildIrisClient: opts.rebuildIrisClient });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

async function waitForEvents(stateStore: StateStore, caseId: string): Promise<number> {
  for (let i = 0; i < 100; i++) {
    const s = await stateStore.load(caseId);
    if (s.forensicTimeline.length > 0) return s.forensicTimeline.length;
    await new Promise((r) => setTimeout(r, 20));
  }
  return (await stateStore.load(caseId)).forensicTimeline.length;
}

describe("DFIR-IRIS import routes (issue #88)", () => {
  it("GET /iris/cases is 501 when IRIS is not configured", async () => {
    const { app } = await makeApp({});
    const res = await request(app).get("/iris/cases");
    expect(res.status).toBe(501);
  });

  it("GET /iris/cases lists cases when configured", async () => {
    const { app } = await makeApp({ irisClient: mockIris() });
    const res = await request(app).get("/iris/cases");
    expect(res.status).toBe(200);
    expect(res.body.cases).toEqual([{ caseId: 7, caseName: "Ransomware FS01" }]);
  });

  it("POST /cases/:id/iris-import is 501 when IRIS is not configured", async () => {
    const { app } = await makeApp({});
    const res = await request(app).post("/cases/c1/iris-import").send({ irisCaseId: 7 });
    expect(res.status).toBe(501);
  });

  it("400s when neither irisCaseId nor irisCaseName is given", async () => {
    const { app } = await makeApp({ irisClient: mockIris() });
    const res = await request(app).post("/cases/c1/iris-import").send({});
    expect(res.status).toBe(400);
  });

  it("imports an IRIS case (by id) into the forensic timeline + IOCs", async () => {
    const { app, stateStore } = await makeApp({ irisClient: mockIris() });
    const res = await request(app).post("/cases/c1/iris-import").send({ irisCaseId: 7 });
    expect(res.status).toBe(202);
    expect(res.body.caseName).toBe("Ransomware FS01");
    expect(res.body.timeline).toBe(1);
    expect(await waitForEvents(stateStore, "c1")).toBeGreaterThan(0);
    const state = await stateStore.load("c1");
    expect(state.iocs.some((i) => i.value === "8.8.8.8")).toBe(true);
    expect(state.forensicTimeline.some((e) => (e.sources ?? []).includes("DFIR-IRIS"))).toBe(true);
  });

  it("resolves the IRIS case by name", async () => {
    const { app, stateStore } = await makeApp({ irisClient: mockIris() });
    const res = await request(app).post("/cases/c1/iris-import").send({ irisCaseName: "Ransomware FS01" });
    expect(res.status).toBe(202);
    expect(await waitForEvents(stateStore, "c1")).toBeGreaterThan(0);
  });

  it("502s when the IRIS case name does not resolve", async () => {
    const { app } = await makeApp({ irisClient: mockIris() });
    const res = await request(app).post("/cases/c1/iris-import").send({ irisCaseName: "Nope" });
    expect(res.status).toBe(502);
  });

  it("POST /iris/reconnect reports not-configured when the rebuild yields no client", async () => {
    const { app } = await makeApp({ rebuildIrisClient: () => undefined });
    const res = await request(app).post("/iris/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
  });

  it("POST /iris/reconnect pings the rebuilt client and reports ok", async () => {
    const { app } = await makeApp({ rebuildIrisClient: () => mockIris() });
    const res = await request(app).post("/iris/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: true });
  });

  it("POST /iris/reconnect reports a reachability failure (configured but ping throws)", async () => {
    const down = mockIris({ async ping() { throw new Error("ECONNREFUSED"); } });
    const { app } = await makeApp({ rebuildIrisClient: () => down });
    const res = await request(app).post("/iris/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: false });
    expect(res.body.error).toMatch(/ECONNREFUSED/);
  });

  it("a successful reconnect swaps in the client so /iris/cases then works", async () => {
    const { app } = await makeApp({ rebuildIrisClient: () => mockIris() });   // no client at startup
    expect((await request(app).get("/iris/cases")).status).toBe(501);
    await request(app).post("/iris/reconnect");
    const res = await request(app).get("/iris/cases");
    expect(res.status).toBe(200);
    expect(res.body.cases).toHaveLength(1);
  });
});
