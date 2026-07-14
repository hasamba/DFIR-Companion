import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SourceTrustStore } from "../../src/analysis/sourceTrustStore.js";

async function makeApp(withStore = true) {
  const root = await mkdtemp(join(tmpdir(), "dfir-trust-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({ stateStore, store, imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }) });
  const app = createApp(store, {
    pipeline, stateStore, aiConfigured: false,
    ...(withStore ? { sourceTrustStore: new SourceTrustStore(store) } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app };
}

describe("source-trust routes (#66)", () => {
  it("GET returns the default map and empty overrides initially", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/source-trust");
    expect(res.status).toBe(200);
    expect(res.body.defaults.crowdstrike).toBe(1.0);
    expect(res.body.overrides).toEqual({});
  });

  it("PUT persists sanitized overrides and GET reflects them", async () => {
    const { app } = await makeApp();
    const put = await request(app).put("/cases/c1/source-trust").send({ overrides: { Velociraptor: 0.4, BadTool: 9, "": 0.2 } });
    expect(put.status).toBe(200);
    expect(put.body.overrides).toEqual({ velociraptor: 0.4 });   // out-of-range + empty-key dropped, lowercased
    const get = (await request(app).get("/cases/c1/source-trust")).body;
    expect(get.overrides).toEqual({ velociraptor: 0.4 });
  });

  it("accepts a bare-map body (no 'overrides' wrapper)", async () => {
    const { app } = await makeApp();
    const put = await request(app).put("/cases/c1/source-trust").send({ splunk: 0.5 });
    expect(put.body.overrides).toEqual({ splunk: 0.5 });
  });

  it("returns 501 when the store is not configured", async () => {
    const { app } = await makeApp(false);
    expect((await request(app).get("/cases/c1/source-trust")).status).toBe(501);
    expect((await request(app).put("/cases/c1/source-trust").send({})).status).toBe(501);
  });
});
