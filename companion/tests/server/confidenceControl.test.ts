import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { ConfidenceControlStore } from "../../src/analysis/confidenceControl.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-confctl-"));
  const store = new CaseStore(root);
  const confidenceControlStore = new ConfidenceControlStore(store);
  const app = createApp(store, { confidenceControlStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app };
}

describe("GET/PUT /cases/:id/confidence-control", () => {
  it("GET defaults to null (show all) for a fresh case", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/confidence-control");
    expect(res.status).toBe(200);
    expect(res.body.minConfidence).toBe(null);
  });

  it("PUT persists a valid minConfidence and GET reflects it", async () => {
    const { app } = await makeApp();
    const put = await request(app).put("/cases/c1/confidence-control").send({ minConfidence: 60 });
    expect(put.status).toBe(200);
    expect(put.body.minConfidence).toBe(60);

    const get = await request(app).get("/cases/c1/confidence-control");
    expect(get.body.minConfidence).toBe(60);
  });

  it("rejects an out-of-range minConfidence with 400", async () => {
    const { app } = await makeApp();
    const res = await request(app).put("/cases/c1/confidence-control").send({ minConfidence: 150 });
    expect(res.status).toBe(400);
  });

  it("rejects a non-numeric minConfidence with 400", async () => {
    const { app } = await makeApp();
    const res = await request(app).put("/cases/c1/confidence-control").send({ minConfidence: "high" });
    expect(res.status).toBe(400);
  });

  it("clears the override when minConfidence is null", async () => {
    const { app } = await makeApp();
    await request(app).put("/cases/c1/confidence-control").send({ minConfidence: 60 });
    const cleared = await request(app).put("/cases/c1/confidence-control").send({ minConfidence: null });
    expect(cleared.status).toBe(200);
    expect(cleared.body.minConfidence).toBe(null);
  });

  it("501s when the store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-confctl-none-"));
    const store = new CaseStore(root);
    const app = createApp(store, {});
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).get("/cases/c1/confidence-control");
    expect(res.status).toBe(501);
  });
});
