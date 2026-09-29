import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-bodies-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: false });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

describe("PUT /cases/:id/narrative body validation", () => {
  it("400s a missing or non-string narrativeTimeline and keeps the saved narrative", async () => {
    const { app, stateStore } = await makeApp();
    expect((await request(app).put("/cases/c1/narrative").send({ narrativeTimeline: "kept" })).status).toBe(
      200,
    );
    for (const body of [
      {},
      { narrative: "typo field" },
      { narrativeTimeline: 42 },
      { narrativeTimeline: null },
    ]) {
      const res = await request(app).put("/cases/c1/narrative").send(body);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("narrativeTimeline must be a string");
    }
    expect((await stateStore.load("c1")).narrativeTimeline).toBe("kept");
  });

  it("still lets an explicit empty string clear the narrative", async () => {
    const { app, stateStore } = await makeApp();
    await request(app).put("/cases/c1/narrative").send({ narrativeTimeline: "old" });
    const res = await request(app).put("/cases/c1/narrative").send({ narrativeTimeline: "" });
    expect(res.status).toBe(200);
    expect((await stateStore.load("c1")).narrativeTimeline).toBe("");
  });
});

describe("POST /cases/:id/ai-control body validation", () => {
  it("400s when enabled is missing or not a boolean, and leaves the setting as it was", async () => {
    const { app } = await makeApp();
    expect((await request(app).post("/cases/c1/ai-control").send({ enabled: true })).status).toBe(200);
    for (const body of [
      {},
      { includeNotebook: true },
      { enabled: "true" },
      { enabled: 1 },
      { enabled: null },
    ]) {
      const res = await request(app).post("/cases/c1/ai-control").send(body);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("enabled must be true or false");
    }
    expect((await request(app).get("/cases/c1/ai-control")).body.enabled).toBe(true);
  });

  it("still accepts a boolean enabled with includeNotebook", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/ai-control")
      .send({ enabled: false, includeNotebook: true });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ enabled: false, includeNotebook: true });
  });
});
