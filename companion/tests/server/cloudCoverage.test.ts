// #1063: the per-upload cloud coverage route and its wiring through the pipeline's stash.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cc-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: false });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

describe("GET /cases/:id/cloud-coverage (#1063)", () => {
  it("returns an empty summary for a fresh case", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/cloud-coverage");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ items: [], caveats: [] });
  });

  it("returns the stored coverage and the read-time caveats", async () => {
    const { app, store } = await makeApp();
    const coverageStore = new CloudCoverageStore(store);
    await coverageStore.record("c1", [
      {
        provider: "aws-cloudtrail",
        scope: { kind: "account", value: "111122223333" },
        uploadId: "u1",
        recordCount: 5,
        first: "2026-01-01T00:00:00.000Z",
        last: "2026-01-02T00:00:00.000Z",
        categories: [{ name: "Management", count: 5 }],
      },
    ]);
    const res = await request(app).get("/cases/c1/cloud-coverage");
    expect(res.status).toBe(200);
    expect(res.body.items).toHaveLength(1);
    expect(res.body.items[0].scope).toEqual({ kind: "account", value: "111122223333" });
    expect(res.body.caveats.some((c: string) => c.includes("no Data-category records"))).toBe(true);
  });
});
