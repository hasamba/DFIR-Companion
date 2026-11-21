import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

// #2792: a GET with a JSON body had its request stream consumed (and auto-destroyed) by the body
// parser, so the abandoned-read gate mistook it for a client that had hung up and never answered.
async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-get-body-"));
  const store = new CaseStore(root);
  const app = createApp(store, { stateStore: new StateStore(store) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return app;
}

describe("GET on a case route with a JSON body (#2792)", () => {
  it("answers instead of leaving the connection hanging", async () => {
    const app = await makeApp();
    const res = await request(app)
      .get("/cases/c1/state")
      .set("content-type", "application/json")
      .send(JSON.stringify({ a: 1 }))
      .timeout(5000);
    expect(res.status).toBe(200);
  });

  it("still answers a GET without a body", async () => {
    const res = await request(await makeApp())
      .get("/cases/c1/state")
      .timeout(5000);
    expect(res.status).toBe(200);
  });
});
