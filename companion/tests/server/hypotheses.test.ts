import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";

async function makeApp(opts: { withStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-hypotheses-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const pinged: string[] = [];
  const app = createApp(store, {
    pipeline, stateStore,
    aiConfigured: false,
    ...(opts.withStore === false ? {} : {
      hypothesisStore: new HypothesisStore(store),
      onHypotheses: (caseId: string) => pinged.push(caseId),
    }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, pinged };
}

describe("hypothesis routes (#140)", () => {
  it("returns 501 when the store is not configured", async () => {
    const { app } = await makeApp({ withStore: false });
    expect((await request(app).get("/cases/c1/hypotheses")).status).toBe(501);
    expect((await request(app).post("/cases/c1/hypotheses").send({ title: "x" })).status).toBe(501);
  });

  it("creates an analyst hypothesis (201, born analystTouched) and lists it", async () => {
    const { app, pinged } = await makeApp();
    const res = await request(app).post("/cases/c1/hypotheses").send({
      title: "Initial access was phishing",
      expectedOutcome: "an .eml attachment or a malicious URL click",
      relatedTechniques: ["T1566.001"],
      author: "Alice",
    });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ title: "Initial access was phishing", source: "analyst", analystTouched: true, status: "open", author: "Alice" });
    expect(res.body.id).toBeTruthy();
    expect(pinged).toContain("c1");

    const list = (await request(app).get("/cases/c1/hypotheses")).body;
    expect(list).toHaveLength(1);
    expect(list[0].relatedTechniques).toEqual(["T1566.001"]);
  });

  it("rejects an empty title with 400", async () => {
    const { app } = await makeApp();
    expect((await request(app).post("/cases/c1/hypotheses").send({ title: "   " })).status).toBe(400);
  });

  it("PATCHes status/notes (marks analystTouched), 404s an unknown id", async () => {
    const { app } = await makeApp();
    const created = (await request(app).post("/cases/c1/hypotheses").send({ title: "Staging before encryption" })).body;
    const patched = await request(app).patch(`/cases/c1/hypotheses/${created.id}`).send({ status: "supported", notes: "confirmed via prefetch" });
    expect(patched.status).toBe(200);
    expect(patched.body).toMatchObject({ status: "supported", notes: "confirmed via prefetch", analystTouched: true });
    expect((await request(app).patch("/cases/c1/hypotheses/nope").send({ status: "refuted" })).status).toBe(404);
  });

  it("ignores an invalid status in PATCH (keeps the prior status)", async () => {
    const { app } = await makeApp();
    const created = (await request(app).post("/cases/c1/hypotheses").send({ title: "h", status: "open" })).body;
    const patched = await request(app).patch(`/cases/c1/hypotheses/${created.id}`).send({ status: "bogus" });
    expect(patched.status).toBe(200);
    expect(patched.body.status).toBe("open");
  });

  it("DELETEs a hypothesis (204) then 404s", async () => {
    const { app } = await makeApp();
    const created = (await request(app).post("/cases/c1/hypotheses").send({ title: "Lateral movement via SMB" })).body;
    expect((await request(app).delete(`/cases/c1/hypotheses/${created.id}`)).status).toBe(204);
    expect((await request(app).delete(`/cases/c1/hypotheses/${created.id}`)).status).toBe(404);
    expect((await request(app).get("/cases/c1/hypotheses")).body).toEqual([]);
  });
});
