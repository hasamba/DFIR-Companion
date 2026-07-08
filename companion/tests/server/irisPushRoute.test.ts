import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { IrisExportStore } from "../../src/integrations/iris/irisExportStore.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";

// A recording mock IRIS client covering every method pushCaseToIris calls, plus a `cases`
// array the tests inspect directly to assert no duplicate/unrelated case was created.
function mockIrisPush(over: Partial<Record<string, unknown>> = {}) {
  const cases: { caseId: number; caseName: string }[] = [];
  let nextCaseId = 100;
  const base = {
    async ping() {},
    async findCaseByName(name: string) {
      return cases.find((c) => c.caseName.toLowerCase() === name.toLowerCase()) ?? null;
    },
    async createCase(body: { case_name: string }) {
      const ref = { caseId: nextCaseId++, caseName: body.case_name };
      cases.push(ref);
      return ref;
    },
    async setSummary() {},
    async iocTypeMap() { return new Map<string, number>(); },
    async assetTypeMap() { return new Map<string, number>(); },
    async eventCategoryMap() { return new Map<string, number>(); },
    async taskStatusMap() { return new Map<string, number>([["to do", 1]]); },
    async listAssets() { return []; },
    async addAsset() { return 1; },
    async listIocs() { return []; },
    async addIoc() { return 1; },
    async listEvents() { return []; },
    async addEvent() { return 1; },
    async listTasks() { return []; },
    async addTask() { return 1; },
    async listDirectories() { return []; },
    async addDirectory() { return 1; },
    async deleteDirectory() {},
    async addNote() { return 1; },
    ...over,
  };
  return { client: base as unknown as IrisClient, cases };
}

async function makeApp(irisClient: IrisClient) {
  const root = await mkdtemp(join(tmpdir(), "dfir-iris-push-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const irisExportStore = new IrisExportStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, irisClient, irisExportStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "Ransomware FS01", investigator: "i", aiProvider: null });
  return app;
}

describe("POST /cases/:id/push/iris (stable case naming + override)", () => {
  it("defaults the IRIS case name to '<case id> — <friendly name>' and creates the case", async () => {
    const { client, cases } = mockIrisPush();
    const app = await makeApp(client);
    const res = await request(app).post("/cases/c1/push/iris").send({});
    expect(res.status).toBe(200);
    expect(res.body.created).toBe(true);
    expect(cases).toEqual([{ caseId: 100, caseName: "c1 — Ransomware FS01" }]);
  });

  it("honors an explicit case-name override", async () => {
    const { client, cases } = mockIrisPush();
    const app = await makeApp(client);
    const res = await request(app).post("/cases/c1/push/iris").send({ caseName: "acme-breach-2026" });
    expect(res.status).toBe(200);
    expect(cases).toEqual([{ caseId: 100, caseName: "acme-breach-2026" }]);
  });

  it("remembers the override on the next push instead of reverting to the default", async () => {
    const { client, cases } = mockIrisPush();
    const app = await makeApp(client);
    await request(app).post("/cases/c1/push/iris").send({ caseName: "acme-breach-2026" });
    const res2 = await request(app).post("/cases/c1/push/iris").send({});
    expect(res2.status).toBe(200);
    expect(res2.body.created).toBe(false);   // matched the SAME case, not a new one
    expect(cases).toHaveLength(1);           // still only one IRIS case exists
    expect(cases[0].caseName).toBe("acme-breach-2026");
  });

  it("creates a new case rather than colliding with an unrelated existing one", async () => {
    const { client, cases } = mockIrisPush();
    cases.push({ caseId: 1, caseName: "Case #1" });   // e.g. IRIS's own seeded default case
    const app = await makeApp(client);
    const res = await request(app).post("/cases/c1/push/iris").send({});
    expect(res.status).toBe(200);
    expect(res.body.created).toBe(true);
    expect(res.body.caseId).not.toBe(1);
    expect(cases).toHaveLength(2);
  });
});

describe("GET /cases/:id/iris-export", () => {
  it("reports the computed default before any push has happened", async () => {
    const { client } = mockIrisPush();
    const app = await makeApp(client);
    const res = await request(app).get("/cases/c1/iris-export");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ caseName: "", defaultCaseName: "c1 — Ransomware FS01" });
  });

  it("reports the saved override after a push", async () => {
    const { client } = mockIrisPush();
    const app = await makeApp(client);
    await request(app).post("/cases/c1/push/iris").send({ caseName: "acme-breach-2026" });
    const res = await request(app).get("/cases/c1/iris-export");
    expect(res.status).toBe(200);
    expect(res.body.caseName).toBe("acme-breach-2026");
  });
});
