import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TemplateStore } from "../../src/analysis/templateStore.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2772: the case folder is claimed first, then the template / incident type / server set / drop
// folder are applied. A failure after the claim used to answer 500 while the case existed, and the
// retry then hit "already exists". The case is real, so the answer is 201 with a seedError.

class FailingSaveStateStore extends StateStore {
  override async save(): Promise<void> {
    throw new Error("disk full");
  }
}

async function makeApp(opts: { failState?: boolean; failIncidentRecord?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-seedfail-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = opts.failState ? new FailingSaveStateStore(store) : new StateStore(store);
  const incidentTypeStore = new IncidentTypeStore(store, join(root, "incident-types"));
  if (opts.failIncidentRecord) {
    incidentTypeStore.saveRecord = async () => {
      throw new Error("record write failed");
    };
  }
  const app = createApp(store, {
    stateStore,
    aiConfigured: false,
    templateStore: new TemplateStore(join(root, "templates")),
    incidentTypeStore,
  });
  return { app, store };
}

const body = (extra: Record<string, unknown>) => ({
  caseId: "c1",
  name: "n",
  investigator: "i",
  aiProvider: null,
  ...extra,
});

describe("POST /cases when a seeding step fails after the case exists (#2772)", () => {
  it("answers 201 with a seedError naming the template", async () => {
    const { app, store } = await makeApp({ failState: true });
    const res = await request(app)
      .post("/cases")
      .send(body({ templateId: "web-intrusion" }));
    expect(res.status).toBe(201);
    expect(res.body.caseId).toBe("c1");
    expect(res.body.seedError).toMatch(/template/);
    expect(res.body.seedError).toMatch(/disk full/);
    expect(await store.caseExists("c1")).toBe(true);
    const listed = await request(app).get("/cases");
    expect(listed.body.map((c: { caseId: string }) => c.caseId)).toContain("c1");
  });

  it("answers 201 with a seedError naming the incident type", async () => {
    const { app } = await makeApp({ failIncidentRecord: true });
    const res = await request(app)
      .post("/cases")
      .send(body({ incidentTypeId: "ransomware" }));
    expect(res.status).toBe(201);
    expect(res.body.seedError).toMatch(/incident type/);
    expect(res.body.seedError).toMatch(/record write failed/);
  });

  it("names both when the template and the incident type fail", async () => {
    const { app } = await makeApp({ failState: true });
    const res = await request(app)
      .post("/cases")
      .send(body({ templateId: "web-intrusion", incidentTypeId: "ransomware" }));
    expect(res.status).toBe(201);
    expect(res.body.seedError).toMatch(/template/);
    expect(res.body.seedError).toMatch(/incident type/);
  });

  it("still answers 409 to a true duplicate after a seed failure", async () => {
    const { app } = await makeApp({ failState: true });
    await request(app)
      .post("/cases")
      .send(body({ templateId: "web-intrusion" }));
    const again = await request(app)
      .post("/cases")
      .send(body({ templateId: "web-intrusion" }));
    expect(again.status).toBe(409);
  });

  it("has no seedError when every step succeeds", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases")
      .send(body({ templateId: "web-intrusion", incidentTypeId: "ransomware" }));
    expect(res.status).toBe(201);
    expect(res.body.seedError).toBeUndefined();
  });
});
