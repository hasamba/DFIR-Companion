import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2594 part one: the New case dialog picks the main evidence source before any evidence arrives.

let store: CaseStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-mscreate-")));
  app = createApp(store, { stateStore: new StateStore(store) });
});

const create = (extra: Record<string, unknown>) =>
  request(app)
    .post("/cases")
    .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null, ...extra });

describe("POST /cases mainSource (#2594)", () => {
  it("stores a picked source as the override from the first second", async () => {
    expect((await create({ mainSource: "splunk" })).status).toBe(201);
    const ms = await request(app).get("/cases/c1/main-source");
    expect(ms.body.override).toBe("splunk");
    expect(ms.body.effective).toBe("splunk");
    expect(ms.body.language.language).toBe("spl");
  });

  it("accepts Mixed", async () => {
    expect((await create({ mainSource: "mixed" })).status).toBe(201);
    expect((await request(app).get("/cases/c1/main-source")).body.override).toBe("mixed");
  });

  it("leaves Automatic when absent, blank or null", async () => {
    for (const [i, extra] of [{}, { mainSource: "" }, { mainSource: null }].entries()) {
      const id = `a${i}`;
      const r = await request(app)
        .post("/cases")
        .send({ caseId: id, name: "n", investigator: "i", aiProvider: null, ...extra });
      expect(r.status).toBe(201);
      expect((await request(app).get(`/cases/${id}/main-source`)).body.override).toBeNull();
    }
  });

  it("refuses an unknown source before the case is created", async () => {
    for (const bad of ["vql", 7]) {
      const r = await create({ mainSource: bad });
      expect(r.status).toBe(400);
      expect(r.body.error).toMatch(/mainSource/);
      expect(await store.caseExists("c1")).toBe(false);
    }
  });
});
