// AI Agent Forensics (#2690): the HTTP surface. Sweep cases stay out of the analyst's case list.
import { beforeEach, describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

let store: CaseStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-aiagent-routes-")));
  app = createApp(store);
});

describe("sweep cases and GET /cases", () => {
  it("hides a sweep case from the case list the pickers read", async () => {
    await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "Incident A", investigator: "y", aiProvider: null });
    await store.createCase({
      caseId: "aiagent-sweep-1",
      name: "sweep",
      investigator: "x",
      aiProvider: null,
      kind: "sweep",
    });
    const res = await request(app).get("/cases");
    expect(res.status).toBe(200);
    expect(res.body.map((c: { caseId: string }) => c.caseId)).toEqual(["c1"]);
  });
});
