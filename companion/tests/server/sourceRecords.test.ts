import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";

// #2301: GET /cases/:id/source-records/:group pages an aggregated cloud event's source records.

const GROUP = "m1:0123456789abcdef01234567";

async function makeApp(withStore = true) {
  const root = await mkdtemp(join(tmpdir(), "dfir-srcrec-"));
  const store = new CaseStore(root);
  const cloudRecordStore = new CloudRecordStore(store);
  const app = createApp(store, {
    stateStore: new StateStore(store),
    aiConfigured: false,
    ...(withStore ? { cloudRecordStore } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, cloudRecordStore };
}

describe("source-records route (#2301)", () => {
  it("answers 501 when the store is not configured", async () => {
    const { app } = await makeApp(false);
    expect((await request(app).get(`/cases/c1/source-records/${GROUP}`)).status).toBe(501);
  });

  it("rejects a malformed group key", async () => {
    const { app } = await makeApp();
    expect((await request(app).get("/cases/c1/source-records/not-a-group")).status).toBe(400);
  });

  it("pages the members with a cursor", async () => {
    const { app, cloudRecordStore } = await makeApp();
    await cloudRecordStore.recordMembers(
      "c1",
      ["r1", "r2", "r3"].map((ref) => ({ group: GROUP, ref })),
    );
    const first = await request(app).get(`/cases/c1/source-records/${GROUP}?limit=2`);
    expect(first.status).toBe(200);
    expect(first.body.total).toBe(3);
    expect(first.body.members.map((m: { ref: string }) => m.ref)).toEqual(["r1", "r2"]);
    const second = await request(app).get(
      `/cases/c1/source-records/${GROUP}?limit=2&after=${first.body.next}`,
    );
    expect(second.body.members.map((m: { ref: string }) => m.ref)).toEqual(["r3"]);
    expect(second.body.next).toBeNull();
  });
});
