import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { PinnedFindingsStore } from "../../src/analysis/pinnedFindings.js";

async function freshStore(): Promise<CaseStore> {
  return new CaseStore(await mkdtemp(join(tmpdir(), "dfir-pins-route-")));
}

async function appWith(max?: number) {
  const store = await freshStore();
  const pinnedFindingsStore = new PinnedFindingsStore(store, max);
  const pinged: string[] = [];
  const app = createApp(store, { pinnedFindingsStore, onPins: (id) => pinged.push(id) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, pinged };
}

describe("pinned-findings routes", () => {
  it("GET returns an empty list + the cap", async () => {
    const { app } = await appWith();
    const res = await request(app).get("/cases/c1/pinned-findings");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ pins: [], limit: 5 });
  });

  it("POST pins a finding, pings clients, and rejects a blank findingId", async () => {
    const { app, pinged } = await appWith();
    const res = await request(app).post("/cases/c1/pinned-findings").send({ findingId: "f-1", pinnedBy: "Alice" });
    expect(res.status).toBe(201);
    expect(res.body.pins).toHaveLength(1);
    expect(res.body.pins[0]).toMatchObject({ findingId: "f-1", pinnedBy: "Alice" });
    expect(pinged).toEqual(["c1"]);

    const bad = await request(app).post("/cases/c1/pinned-findings").send({ pinnedBy: "Alice" });
    expect(bad.status).toBe(400);
  });

  it("POST returns 409 with the limit when the cap is reached", async () => {
    const { app } = await appWith(2);
    await request(app).post("/cases/c1/pinned-findings").send({ findingId: "f-1" });
    await request(app).post("/cases/c1/pinned-findings").send({ findingId: "f-2" });
    const over = await request(app).post("/cases/c1/pinned-findings").send({ findingId: "f-3" });
    expect(over.status).toBe(409);
    expect(over.body.limit).toBe(2);
  });

  it("PUT /order reorders the pins", async () => {
    const { app } = await appWith();
    for (const id of ["f-1", "f-2", "f-3"]) {
      await request(app).post("/cases/c1/pinned-findings").send({ findingId: id });
    }
    const res = await request(app).put("/cases/c1/pinned-findings/order").send({ order: ["f-3", "f-1", "f-2"] });
    expect(res.status).toBe(200);
    expect(res.body.pins.map((p: { findingId: string }) => p.findingId)).toEqual(["f-3", "f-1", "f-2"]);

    const bad = await request(app).put("/cases/c1/pinned-findings/order").send({ order: "nope" });
    expect(bad.status).toBe(400);
  });

  it("DELETE /:findingId unpins", async () => {
    const { app } = await appWith();
    await request(app).post("/cases/c1/pinned-findings").send({ findingId: "f-1" });
    await request(app).post("/cases/c1/pinned-findings").send({ findingId: "f-2" });
    const res = await request(app).delete("/cases/c1/pinned-findings/f-1");
    expect(res.status).toBe(200);
    expect(res.body.pins.map((p: { findingId: string }) => p.findingId)).toEqual(["f-2"]);
  });

  it("returns 501 when the store is not configured", async () => {
    const store = await freshStore();
    const app = createApp(store, {});
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    expect((await request(app).get("/cases/c1/pinned-findings")).status).toBe(501);
  });
});
