import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { FindingOutcomeStore } from "../../src/analysis/findingOutcome.js";

async function appWith() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fout-route-")));
  const findingOutcomeStore = new FindingOutcomeStore(store);
  const pinged: string[] = [];
  const app = createApp(store, { findingOutcomeStore, onFindingOutcome: (id) => pinged.push(id) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, pinged };
}

describe("finding-outcome routes", () => {
  it("GET returns an empty list initially", async () => {
    const { app } = await appWith();
    const res = await request(app).get("/cases/c1/finding-outcome");
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it("PATCH records both axes, pings clients, and GET reflects it", async () => {
    const { app, pinged } = await appWith();
    const res = await request(app).patch("/cases/c1/findings/f-1/outcome").send({
      execution: "observed",
      control: "remediated",
      note: "ran, then quarantined",
      updatedBy: "Alice",
    });
    expect(res.status).toBe(200);
    expect(res.body.record).toMatchObject({
      findingId: "f-1",
      execution: "observed",
      control: "remediated",
      note: "ran, then quarantined",
      updatedBy: "Alice",
    });
    expect(pinged).toEqual(["c1"]);
    const list = await request(app).get("/cases/c1/finding-outcome");
    expect(list.body).toHaveLength(1);
  });

  it("PATCH merges partial updates (control-only keeps execution)", async () => {
    const { app } = await appWith();
    await request(app).patch("/cases/c1/findings/f-1/outcome").send({ execution: "not-observed" });
    const res = await request(app).patch("/cases/c1/findings/f-1/outcome").send({ control: "blocked" });
    expect(res.body.record.execution).toBe("not-observed");
    expect(res.body.record.control).toBe("blocked");
  });

  it("PATCH with null axes and an empty note clears the record (record: null)", async () => {
    const { app } = await appWith();
    await request(app).patch("/cases/c1/findings/f-1/outcome").send({ execution: "observed" });
    const res = await request(app)
      .patch("/cases/c1/findings/f-1/outcome")
      .send({ execution: null, control: null, note: "" });
    expect(res.status).toBe(200);
    expect(res.body.record).toBeNull();
    expect((await request(app).get("/cases/c1/finding-outcome")).body).toEqual([]);
  });

  // "prevented" is exactly the single-word verdict the two-axis design refuses to have.
  it("rejects a value outside the vocabulary (400) and an empty patch (400)", async () => {
    const { app } = await appWith();
    const bad = await request(app).patch("/cases/c1/findings/f-1/outcome").send({ execution: "prevented" });
    expect(bad.status).toBe(400);
    expect(bad.body.error).toMatch(/execution must be one of/);
    const badControl = await request(app)
      .patch("/cases/c1/findings/f-1/outcome")
      .send({ control: "stopped" });
    expect(badControl.status).toBe(400);
    const empty = await request(app).patch("/cases/c1/findings/f-1/outcome").send({});
    expect(empty.status).toBe(400);
  });

  it("501s when the store is not configured", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fout-none-")));
    const app = createApp(store, {});
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    expect((await request(app).get("/cases/c1/finding-outcome")).status).toBe(501);
    expect(
      (await request(app).patch("/cases/c1/findings/f-1/outcome").send({ control: "blocked" })).status,
    ).toBe(501);
  });
});
