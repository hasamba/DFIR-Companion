import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { FindingWorkflowStore } from "../../src/analysis/findingWorkflow.js";

async function appWith() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fwf-route-")));
  const findingWorkflowStore = new FindingWorkflowStore(store);
  const pinged: string[] = [];
  const app = createApp(store, { findingWorkflowStore, onFindingWorkflow: (id) => pinged.push(id) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, pinged };
}

describe("finding-workflow routes", () => {
  it("GET returns an empty list initially", async () => {
    const { app } = await appWith();
    const res = await request(app).get("/cases/c1/finding-workflow");
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it("PATCH assigns a finding + sets a status, pings clients, and GET reflects it", async () => {
    const { app, pinged } = await appWith();
    const res = await request(app)
      .patch("/cases/c1/findings/f-1/workflow")
      .send({ assignee: "Alice", status: "in_progress", updatedBy: "Bob" });
    expect(res.status).toBe(200);
    expect(res.body.record).toMatchObject({ findingId: "f-1", assignee: "Alice", status: "in_progress", updatedBy: "Bob" });
    expect(pinged).toEqual(["c1"]);

    const list = await request(app).get("/cases/c1/finding-workflow");
    expect(list.body).toHaveLength(1);
    expect(list.body[0]).toMatchObject({ findingId: "f-1", assignee: "Alice", status: "in_progress" });
  });

  it("PATCH merges partial updates (status-only keeps the assignee)", async () => {
    const { app } = await appWith();
    await request(app).patch("/cases/c1/findings/f-1/workflow").send({ assignee: "Alice" });
    const res = await request(app).patch("/cases/c1/findings/f-1/workflow").send({ status: "resolved" });
    expect(res.body.record).toMatchObject({ assignee: "Alice", status: "resolved" });
  });

  it("PATCH with empty assignee + empty status clears the record (record: null)", async () => {
    const { app } = await appWith();
    await request(app).patch("/cases/c1/findings/f-1/workflow").send({ assignee: "Alice", status: "new" });
    const res = await request(app).patch("/cases/c1/findings/f-1/workflow").send({ assignee: "", status: "" });
    expect(res.status).toBe(200);
    expect(res.body.record).toBeNull();
    const list = await request(app).get("/cases/c1/finding-workflow");
    expect(list.body).toEqual([]);
  });

  it("rejects an invalid status (400) and an empty patch (400)", async () => {
    const { app } = await appWith();
    const bad = await request(app).patch("/cases/c1/findings/f-1/workflow").send({ status: "bogus" });
    expect(bad.status).toBe(400);
    const empty = await request(app).patch("/cases/c1/findings/f-1/workflow").send({});
    expect(empty.status).toBe(400);
  });

  it("501s when the store is not configured", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fwf-noconf-")));
    const app = createApp(store, {});
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).get("/cases/c1/finding-workflow");
    expect(res.status).toBe(501);
  });
});
