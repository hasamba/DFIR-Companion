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

  it("stores the finding's semanticKey when the finding is in the case state", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fout-key-")));
    const { StateStore } = await import("../../src/analysis/stateStore.js");
    const { emptyState } = await import("../../src/analysis/stateTypes.js");
    const stateStore = new StateStore(store);
    const findingOutcomeStore = new FindingOutcomeStore(store);
    const app = createApp(store, { findingOutcomeStore, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const state = emptyState("c1");
    state.findings.push({
      id: "f-1",
      severity: "High",
      title: "t",
      description: "d",
      relatedIocs: [],
      sourceScreenshots: [],
      mitreTechniques: [],
      firstSeen: "2026-01-01T00:00:00Z",
      lastUpdated: "2026-01-01T00:00:00Z",
      status: "open",
      semanticKey: "T1059:powershell dropper",
    });
    await stateStore.save(state);
    const res = await request(app).patch("/cases/c1/findings/f-1/outcome").send({ control: "blocked" });
    expect(res.status).toBe(200);
    expect(res.body.record.semanticKey).toBe("T1059:powershell dropper");
  });

  // A save that fails is the server's fault, not the caller's — the dashboard reverts and says so
  // on a non-2xx, and must not read a storage failure as "you sent something wrong".
  it("returns 500, not 400, when the store itself fails", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fout-500-")));
    const findingOutcomeStore = new FindingOutcomeStore(store);
    findingOutcomeStore.patch = async () => {
      throw new Error("ENOSPC: no space left on device");
    };
    const app = createApp(store, { findingOutcomeStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).patch("/cases/c1/findings/f-1/outcome").send({ control: "blocked" });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/ENOSPC/);
  });

  it("404s a PATCH for a finding that is not in the case, rather than storing an unguarded record", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fout-404-")));
    const { StateStore } = await import("../../src/analysis/stateStore.js");
    const { emptyState } = await import("../../src/analysis/stateTypes.js");
    const stateStore = new StateStore(store);
    const findingOutcomeStore = new FindingOutcomeStore(store);
    const app = createApp(store, { findingOutcomeStore, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    const res = await request(app).patch("/cases/c1/findings/ghost/outcome").send({ control: "blocked" });
    expect(res.status).toBe(404);
    expect(await findingOutcomeStore.load("c1")).toEqual([]);
  });

  it("500s when the case state cannot be read, and stores nothing", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fout-state500-")));
    const { StateStore } = await import("../../src/analysis/stateStore.js");
    const stateStore = new StateStore(store);
    stateStore.load = async () => {
      throw new Error("EIO: state unreadable");
    };
    const findingOutcomeStore = new FindingOutcomeStore(store);
    const app = createApp(store, { findingOutcomeStore, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).patch("/cases/c1/findings/f-1/outcome").send({ control: "blocked" });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/EIO/);
    expect(await findingOutcomeStore.load("c1")).toEqual([]);
  });
});
