import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HostScopeStore } from "../../src/analysis/hostScopeStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostscope-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, {
    stateStore: new StateStore(cases),
    superTimelineStore: new SuperTimelineStore(cases),
    hostScopeStore: new HostScopeStore(cases),
  });
});

describe("/cases/:id/host-scope", () => {
  it("returns an empty ledger for a fresh case", async () => {
    const res = await request(app).get("/cases/c1/host-scope");
    expect(res.status).toBe(200);
    expect(res.body.hosts).toEqual([]);
    expect(res.body.counts.cleared).toBe(0);
    expect(res.body.fleet).toBeNull();
  });

  it("rejects a clearance with no reason", async () => {
    const res = await request(app).post("/cases/c1/host-scope/ws-042").send({ to: "cleared", reason: "" });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown status", async () => {
    const res = await request(app)
      .post("/cases/c1/host-scope/ws-042")
      .send({ to: "definitely-fine", reason: "x" });
    expect(res.status).toBe(400);
  });

  it("records a decision and reflects it in the ledger without marking it stale", async () => {
    const res = await request(app)
      .post("/cases/c1/host-scope/ws-042")
      .send({ to: "out-of-scope", reason: "decommissioned before the incident" });
    expect(res.status).toBe(200);
    const row = res.body.hosts.find((h: { name: string }) => h.name === "ws-042");
    expect(row.effectiveStatus).toBe("out-of-scope");
    expect(row.stale).toBeUndefined();
    expect(row.decision.reason).toBe("decommissioned before the incident");
  });

  it("persists the decision across requests", async () => {
    await request(app)
      .post("/cases/c1/host-scope/ws-042")
      .send({ to: "out-of-scope", reason: "decommissioned" });
    const res = await request(app).get("/cases/c1/host-scope");
    const row = res.body.hosts.find((h: { name: string }) => h.name === "ws-042");
    expect(row.effectiveStatus).toBe("out-of-scope");
  });
});
