import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Response } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { PresidioApprovalRequired } from "../../src/analysis/presidio.js";
import { sendPipelineError } from "../../src/routes/presidioApproval.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let pendingStore: PresidioPendingStore;
let discoveredStore: DiscoveredEntitiesStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidioroute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { stateStore: new StateStore(cases) });
  pendingStore = new PresidioPendingStore(cases);
  discoveredStore = new DiscoveredEntitiesStore(cases);
  await pendingStore.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
});

describe("presidio approval routes", () => {
  it("GET /cases/:id/presidio-pending returns the pending list", async () => {
    const res = await request(app).get("/cases/c1/presidio-pending");
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("GET /cases/:id/presidio-pending rejects an invalid case id", async () => {
    const res = await request(app).get("/cases/bad%20id/presidio-pending");
    expect(res.status).toBe(400);
  });

  it("POST .../approve moves a value into the discovered list and clears it from pending", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/approve")
      .send({ value: "Jane Doe", category: "PERSON" });
    expect(res.status).toBe(200);
    expect((await discoveredStore.load("c1")).discovered).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
    expect(await pendingStore.load("c1")).toEqual([]);
    // Approve must NOT touch the suppressed list — it's a distinct outcome from veto.
    expect((await discoveredStore.load("c1")).suppressed).toEqual([]);
  });

  it("POST .../suppress vetoes a value and clears it from pending", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/suppress")
      .send({ value: "Jane Doe" });
    expect(res.status).toBe(200);
    expect((await discoveredStore.load("c1")).suppressed).toContain("jane doe");
    expect(await pendingStore.load("c1")).toEqual([]);
    // Suppress must NOT add the value to the discovered (tokenize) list — it's a distinct outcome from approve.
    expect((await discoveredStore.load("c1")).discovered).toEqual([]);
  });

  it("rejects a blank value on suppress", async () => {
    const res = await request(app).post("/cases/c1/presidio-pending/suppress").send({ value: "  " });
    expect(res.status).toBe(400);
    // The pending entry must survive a rejected request.
    expect(await pendingStore.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("rejects a blank value on approve", async () => {
    const res = await request(app).post("/cases/c1/presidio-pending/approve").send({ value: "  " });
    expect(res.status).toBe(400);
    expect(await pendingStore.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("POST .../approve rejects an invalid case id", async () => {
    const res = await request(app).post("/cases/bad%20id/presidio-pending/approve").send({ value: "Jane Doe" });
    expect(res.status).toBe(400);
  });

  it("POST .../suppress rejects an invalid case id", async () => {
    const res = await request(app).post("/cases/bad%20id/presidio-pending/suppress").send({ value: "Jane Doe" });
    expect(res.status).toBe(400);
  });
});

// Minimal Response stub — sendPipelineError only ever touches status() and json().
function fakeRes(): Response & { statusCode: number; body: unknown } {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) { res.statusCode = code; return res; },
    json(payload: unknown) { res.body = payload; return res; },
  };
  return res as unknown as Response & { statusCode: number; body: unknown };
}

describe("sendPipelineError", () => {
  it("returns 409 with the findings for PresidioApprovalRequired", () => {
    const res = fakeRes();
    sendPipelineError(res, new PresidioApprovalRequired([{ value: "Jane Doe", category: "PERSON" }]));
    expect(res.statusCode).toBe(409);
    expect(res.body).toEqual({
      error: "presidio_approval_required",
      findings: [{ value: "Jane Doe", category: "PERSON" }],
    });
  });

  it("returns 500 for any other error", () => {
    const res = fakeRes();
    sendPipelineError(res, new Error("boom"));
    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: "boom" });
  });

  it("returns 500 for a non-Error thrown value", () => {
    const res = fakeRes();
    sendPipelineError(res, "boom-string");
    expect(res.statusCode).toBe(500);
  });
});
