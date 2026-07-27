import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Response } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { PresidioApprovalRequired } from "../../src/analysis/presidio.js";
import { sendPipelineError } from "../../src/routes/presidioApproval.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { LoggerImpl, createConsoleLogger } from "../../src/logging/logger.js";
import { createApp, setServerLogger } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let pendingStore: PresidioPendingStore;
let discoveredStore: DiscoveredEntitiesStore;
let customStore: CustomEntitiesStore;
// Captures every line the route handlers pass to ctx.serverLogger (logLine), so tests can assert
// on what actually lands in the server/case log — never the PII value itself. createApp captures
// the CURRENT server logger by reference when it builds ctx, so the fake must be installed BEFORE
// createApp() runs.
let loggedLines: string[];

beforeEach(async () => {
  loggedLines = [];
  setServerLogger(new LoggerImpl({
    level: "info",
    sessionLogPath: null,
    consoleFns: {
      log: (s) => loggedLines.push(s),
      warn: (s) => loggedLines.push(s),
      error: (s) => loggedLines.push(s),
    },
  }));
  const root = await mkdtemp(join(tmpdir(), "dfir-presidioroute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { stateStore: new StateStore(cases), activityLogStore: new ActivityLogStore(cases) });
  pendingStore = new PresidioPendingStore(cases);
  discoveredStore = new DiscoveredEntitiesStore(cases);
  customStore = new CustomEntitiesStore(cases);
  await pendingStore.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
});

afterEach(() => {
  // Restore a quiet real logger so no later test file's console noise is silently swallowed by a
  // leftover capture array from this one (setServerLogger mutates a module-level singleton).
  setServerLogger(createConsoleLogger("error"));
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

  it("POST .../approve moves a value into the CUSTOM list and clears it from pending", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/approve")
      .send({ value: "Jane Doe", category: "PERSON" });
    expect(res.status).toBe(200);
    // Custom, not discovered: the dashboard renders `discovered` as a read-only AUTO-DETECTED
    // section, and approving is the opposite of automatic — an analyst was shown the value and
    // decided. It lands where they can edit or remove it afterwards.
    expect(await customStore.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
    expect((await discoveredStore.load("c1")).discovered).toEqual([]);
    expect(await pendingStore.load("c1")).toEqual([]);
    // Approve must NOT touch the suppressed list — it's a distinct outcome from veto.
    expect((await discoveredStore.load("c1")).suppressed).toEqual([]);
  });

  it("POST .../approve twice does not duplicate the entity", async () => {
    const body = { value: "Jane Doe", category: "PERSON" };
    await request(app).post("/cases/c1/presidio-pending/approve").send(body);
    await request(app).post("/cases/c1/presidio-pending/approve").send(body);
    expect(await customStore.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("POST .../approve keeps entities the analyst added by hand", async () => {
    await customStore.save("c1", [{ value: "PROJECT-ORION", category: "OTHER" }]);
    await request(app)
      .post("/cases/c1/presidio-pending/approve")
      .send({ value: "Jane Doe", category: "PERSON" });
    expect(await customStore.load("c1")).toEqual([
      { value: "PROJECT-ORION", category: "OTHER" },
      { value: "Jane Doe", category: "PERSON" },
    ]);
  });

  it("POST .../suppress vetoes a value and clears it from pending", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/suppress")
      .send({ value: "Jane Doe" });
    expect(res.status).toBe(200);
    expect((await discoveredStore.load("c1")).suppressed).toContain("jane doe");
    expect(await pendingStore.load("c1")).toEqual([]);
    // Suppress must NOT add the value anywhere that tokenizes it — a distinct outcome from approve.
    expect((await discoveredStore.load("c1")).discovered).toEqual([]);
    expect(await customStore.load("c1")).toEqual([]);
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

  // An approved value is CONFIRMED PII by definition (approving it is the act of saying "mask this
  // from now on") — and these logs are per-case, living in the case directory as part of the audit
  // trail. Writing the confirmed name into them would defeat the point of the masking feature. A
  // suppressed value gets the same treatment for the opposite reason: it might still be real PII
  // even though the analyst judged it a false positive.
  it("does not write the approved value's text to the server log", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/approve")
      .send({ value: "Jane Doe", category: "PERSON" });
    expect(res.status).toBe(200);
    expect(loggedLines.some((l) => l.includes("Jane Doe"))).toBe(false);
    // The category IS safe to log — confirm the line still says something useful.
    expect(loggedLines.some((l) => /approved a PERSON finding/.test(l))).toBe(true);
  });

  it("does not write the approved value's text to the case's activity log", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/approve")
      .send({ value: "Jane Doe", category: "PERSON" });
    expect(res.status).toBe(200);
    const log = await request(app).get("/cases/c1/activity-log");
    const entries = log.body.filter((e: { action: string }) => e.action === "presidio-approve");
    expect(entries).toHaveLength(1);
    expect(entries[0].detail).not.toContain("Jane Doe");
    expect(entries[0].detail).toContain("PERSON");
  });

  it("does not write the suppressed value's text to the server log", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/suppress")
      .send({ value: "Jane Doe" });
    expect(res.status).toBe(200);
    expect(loggedLines.some((l) => l.includes("Jane Doe"))).toBe(false);
    expect(loggedLines.some((l) => /suppressed a finding/.test(l))).toBe(true);
  });

  it("does not write the suppressed value's text to the case's activity log", async () => {
    const res = await request(app)
      .post("/cases/c1/presidio-pending/suppress")
      .send({ value: "Jane Doe" });
    expect(res.status).toBe(200);
    const log = await request(app).get("/cases/c1/activity-log");
    const entries = log.body.filter((e: { action: string }) => e.action === "presidio-suppress");
    expect(entries).toHaveLength(1);
    expect(entries[0].detail).not.toContain("Jane Doe");
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
