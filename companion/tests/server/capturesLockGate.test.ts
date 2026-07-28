import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// POST /captures is a top-level route (not under /cases/:id), so createCaseLockGate never covers
// it (see tests/analysis/caseLockGate.test.ts) — the route carries its own password check instead
// (#242). These tests exercise the REAL route via createApp()/registerCaptureRoutes, not a
// stand-in, so a regression in the actual check would fail here.

let app: ReturnType<typeof createApp>;
let cases: CaseStore;

const CAPTURE_BODY = {
  caseId: "c1",
  timestamp: "2026-07-24T00:00:00.000Z",
  url: "http://victim/",
  tabTitle: "t",
  triggerType: "timer" as const,
  // Carries a real PNG signature: ingest magic-byte-checks the bytes, and this suite is about the
  // password gate, so the payload must clear that check to reach it.
  imageBase64: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]).toString("base64"),
};

beforeEach(async () => {
  _resetDedupCache();
  resetLimiters();
  const root = await mkdtemp(join(tmpdir(), "dfir-captureslock-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, {});
});

describe("POST /captures — case-password gate", () => {
  it("accepts a capture for a case with no password set (no regression)", async () => {
    const res = await request(app).post("/captures").send(CAPTURE_BODY);
    expect(res.status).toBe(201);
  });

  it("401s with no unlock cookie and no casePassword", async () => {
    await cases.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    const res = await request(app).post("/captures").send(CAPTURE_BODY);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("locked");
  });

  it("401s with a wrong casePassword in the body", async () => {
    await cases.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    const res = await request(app).post("/captures").send({ ...CAPTURE_BODY, casePassword: "wrong" });
    expect(res.status).toBe(401);
  });

  it("accepts the right casePassword in the body (browser-extension flow)", async () => {
    await cases.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    const res = await request(app).post("/captures").send({ ...CAPTURE_BODY, casePassword: "secret123" });
    expect(res.status).toBe(201);
  });

  it("accepts a valid unlock cookie (dashboard flow)", async () => {
    await cases.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    // Get a REAL signed cookie the same way the dashboard does, rather than forging a token —
    // this also incidentally proves /cases/:id/unlock and POST /captures agree on the secret.
    const login = await request(app).post("/cases/c1/unlock").send({ password: "secret123" });
    expect(login.status).toBe(200);
    const cookie = login.headers["set-cookie"]?.[0];
    expect(cookie).toBeTruthy();
    const res = await request(app).post("/captures").set("Cookie", cookie!).send(CAPTURE_BODY);
    expect(res.status).toBe(201);
  });

  it("400s an invalid caseId before ever touching the store", async () => {
    const res = await request(app).post("/captures").send({ ...CAPTURE_BODY, caseId: "../../etc/passwd" });
    expect(res.status).toBe(400);
  });

  it("rate-limits brute-force: 5 wrong passwords via /captures then 429 lockout", async () => {
    await cases.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    // Hammer /captures with wrong passwords (the previously-unthrottled second entry point).
    let statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await request(app).post("/captures").send({ ...CAPTURE_BODY, casePassword: `wrong${i}` });
      statuses.push(res.status);
    }
    // First 5 are 401 (failures), 6th triggers the lockout → 429.
    expect(statuses.filter((s) => s === 401).length).toBeLessThanOrEqual(5);
    expect(statuses).toContain(429);
    // After lockout, even the CORRECT password is rejected with 429 (lockout takes precedence).
    const locked = await request(app).post("/captures").send({ ...CAPTURE_BODY, casePassword: "secret123" });
    expect(locked.status).toBe(429);
  });

  it("shares the limiter with /unlock so /captures failures count toward /unlock lockout", async () => {
    await cases.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    // Burn attempts on /captures, then /unlock should already be locked out (shared counter).
    for (let i = 0; i < 6; i++) {
      await request(app).post("/captures").send({ ...CAPTURE_BODY, casePassword: `wrong${i}` });
    }
    const unlock = await request(app).post("/cases/c1/unlock").send({ password: "secret123" });
    expect(unlock.status).toBe(429);
  });
});
