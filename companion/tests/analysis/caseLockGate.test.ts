import { describe, it, expect, beforeEach, vi } from "vitest";
import express, { type Express } from "express";
import request from "supertest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaseLockGate } from "../../src/analysis/caseLockGate.js";
import { hashCasePassword, signUnlockToken, unlockCookieName } from "../../src/analysis/casePassword.js";

let store: CaseStore;
let secret: Buffer;
let app: Express;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-lockgate-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  secret = randomBytes(32);
  app = express();
  app.use(express.json());
  app.use("/cases/:id", createCaseLockGate(store, secret));
  // Stand-ins for the real server.ts routes — the gate must treat them identically.
  app.get("/cases/:id/lock-status", (_req, res) => res.status(200).json({ ok: true }));
  app.post("/cases/:id/unlock", (_req, res) => res.status(200).json({ ok: true }));
  app.post("/cases/:id/lock", (_req, res) => res.status(200).json({ ok: true }));
  app.post("/cases/:id/import", (_req, res) => res.status(202).json({ ok: true }));
  app.get("/cases/:id/state", (_req, res) => res.status(200).json({ ok: true }));
  app.get("/cases/:id/present", (_req, res) => res.status(200).send("<html></html>"));
});

describe("createCaseLockGate", () => {
  it("passes every route through when the case has no password", async () => {
    expect((await request(app).get("/cases/c1/state")).status).toBe(200);
    expect((await request(app).get("/cases/c1/present")).status).toBe(200);
  });

  it("always exempts lock-status, unlock, lock, and import even when a password is set", async () => {
    await store.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    expect((await request(app).get("/cases/c1/lock-status")).status).toBe(200);
    expect((await request(app).post("/cases/c1/unlock")).status).toBe(200);
    expect((await request(app).post("/cases/c1/lock")).status).toBe(200);
    expect((await request(app).post("/cases/c1/import")).status).toBe(202);
  });

  it("blocks a gated route with a 401 JSON error when locked", async () => {
    await store.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    const res = await request(app).get("/cases/c1/state");
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("locked");
  });

  it("blocks /present with a 401 HTML lock prompt instead of a JSON error", async () => {
    await store.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    const res = await request(app).get("/cases/c1/present");
    expect(res.status).toBe(401);
    expect(res.type).toBe("text/html");
    expect(res.text).toContain("password-protected");
  });

  it("allows a gated route through with a valid unlock cookie", async () => {
    const meta = await store.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    const token = signUnlockToken("c1", meta.password!.salt, secret, 60_000, false);
    const res = await request(app).get("/cases/c1/state").set("Cookie", `${unlockCookieName("c1")}=${token}`);
    expect(res.status).toBe(200);
  });

  it("rejects a cookie signed under the previous (pre-change) password", async () => {
    const meta = await store.updateCaseMeta("c1", { password: hashCasePassword("secret123") });
    const staleToken = signUnlockToken("c1", meta.password!.salt, secret, 60_000, false);
    await store.updateCaseMeta("c1", { password: hashCasePassword("new-password") }); // new salt
    const res = await request(app).get("/cases/c1/state").set("Cookie", `${unlockCookieName("c1")}=${staleToken}`);
    expect(res.status).toBe(401);
  });

  it("does not block requests for a case that doesn't exist (downstream 404s handle it)", async () => {
    const res = await request(app).get("/cases/does-not-exist/state");
    expect(res.status).toBe(200); // the stand-in route doesn't check existence — proves the gate called next()
  });

  it("fails closed with a 401 when getCaseMeta throws unexpectedly", async () => {
    vi.spyOn(store, "getCaseMeta").mockRejectedValueOnce(new Error("simulated store failure"));
    const res = await request(app).get("/cases/c1/state");
    expect(res.status).toBe(401);
  });
});
