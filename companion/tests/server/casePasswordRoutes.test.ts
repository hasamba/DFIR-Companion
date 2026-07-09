import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-casepw-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  // /cases/:id/state 501s without a stateStore wired (see server.ts) — used here as a
  // representative gated route, so it needs to actually work when unlocked.
  app = createApp(store, { stateStore: new StateStore(store) });
});

describe("case password lifecycle", () => {
  it("an unprotected case reports hasPassword:false, unlocked:true, and every route is open", async () => {
    const status = await request(app).get("/cases/c1/lock-status");
    expect(status.status).toBe(200);
    expect(status.body).toEqual({ hasPassword: false, unlocked: true });
    expect((await request(app).get("/cases/c1/state")).status).toBe(200);
  });

  it("GET /cases never leaks the password hash, only hasPassword", async () => {
    const agent = request.agent(app);
    await agent.post("/cases/c1/password").send({ newPassword: "correct horse" });
    const list = await agent.get("/cases");
    const c1 = list.body.find((c: { caseId: string }) => c.caseId === "c1");
    expect(c1.hasPassword).toBe(true);
    expect(c1.password).toBeUndefined();
  });

  it("POST /cases and PATCH .../status also never leak the password hash", async () => {
    const created = await request(app).post("/cases").send({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    expect(created.body.password).toBeUndefined();
    expect(created.body.hasPassword).toBe(false);
    const patched = await request(app).patch("/cases/c2/status").send({ status: "closed" });
    expect(patched.body.password).toBeUndefined();
  });

  it("rejects a too-short password", async () => {
    const res = await request(app).post("/cases/c1/password").send({ newPassword: "ab" });
    expect(res.status).toBe(400);
  });

  it("setting a password immediately re-locks the case for a fresh (cookie-less) client", async () => {
    await request(app).post("/cases/c1/password").send({ newPassword: "correct horse" });
    const res = await request(app).get("/cases/c1/state");
    expect(res.status).toBe(401);
  });

  it("setting a password does not lock out the browser that just set it", async () => {
    const agent = request.agent(app);
    await agent.post("/cases/c1/password").send({ newPassword: "correct horse" });
    expect((await agent.get("/cases/c1/state")).status).toBe(200);
  });

  it("unlock with the wrong password is rejected; the correct password unlocks", async () => {
    await request(app).post("/cases/c1/password").send({ newPassword: "correct horse" });
    const agent = request.agent(app);
    const wrong = await agent.post("/cases/c1/unlock").send({ password: "nope" });
    expect(wrong.status).toBe(401);
    const right = await agent.post("/cases/c1/unlock").send({ password: "correct horse" });
    expect(right.status).toBe(200);
    expect((await agent.get("/cases/c1/state")).status).toBe(200);
  });

  it("without remember, the unlock cookie has no Max-Age (browser-session only)", async () => {
    await request(app).post("/cases/c1/password").send({ newPassword: "correct horse" });
    const res = await request(app).post("/cases/c1/unlock").send({ password: "correct horse", remember: false });
    expect(res.headers["set-cookie"][0]).not.toMatch(/Max-Age/i);
  });

  it("with remember, the unlock cookie carries a long Max-Age", async () => {
    await request(app).post("/cases/c1/password").send({ newPassword: "correct horse" });
    const res = await request(app).post("/cases/c1/unlock").send({ password: "correct horse", remember: true });
    expect(res.headers["set-cookie"][0]).toMatch(/Max-Age/i);
  });

  it("removing the password re-opens the case for everyone", async () => {
    const agent = request.agent(app);
    await agent.post("/cases/c1/password").send({ newPassword: "correct horse" });
    const del = await agent.delete("/cases/c1/password");
    expect(del.status).toBe(200);
    expect(del.body.hasPassword).toBe(false);
    expect((await request(app).get("/cases/c1/state")).status).toBe(200);
  });

  it("changing the password invalidates a previously-unlocked cookie", async () => {
    // Per the design spec, POST /cases/:id/password is itself gated once a password is set —
    // "being unlocked is sufficient proof of knowing the current password" — so a stranger with
    // no cookie cannot change it. The still-unlocked agent that set the first password is the
    // one that changes it; we prove its OLD (pre-rotation) cookie stops working afterward.
    const agent = request.agent(app);
    const first = await agent.post("/cases/c1/password").send({ newPassword: "first-password" });
    const staleCookie = first.headers["set-cookie"][0].split(";")[0];
    expect((await agent.get("/cases/c1/state")).status).toBe(200);
    await agent.post("/cases/c1/password").send({ newPassword: "second-password" });
    const staleRes = await request(app).get("/cases/c1/state").set("Cookie", staleCookie);
    expect(staleRes.status).toBe(401);
  });

  it("the capture-ingestion route stays reachable while locked", async () => {
    await request(app).post("/cases/c1/password").send({ newPassword: "correct horse" });
    // No AI pipeline configured in this test app, so the route itself 501s — the point is
    // that it's NOT the lock gate rejecting it with 401.
    const res = await request(app).post("/cases/c1/import").send({ text: "irrelevant", filename: "x.csv" });
    expect(res.status).not.toBe(401);
  });

  it("lock-status reflects both password-bearing states: locked for a stranger, unlocked for the setter", async () => {
    const agent = request.agent(app);
    await agent.post("/cases/c1/password").send({ newPassword: "correct horse" });
    const own = await agent.get("/cases/c1/lock-status");
    expect(own.body).toEqual({ hasPassword: true, unlocked: true });
    const stranger = await request(app).get("/cases/c1/lock-status");
    expect(stranger.body).toEqual({ hasPassword: true, unlocked: false });
  });

  it("404s for an unknown case on lock-status / unlock / password", async () => {
    expect((await request(app).get("/cases/nope/lock-status")).status).toBe(404);
    expect((await request(app).post("/cases/nope/unlock").send({ password: "x" })).status).toBe(404);
    expect((await request(app).post("/cases/nope/password").send({ newPassword: "correct horse" })).status).toBe(404);
  });
});
