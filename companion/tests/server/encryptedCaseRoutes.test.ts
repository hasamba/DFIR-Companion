import { describe, it, expect, beforeEach } from "vitest";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { encryptBuffer } from "../../src/analysis/caseEncryption.js";

const PASSWORD = "correct horse battery staple";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-encroute-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const commentsStore = new CommentsStore(store);
  const app = createApp(store, { stateStore, commentsStore });
  return { app, store, stateStore };
}

async function seedCase(app: ReturnType<typeof createApp>, stateStore: StateStore, store: CaseStore) {
  await request(app).post("/cases").send({ caseId: "INC-1", name: "Case One", investigator: "alice", aiProvider: "anthropic" });
  await stateStore.save({
    ...emptyState("INC-1"),
    findings: [{ id: "f1", severity: "High", title: "t", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open" }],
    iocs: [{ id: "i1", type: "ip", value: "8.8.8.8", firstSeen: "2026-01-01T00:00:00Z" }],
    forensicTimeline: [{ id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "evt", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] }],
  });
  await request(app).post("/cases/INC-1/comments").send({ targetType: "ioc", targetId: "i1", text: "looks malicious" });
  await store.saveScreenshot("INC-1", "shot.webp", Buffer.from([1, 2, 3, 4]));
}

function bufferRequest(req: request.Test): request.Test {
  return req.buffer().parse((r, cb) => {
    const chunks: Buffer[] = [];
    r.on("data", (c: Buffer) => chunks.push(c));
    r.on("end", () => cb(null, Buffer.concat(chunks)));
  });
}

async function exportArchive(app: ReturnType<typeof createApp>, caseId: string) {
  const res = await bufferRequest(
    request(app).post(`/cases/${caseId}/export/encrypted`).send({ password: PASSWORD }),
  );
  return (res.body as Buffer).toString("base64");
}

describe("POST /cases/:id/export/encrypted", () => {
  it("returns a .dfircase attachment", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const res = await bufferRequest(
      request(app).post("/cases/INC-1/export/encrypted").send({ password: PASSWORD }),
    );
    expect(res.status).toBe(200);
    expect(res.headers["content-disposition"]).toContain('attachment; filename="INC-1 - Case One.dfircase"');
    expect((res.body as Buffer).length).toBeGreaterThan(0);
  });

  it("400s on a too-short password", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const res = await request(app).post("/cases/INC-1/export/encrypted").send({ password: "short" });
    expect(res.status).toBe(400);
  });

  it("404s for an unknown case", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/ghost/export/encrypted").send({ password: PASSWORD });
    expect(res.status).toBe(404);
  });

  it("400s on a path-traversal case id instead of reading outside the cases root", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/cases/..%2F..%2Fetc/export/encrypted")
      .send({ password: PASSWORD });
    expect(res.status).toBe(400);
  });

  // A case name is free text an analyst typed, so it routinely holds characters outside Latin-1 —
  // an em dash, an accent, a non-Latin script. Node rejects those outright in a header VALUE, so
  // interpolating the name straight into Content-Disposition threw and the route turned it into a
  // bare 500 with no hint of what was wrong. The demo case ships one ("GlobalTech Industries —
  // BEC & Ransomware Precursor"), which made every seeded demo un-exportable.
  it("exports a case whose name contains non-Latin-1 characters", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    await store.updateCaseMeta("INC-1", { name: "GlobalTech — BEC & Ransomware" });

    const res = await bufferRequest(
      request(app).post("/cases/INC-1/export/encrypted").send({ password: PASSWORD }),
    );

    expect(res.status).toBe(200);
    expect((res.body as Buffer).length).toBeGreaterThan(0);
    // RFC 6266: the exact name travels in filename*, so a modern client saves the em dash intact,
    // while filename= keeps an ASCII rendering for clients that ignore filename*.
    expect(res.headers["content-disposition"]).toBe(
      'attachment; filename="INC-1 - GlobalTech _ BEC & Ransomware.dfircase"; ' +
        "filename*=UTF-8''INC-1%20-%20GlobalTech%20%E2%80%94%20BEC%20%26%20Ransomware.dfircase",
    );
  });

  it("exports a case seeded by POST /cases/seed-demo", async () => {
    const { app } = await harness();
    const seeded = await request(app).post("/cases/seed-demo").send({ caseId: "demo", force: true });
    expect(seeded.status).toBe(201);

    const res = await bufferRequest(
      request(app).post("/cases/demo/export/encrypted").send({ password: PASSWORD }),
    );

    expect(res.status).toBe(200);
    expect((res.body as Buffer).length).toBeGreaterThan(0);
  });
});

describe("POST /cases/import/encrypted", () => {
  // The import limiter is a module-level singleton keyed by client IP, so every test in this
  // block would otherwise share one counter (and supertest gives them all the same address).
  beforeEach(() => resetLimiters());

  it("round-trips an encrypted archive into a new case, including evidence", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");

    const imp = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD, targetCaseId: "INC-2" });
    expect(imp.status).toBe(201);
    expect(imp.body.caseId).toBe("INC-2");
    expect(imp.body.counts).toMatchObject({ findings: 1, iocs: 1, forensicEvents: 1 });

    const state = await request(app).get("/cases/INC-2/state");
    expect(state.body.caseId).toBe("INC-2");
    expect(state.body.findings).toHaveLength(1);
    expect((await request(app).get("/cases/INC-2/comments")).body.length).toBeGreaterThan(0);

    // evidence bytes travelled too — this is the whole point of replacing the JSON snapshot
    const evidence = await request(app).get("/cases/INC-2/evidence/shot.webp");
    expect(evidence.status).toBe(200);
  });

  it("imports under the archive's own id when no target is given", async () => {
    const { app: app1, stateStore, store } = await harness();
    await seedCase(app1, stateStore, store);
    const data = await exportArchive(app1, "INC-1");

    const { app: app2 } = await harness(); // a separate companion where INC-1 is free
    const imp = await request(app2).post("/cases/import/encrypted").send({ data, password: PASSWORD });
    expect(imp.status).toBe(201);
    expect(imp.body.caseId).toBe("INC-1");
  });

  it("409s when the target case already exists", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");
    const imp = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD });
    expect(imp.status).toBe(409);
    expect(imp.body.caseId).toBe("INC-1");
  });

  it("400s on the wrong password", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");
    const imp = await request(app).post("/cases/import/encrypted").send({ data, password: "totally-wrong", targetCaseId: "INC-3" });
    expect(imp.status).toBe(400);
  });

  // Opening an archive costs a deliberate ~1s scrypt derivation on the synchronous path, so an
  // unauthenticated caller looping failed imports can hold the event loop — the whole server —
  // for as long as it likes. The limiter has to cut in BEFORE the derivation.
  it("locks the caller out after repeated failed decrypts, and refuses even a valid archive while locked", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");

    // Drive the counter with cheap failures — a buffer that fails the magic check costs no
    // derivation at all, and the limiter counts every failed decrypt alike. Using five
    // wrong-password attempts against the real archive would burn five ~1s derivations to
    // prove exactly the same thing.
    const junk = Buffer.from("nowhere near a .dfircase container").toString("base64");
    for (let i = 0; i < 4; i++) {
      expect((await request(app).post("/cases/import/encrypted").send({ data: junk, password: "x" })).status).toBe(400);
    }
    const tripped = await request(app).post("/cases/import/encrypted").send({ data: junk, password: "x" });
    expect(tripped.status).toBe(429);
    expect(tripped.headers["retry-after"]).toBeDefined();
    expect(tripped.body.retryAfterMs).toBeGreaterThan(0);

    // The lockout is what protects the CPU: the correct password no longer buys a derivation.
    const locked = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD, targetCaseId: "INC-9" });
    expect(locked.status).toBe(429);
    expect((await request(app).get("/cases/INC-9/state")).status).toBe(404); // and nothing was imported
  });

  it("does not count a successful decrypt against the caller — a re-import conflict is not an attack", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");

    // Two 409s: the archive opened both times, so neither is a failed attempt.
    for (let i = 0; i < 2; i++) {
      expect((await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD })).status).toBe(409);
    }
    // Four genuine failures then still fit under the 5-attempt threshold — they would not if the
    // two conflicts had been counted. (Two conflicts, not six: each one costs a real derivation.)
    const junk = Buffer.from("nowhere near a .dfircase container").toString("base64");
    for (let i = 0; i < 4; i++) {
      expect((await request(app).post("/cases/import/encrypted").send({ data: junk, password: "x" })).status).toBe(400);
    }
  });

  // #424: the limiter recorded a failure only for a DecryptionError. A CORRECTLY encrypted archive
  // whose contents are not a ZIP pays exactly the same ~1s synchronous scrypt derivation and then
  // throws an archive error instead — so it never touched the limiter, and looping it was an
  // unmetered way to hold the event loop. (It answered 500 as well: a client-supplied archive that
  // does not parse is a bad request, not a server fault.)
  it("counts a correctly encrypted but malformed archive, which costs the same derivation", { timeout: 60_000 }, async () => {
    const { app } = await harness();
    // Valid container, correct password, contents that are not a ZIP. Decryption succeeds; the
    // ZIP parse is what fails.
    const data = encryptBuffer(Buffer.from("valid container, contents are not a ZIP"), PASSWORD).toString("base64");

    for (let i = 0; i < 4; i++) {
      const res = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD });
      expect(res.status).toBe(400);
    }
    const tripped = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD });
    expect(tripped.status).toBe(429);
    expect(tripped.headers["retry-after"]).toBeDefined();
  });

  it("clears the failure state only on a successful import", { timeout: 60_000 }, async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const good = await exportArchive(app, "INC-1");
    const bad = encryptBuffer(Buffer.from("not a ZIP"), PASSWORD).toString("base64");

    for (let i = 0; i < 4; i++) {
      expect((await request(app).post("/cases/import/encrypted").send({ data: bad, password: PASSWORD })).status).toBe(400);
    }
    // One good import resets the counter...
    expect((await request(app).post("/cases/import/encrypted").send({ data: good, password: PASSWORD, targetCaseId: "INC-2" })).status).toBe(201);
    // ...so four more failures fit again rather than tripping on the first.
    for (let i = 0; i < 4; i++) {
      expect((await request(app).post("/cases/import/encrypted").send({ data: bad, password: PASSWORD })).status).toBe(400);
    }
  });

  // The conflict stays uncounted by the failure limiter — an analyst re-importing is not an
  // attack — but it opens the archive, which means it pays for a derivation. The per-request
  // budget is what stops a loop of them from being free.
  it("stops repeated conflicts from being an unmetered derivation loop", { timeout: 120_000 }, async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");

    let budgetHit = 0;
    for (let i = 0; i < 12; i++) {
      const res = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD });
      if (res.status === 429) { budgetHit = i; break; }
      expect(res.status).toBe(409);   // still a conflict, still not a "failed import"
    }
    expect(budgetHit).toBeGreaterThan(0);
    // The bound came from the request budget, not the failure lockout — so the message is the
    // budget's, and the failure limiter was never touched.
    const res = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD });
    expect(res.body.error).toMatch(/too many import attempts/i);
  });

  it("400s on a malformed payload", async () => {
    const { app } = await harness();
    expect((await request(app).post("/cases/import/encrypted").send({ hello: "world" })).status).toBe(400);
    expect((await request(app).post("/cases/import/encrypted").send({ data: "@@@not-base64@@@", password: PASSWORD })).status).toBe(400);
  });

  it("never leaks a case-lock password hash — an archived case that had one keeps it out of the import response", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    // The source case has its own dashboard case-lock password (unrelated to the archive's
    // export password) — case.json is written back byte-for-byte on import, so the hash
    // travels in the archive too. It must never reach the import response. Setting a password
    // no longer auto-unlocks the setter, and /export/encrypted is itself gated once a password
    // is set, so the agent must actually unlock before it can export.
    const agent = request.agent(app);
    await agent.post("/cases/INC-1/password").send({ newPassword: "correct horse" });
    await agent.post("/cases/INC-1/unlock").send({ password: "correct horse" });
    const exportRes = await bufferRequest(agent.post("/cases/INC-1/export/encrypted").send({ password: PASSWORD }));
    const data = (exportRes.body as Buffer).toString("base64");

    const imp = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD, targetCaseId: "INC-4" });
    expect(imp.status).toBe(201);
    expect(imp.body.hasPassword).toBe(true);
    expect(imp.body.password).toBeUndefined();
    expect(JSON.stringify(imp.body)).not.toContain("hash");
  });
});
