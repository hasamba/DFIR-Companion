// #1853 — POST /cases/seed-demo is a way a case id is born, so it must run the same id-reuse checks
// #1831 added to POST /cases and the whole-case imports: clear roles a failed delete left on the id,
// wait out the deleted case's jobs, and never adopt a part-deleted folder's files.

import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";

const exists = (p: string) =>
  stat(p).then(
    () => true,
    () => false,
  );

async function tmpRoot(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dfir-seed-reuse-"));
}

describe("seed-demo on an id a deleted case left roles on", () => {
  it("clears the stale role before granting the creator", async () => {
    const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
    const root = await tmpRoot();
    const store = new CaseStore(join(root, "cases"));
    const authStore = new AuthStore(join(root, "auth.sqlite"));
    const app = createApp(store, {
      stateStore: new StateStore(store),
      teamAuth: new TeamAuth({
        store: authStore,
        bootstrapToken: BOOTSTRAP_TOKEN,
        cookieSecure: false,
        sessionTtlMs: 60 * 60_000,
      }),
    });
    const admin = request.agent(app);
    expect(
      (
        await admin.post("/auth/bootstrap").send({
          bootstrapToken: BOOTSTRAP_TOKEN,
          username: "admin",
          password: "correct horse battery staple",
          displayName: "Primary Admin",
        })
      ).status,
    ).toBe(201);
    const me = await admin.get("/auth/me");
    const csrf = me.body.csrfToken as string;
    const adminId = (me.body.identity?.id ?? me.body.id) as string;
    const reader = await admin.post("/auth/users").set("X-DFIR-CSRF", csrf).send({
      username: "reader",
      password: "a different sufficiently long password",
      displayName: "READER",
    });
    const readerId = reader.body.id as string;
    const body = { caseId: "d9", name: "Old", investigator: "admin", aiProvider: "mock" };
    expect((await admin.post("/cases").set("X-DFIR-CSRF", csrf).send(body)).status).toBe(201);
    await admin
      .put(`/auth/cases/d9/roles/${encodeURIComponent(readerId)}`)
      .set("X-DFIR-CSRF", csrf)
      .send({ role: "administrator" });
    await admin.patch("/cases/d9/status").set("X-DFIR-CSRF", csrf).send({ status: "closed" });
    // The delete's cleanup fails to revoke access: the case is gone, its roles are not.
    const revoke = authStore.deleteCaseAccess.bind(authStore);
    authStore.deleteCaseAccess = () => {
      authStore.deleteCaseAccess = revoke;
      throw new Error("database is locked");
    };
    const del = await admin.post("/cases/d9/delete").set("X-DFIR-CSRF", csrf).send({ archiveFirst: "none" });
    expect(del.body).toMatchObject({ deleted: true });
    expect(authStore.getCaseRole(readerId, "d9")).toBe("administrator");

    const seeded = await admin.post("/cases/seed-demo").set("X-DFIR-CSRF", csrf).send({ caseId: "d9" });

    expect(seeded.status).toBe(201);
    expect(authStore.getCaseRole(readerId, "d9")).toBeNull();
    expect(authStore.getCaseRole(adminId, "d9")).toBe("administrator");
  });
});

describe("seed-demo on an id whose deleted case still has work stopping", () => {
  it("answers 409 until the old work reports its end, then seeds", async () => {
    const store = new CaseStore(await tmpRoot());
    const jobManager = new JobManager({ perCaseConcurrency: 1 });
    const app = createApp(store, { stateStore: new StateStore(store), jobManager });
    const body = { caseId: "d1", name: "Old", investigator: "alice", aiProvider: "mock" };
    expect((await request(app).post("/cases").send(body)).status).toBe(201);
    const job = jobManager.register({ caseId: "d1", kind: "import", cancellable: true });
    await job.ready;
    await request(app).patch("/cases/d1/status").send({ status: "closed" });
    expect((await request(app).post("/cases/d1/delete").send({ archiveFirst: "none" })).body).toMatchObject({
      deleted: true,
    });

    const refused = await request(app).post("/cases/seed-demo").send({ caseId: "d1" });
    expect(refused.status).toBe(409);
    expect(refused.body.error).toMatch(/still stopping/);
    expect(await store.caseExists("d1")).toBe(false);

    await jobManager.fail(job.jobId, new Error("aborted"));
    expect((await request(app).post("/cases/seed-demo").send({ caseId: "d1" })).status).toBe(201);
  });
});

describe("seed-demo on an id with a part-deleted folder", () => {
  it("refuses with 409 and leaves the old files alone", async () => {
    const store = new CaseStore(await tmpRoot());
    const app = createApp(store, { stateStore: new StateStore(store) });
    const dir = store.caseDir("d2");
    await mkdir(join(dir, "imports"), { recursive: true });
    await writeFile(join(dir, "imports", "old-evidence.csv"), "a,b\n1,2\n");

    const res = await request(app).post("/cases/seed-demo").send({ caseId: "d2" });

    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/still on disk/);
    expect(await exists(join(dir, "case.json"))).toBe(false);
    expect(await readFile(join(dir, "imports", "old-evidence.csv"), "utf8")).toBe("a,b\n1,2\n");
  });

  it("still force-reseeds an existing closed demo case", async () => {
    const store = new CaseStore(await tmpRoot());
    const app = createApp(store, { stateStore: new StateStore(store) });
    expect((await request(app).post("/cases/seed-demo").send({ caseId: "d3" })).status).toBe(201);
    await request(app).patch("/cases/d3/status").send({ status: "closed" });
    expect((await request(app).post("/cases/seed-demo").send({ caseId: "d3", force: true })).status).toBe(
      201,
    );
  });
});
