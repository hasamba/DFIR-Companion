// #1831 — a case id that is deleted and then created again must start clean. Three leftovers could
// reach the new case: (a) role grants a failed delete cleanup did not revoke, (b) late writes from
// the old case's aborted jobs, (c) files a part-failed folder removal left on disk.

import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore, CaseAlreadyExistsError, CaseFolderLeftoverError } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { StoppingJobs } from "../../src/analysis/stoppingJobs.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { AuditCursorStore } from "../../src/analysis/auditExportCursor.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { importZipArchiveCase } from "../../src/analysis/caseZipImport.js";
import { CaseImportConflictError } from "../../src/analysis/caseExportArchive.js";
import { importedCaseIdClaim } from "../../src/routes/caseIdentity.js";
import type { RouteContext } from "../../src/routes/context.js";
import type { Request } from "express";

const exists = (p: string) =>
  stat(p).then(
    () => true,
    () => false,
  );

async function tmpRoot(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dfir-id-reuse-"));
}

describe("(a) access rows a deleted case left behind", () => {
  it("createCase runs onClaimed after the claim; a throw undoes the claim", async () => {
    const root = await tmpRoot();
    const store = new CaseStore(root);
    await expect(
      store.createCase({
        caseId: "a1",
        name: "n",
        investigator: "i",
        aiProvider: null,
        onClaimed: () => {
          throw new Error("access store down");
        },
      }),
    ).rejects.toThrow(/access store down/);
    expect(await exists(join(root, "a1"))).toBe(false);
    const order: string[] = [];
    await store.createCase({
      caseId: "a1",
      name: "n",
      investigator: "i",
      aiProvider: null,
      onClaimed: async () => {
        order.push(await readFile(join(root, "a1", "case.json"), "utf8").then(() => "claimed"));
      },
    });
    expect(order).toEqual(["claimed"]);
  });

  it("never runs onClaimed for an id that already exists", async () => {
    const store = new CaseStore(await tmpRoot());
    await store.createCase({ caseId: "a2", name: "n", investigator: "i", aiProvider: null });
    let ran = false;
    const create = store.createCase({
      caseId: "a2",
      name: "n",
      investigator: "i",
      aiProvider: null,
      onClaimed: () => {
        ran = true;
      },
    });
    await expect(create).rejects.toBeInstanceOf(CaseAlreadyExistsError);
    expect(ran).toBe(false);
  });

  it("POST /cases clears a stale role on the id before granting the creator", async () => {
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
    const boot = await admin.post("/auth/bootstrap").send({
      bootstrapToken: BOOTSTRAP_TOKEN,
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Primary Admin",
    });
    expect(boot.status).toBe(201);
    const me = await admin.get("/auth/me");
    const csrf = me.body.csrfToken as string;
    const adminId = me.body.identity?.id ?? me.body.id;
    const reader = await admin.post("/auth/users").set("X-DFIR-CSRF", csrf).send({
      username: "reader",
      password: "a different sufficiently long password",
      displayName: "READER",
    });
    expect(reader.status).toBe(201);
    const readerId = reader.body.id as string;
    const body = { caseId: "c9", name: "Old", investigator: "admin", aiProvider: "mock" };
    expect((await admin.post("/cases").set("X-DFIR-CSRF", csrf).send(body)).status).toBe(201);
    const grant = await admin
      .put(`/auth/cases/c9/roles/${encodeURIComponent(readerId)}`)
      .set("X-DFIR-CSRF", csrf)
      .send({ role: "administrator" });
    expect(grant.status).toBe(200);
    expect(
      (await admin.patch("/cases/c9/status").set("X-DFIR-CSRF", csrf).send({ status: "closed" })).status,
    ).toBe(200);
    // The delete's cleanup fails to revoke access: the case is gone, its roles are not.
    const revoke = authStore.deleteCaseAccess.bind(authStore);
    authStore.deleteCaseAccess = () => {
      authStore.deleteCaseAccess = revoke;
      throw new Error("database is locked");
    };
    const del = await admin.post("/cases/c9/delete").set("X-DFIR-CSRF", csrf).send({ archiveFirst: "none" });
    expect(del.body).toMatchObject({ deleted: true });
    expect(authStore.getCaseRole(readerId, "c9")).toBe("administrator");

    const created = await admin
      .post("/cases")
      .set("X-DFIR-CSRF", csrf)
      .send({ ...body, name: "New" });
    expect(created.status).toBe(201);
    expect(authStore.getCaseRole(readerId, "c9")).toBeNull();
    expect(authStore.getCaseRole(adminId as string, "c9")).toBe("administrator");
  });
});

describe("(b) a deleted case's jobs still stopping", () => {
  it("StoppingJobs holds a case until every job settles, and adopts follow-on jobs", () => {
    const s = new StoppingJobs();
    s.add("c1", [
      { id: "j1", status: "running" },
      { id: "j2", status: "running" },
      { id: "q1", status: "queued" },
    ]);
    s.adopt("c1", "j3");
    s.adopt("other", "j4");
    expect(s.has("other")).toBe(false);
    s.settle("j1");
    s.settle("j2");
    expect(s.has("c1")).toBe(true);
    s.settle("j3");
    expect(s.has("c1")).toBe(false);
    s.settle("unknown"); // no-op
  });

  it("forgetCase keeps a running job's case stopping until the work reports its end", async () => {
    const jm = new JobManager({ perCaseConcurrency: 1 });
    const running = jm.register({ caseId: "c1", kind: "import", cancellable: true });
    await running.ready;
    const queued = jm.register({ caseId: "c1", kind: "import", cancellable: true });
    queued.ready.catch(() => undefined);
    await jm.forgetCase("c1");
    expect(running.signal?.aborted).toBe(true);
    expect(jm.isStopping("c1")).toBe(true); // the queued one never started, so it does not count
    // A follow-on job the old work registers while it winds down holds the id too.
    const followOn = jm.register({ caseId: "c1", kind: "synthesis" });
    await jm.fail(running.jobId, new Error("aborted"));
    expect(jm.isStopping("c1")).toBe(true);
    await followOn.ready;
    await jm.finish(followOn.jobId);
    expect(jm.isStopping("c1")).toBe(false);
  });

  it("POST /cases answers 409 while the old case's work is stopping, then 201", async () => {
    const store = new CaseStore(await tmpRoot());
    const jobManager = new JobManager({ perCaseConcurrency: 1 });
    const app = createApp(store, { stateStore: new StateStore(store), jobManager });
    const body = { caseId: "b1", name: "Old", investigator: "alice", aiProvider: "mock" };
    expect((await request(app).post("/cases").send(body)).status).toBe(201);
    const job = jobManager.register({ caseId: "b1", kind: "import", cancellable: true });
    await job.ready;
    expect((await request(app).patch("/cases/b1/status").send({ status: "closed" })).status).toBe(200);
    const del = await request(app).post("/cases/b1/delete").send({ archiveFirst: "none" });
    expect(del.body).toMatchObject({ deleted: true });
    expect(job.signal?.aborted).toBe(true);

    const refused = await request(app)
      .post("/cases")
      .send({ ...body, name: "New" });
    expect(refused.status).toBe(409);
    expect(refused.body.error).toMatch(/still stopping/);
    expect(await store.caseExists("b1")).toBe(false);

    await jobManager.fail(job.jobId, new Error("aborted")); // the old work notices and ends
    const created = await request(app)
      .post("/cases")
      .send({ ...body, name: "New" });
    expect(created.status).toBe(201);
  });
});

describe("(b) cancelled or superseded work still winding down", () => {
  it("a running job cancelled before the delete still holds the id until it reports", async () => {
    const jm = new JobManager({ perCaseConcurrency: 1 });
    const job = jm.register({ caseId: "c1", kind: "import", cancellable: true });
    await job.ready;
    expect((await jm.cancel(job.jobId)).ok).toBe(true);
    await jm.forgetCase("c1");
    expect(jm.isStopping("c1")).toBe(true);
    await jm.fail(job.jobId, new Error("aborted")); // the worker notices and ends
    expect(jm.isStopping("c1")).toBe(false);
  });

  it("a running job superseded before the delete still holds the id until it reports", async () => {
    const jm = new JobManager({ perCaseConcurrency: 2 });
    const first = jm.register({ caseId: "c1", kind: "synthesis", cancellable: true, exclusive: true });
    await first.ready;
    const second = jm.register({ caseId: "c1", kind: "synthesis", cancellable: true, exclusive: true });
    await second.ready;
    expect(first.signal?.aborted).toBe(true);
    await jm.finish(second.jobId);
    await jm.forgetCase("c1");
    expect(jm.isStopping("c1")).toBe(true);
    await jm.finish(first.jobId);
    expect(jm.isStopping("c1")).toBe(false);
  });

  it("a cancelled job that already reported does not hold a later delete", async () => {
    const jm = new JobManager({ perCaseConcurrency: 1 });
    const job = jm.register({ caseId: "c1", kind: "import", cancellable: true });
    await job.ready;
    await jm.cancel(job.jobId);
    await jm.fail(job.jobId, new Error("aborted"));
    const other = jm.register({ caseId: "c1", kind: "import" });
    await other.ready;
    await jm.finish(other.jobId);
    await jm.forgetCase("c1");
    expect(jm.isStopping("c1")).toBe(false);
  });
});

describe("whole-case imports of a reused id", () => {
  async function archive(app: ReturnType<typeof createApp>, stateStore: StateStore): Promise<Buffer> {
    await request(app)
      .post("/cases")
      .send({ caseId: "SRC", name: "Source", investigator: "alice", aiProvider: "mock" });
    await stateStore.save(emptyState("SRC"));
    const archived = await request(app).post("/cases/SRC/archive").send({});
    expect(archived.status).toBe(200);
    return readFile(archived.body.archivePath as string);
  }

  it("a ZIP import refuses an id whose deleted case still has work stopping, then succeeds", async () => {
    resetLimiters();
    const store = new CaseStore(await tmpRoot());
    const stateStore = new StateStore(store);
    const jobManager = new JobManager({ perCaseConcurrency: 1 });
    const app = createApp(store, { stateStore, jobManager });
    const zip = (await archive(app, stateStore)).toString("base64");
    await request(app)
      .post("/cases")
      .send({ caseId: "R1", name: "Old", investigator: "alice", aiProvider: "mock" });
    const job = jobManager.register({ caseId: "R1", kind: "import", cancellable: true });
    await job.ready;
    await request(app).patch("/cases/R1/status").send({ status: "closed" });
    expect((await request(app).post("/cases/R1/delete").send({ archiveFirst: "none" })).body).toMatchObject({
      deleted: true,
    });

    const refused = await request(app).post("/cases/import/zip").send({ data: zip, targetCaseId: "R1" });
    expect(refused.status).toBe(409);
    expect(refused.body.error).toMatch(/still stopping/);
    expect(await store.caseExists("R1")).toBe(false);

    await jobManager.fail(job.jobId, new Error("aborted"));
    const imported = await request(app).post("/cases/import/zip").send({ data: zip, targetCaseId: "R1" });
    expect(imported.status).toBe(201);
  });

  it("the import claim refuses a mid-delete or stopping id and clears stale access otherwise", () => {
    const cleared: string[] = [];
    const ctx = (deleting: boolean, stopping: boolean) =>
      ({
        store: { isDeleting: () => deleting },
        options: {
          jobManager: { isStopping: () => stopping },
          teamAuth: { store: { deleteCaseAccess: (id: string) => cleared.push(id) } },
        },
      }) as unknown as RouteContext;
    const req = {} as Request;
    expect(() => importedCaseIdClaim(ctx(true, false), req)("x1")).toThrow(CaseImportConflictError);
    expect(() => importedCaseIdClaim(ctx(false, true), req)("x2")).toThrow(/still stopping/);
    expect(cleared).toEqual([]);
    importedCaseIdClaim(ctx(false, false), req)("x3");
    expect(cleared).toEqual(["x3"]);
  });

  it("a claim that throws before the publish leaves nothing published", async () => {
    resetLimiters();
    const store = new CaseStore(await tmpRoot());
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore });
    const zip = await archive(app, stateStore);
    await expect(
      importZipArchiveCase(store, zip, {
        targetCaseId: "R2",
        beforePublish: () => {
          throw new Error("access store down");
        },
      }),
    ).rejects.toThrow(/access store down/);
    expect(await store.caseExists("R2")).toBe(false);
    expect(await exists(store.caseDir("R2"))).toBe(false);
  });
});

describe("(c) a folder a part-failed delete left on disk", () => {
  it("refuses a non-empty folder with no case.json and leaves its files alone", async () => {
    const root = await tmpRoot();
    const store = new CaseStore(root);
    await mkdir(join(root, "c1", "imports"), { recursive: true });
    await writeFile(join(root, "c1", "imports", "old-evidence.json"), "[]");
    const err = await store
      .createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CaseFolderLeftoverError);
    expect(err).toBeInstanceOf(CaseAlreadyExistsError);
    expect((err as Error).message).toMatch(/still on disk/);
    expect(await exists(join(root, "c1", "case.json"))).toBe(false);
    expect(await readFile(join(root, "c1", "imports", "old-evidence.json"), "utf8")).toBe("[]");
  });

  it("POST /cases answers the leftover folder with 409", async () => {
    const root = await tmpRoot();
    const store = new CaseStore(root);
    await mkdir(join(root, "c2"), { recursive: true });
    await writeFile(join(root, "c2", "stray.txt"), "x");
    const app = createApp(store, { stateStore: new StateStore(store) });
    const res = await request(app)
      .post("/cases")
      .send({ caseId: "c2", name: "n", investigator: "i", aiProvider: "mock" });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/still on disk/);
  });

  it("an empty folder is harmless and the create goes ahead", async () => {
    const root = await tmpRoot();
    const store = new CaseStore(root);
    await mkdir(join(root, "c3"), { recursive: true });
    const meta = await store.createCase({ caseId: "c3", name: "n", investigator: "i", aiProvider: null });
    expect(meta.caseId).toBe("c3");
  });
});

describe("the SIEM audit export position of a deleted case (#1868)", () => {
  it("is cleared by the delete, so a same-id new case's records are exported from line 0", async () => {
    const root = await tmpRoot();
    const store = new CaseStore(join(root, "cases"));
    const auditExportCursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    const app = createApp(store, { stateStore: new StateStore(store), auditExportCursors });
    const body = { caseId: "a1", name: "Old", investigator: "alice", aiProvider: "mock" };
    expect((await request(app).post("/cases").send(body)).status).toBe(201);
    await auditExportCursors.set("siem-1", "a1", 120);
    await request(app).patch("/cases/a1/status").send({ status: "closed" });

    const del = await request(app).post("/cases/a1/delete").send({ archiveFirst: "none" });

    expect(del.body).toMatchObject({ deleted: true });
    expect(await auditExportCursors.get("siem-1", "a1")).toBe(0);
  });
});
