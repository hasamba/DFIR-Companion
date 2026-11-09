import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

/**
 * The "all my cases" service-token scope (#2474). One token acts for its OWNER on every case the
 * owner can currently write to. Every test below pins one of the containment rules from the issue:
 * access follows the owner live, permissions are capped at capture + write, expiry is required and
 * bounded, closed/archived and password-locked cases stay shut, and every request is audited.
 */

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const PASSWORD = "a different sufficiently long password";
const DAY_MS = 24 * 60 * 60_000;

interface Session {
  agent: ReturnType<typeof request.agent>;
  csrf: string;
  identityId: string;
}

function inDays(days: number): string {
  return new Date(Date.now() + days * DAY_MS).toISOString();
}

describe("all-cases service tokens (#2474)", () => {
  let cases: CaseStore;
  let authStore: AuthStore;
  let app: ReturnType<typeof createApp>;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-all-cases-token-"));
    cases = new CaseStore(join(root, "cases"));
    authStore = new AuthStore(join(root, "auth.sqlite"));
    const auth = new TeamAuth({
      store: authStore,
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    app = createApp(cases, {
      teamAuth: auth,
      jobManager: new JobManager(),
      stateLock: new StateLock(),
      stateStore: new StateStore(cases),
      activityLogStore: new ActivityLogStore(cases),
      commentsStore: new CommentsStore(cases),
    });
  });

  async function sessionOf(agent: ReturnType<typeof request.agent>): Promise<Session> {
    const me = await agent.get("/auth/me");
    expect(me.status).toBe(200);
    return { agent, csrf: me.body.csrfToken as string, identityId: me.body.identity.id as string };
  }

  async function bootstrap(): Promise<Session> {
    const agent = request.agent(app);
    const res = await agent.post("/auth/bootstrap").send({
      bootstrapToken: BOOTSTRAP_TOKEN,
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Primary Admin",
    });
    expect(res.status).toBe(201);
    return sessionOf(agent);
  }

  async function userSession(admin: Session, username: string): Promise<Session> {
    const created = await admin.agent
      .post("/auth/users")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ username, password: PASSWORD, displayName: username.toUpperCase() });
    expect(created.status).toBe(201);
    const agent = request.agent(app);
    expect((await agent.post("/auth/local/login").send({ username, password: PASSWORD })).status).toBe(200);
    return sessionOf(agent);
  }

  async function createCase(admin: Session, caseId: string): Promise<void> {
    const res = await admin.agent
      .post("/cases")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId, name: caseId });
    expect(res.status).toBe(201);
  }

  async function grant(admin: Session, caseId: string, identityId: string, role: string): Promise<void> {
    const res = await admin.agent
      .put(`/auth/cases/${caseId}/roles/${encodeURIComponent(identityId)}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ role });
    expect(res.status).toBe(200);
  }

  async function mint(
    owner: Session,
    body: Record<string, unknown> = {},
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await owner.agent
      .post("/auth/service-tokens")
      .set("X-DFIR-CSRF", owner.csrf)
      .send({
        name: "capture extension",
        scope: "all-cases",
        permissions: ["capture", "write"],
        expiresAt: inDays(30),
        ...body,
      });
    return { status: res.status, body: res.body as Record<string, unknown> };
  }

  async function mintToken(owner: Session, body: Record<string, unknown> = {}): Promise<string> {
    const created = await mint(owner, body);
    expect(created.status).toBe(201);
    return created.body.token as string;
  }

  const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });
  const listed = async (token: string) =>
    (await request(app).get("/cases").set(bearer(token))).body.map((item: { caseId: string }) => item.caseId);
  const capture = (token: string, caseId: string, extra: Record<string, unknown> = {}) =>
    request(app)
      .post("/captures")
      .set(bearer(token))
      .send({ caseId, ...extra });

  /** Sets up: admin, an investigator owner, cases w1/w2 (investigator), r1 (reader), v1 (reviewer), x1 (none). */
  async function world(): Promise<{ admin: Session; owner: Session; token: string }> {
    const admin = await bootstrap();
    for (const caseId of ["w1", "w2", "r1", "v1", "x1"]) await createCase(admin, caseId);
    const owner = await userSession(admin, "analyst");
    await grant(admin, "w1", owner.identityId, "investigator");
    await grant(admin, "w2", owner.identityId, "administrator");
    await grant(admin, "r1", owner.identityId, "reader");
    await grant(admin, "v1", owner.identityId, "reviewer");
    const token = await mintToken(owner);
    return { admin, owner, token };
  }

  it("lets a user with no case-admin role mint one and act on every case they can write to", async () => {
    const { token } = await world();
    expect(await listed(token)).toEqual(expect.arrayContaining(["w1", "w2"]));
    expect([...(await listed(token))].sort()).toEqual(["w1", "w2"]);
    // 400 = past auth and into the capture handler (no image); 404 = refused by team auth.
    expect((await capture(token, "w1")).status).toBe(400);
    expect((await capture(token, "w2")).status).toBe(400);
    expect((await request(app).get("/cases/w1/state").set(bearer(token))).status).toBe(200);
  });

  it("never reaches cases where the owner is only a reader, a reviewer, or has no role", async () => {
    const { token } = await world();
    for (const caseId of ["r1", "v1", "x1"]) {
      expect((await capture(token, caseId)).status).toBe(404);
      expect((await request(app).get(`/cases/${caseId}/state`).set(bearer(token))).status).toBe(404);
    }
  });

  it("follows the owner's roles live: removed, granted later, and disabled", async () => {
    const { admin, owner, token } = await world();
    await admin.agent
      .delete(`/auth/cases/w1/roles/${encodeURIComponent(owner.identityId)}`)
      .set("X-DFIR-CSRF", admin.csrf);
    expect((await capture(token, "w1")).status).toBe(404);
    expect(await listed(token)).toEqual(["w2"]);

    await createCase(admin, "later");
    await grant(admin, "later", owner.identityId, "investigator");
    expect((await capture(token, "later")).status).toBe(400);

    await grant(admin, "w2", owner.identityId, "reader");
    expect((await capture(token, "w2")).status).toBe(404);

    await admin.agent
      .patch(`/auth/users/${encodeURIComponent(owner.identityId)}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ disabled: true });
    expect((await capture(token, "later")).status).toBe(401);
  });

  it("caps permissions at capture + write whatever is requested", async () => {
    const { owner } = await world();
    const created = await mint(owner, { permissions: ["capture", "write", "read", "review", "export"] });
    expect(created.status).toBe(201);
    expect([...(created.body.permissions as string[])].sort()).toEqual(["capture", "write"]);
    expect(created.body.scope).toBe("all-cases");
    expect((await mint(owner, { permissions: ["review", "export"] })).status).toBe(400);
    // A write-capable token cannot reach review, export or admin routes on its owner's admin case.
    const token = created.body.token as string;
    expect((await request(app).post("/cases/w2/password").set(bearer(token)).send({})).status).toBe(403);
  });

  it("requires an expiry no later than 90 days out", async () => {
    const { owner } = await world();
    expect((await mint(owner, { expiresAt: undefined })).status).toBe(400);
    expect((await mint(owner, { expiresAt: "not a date" })).status).toBe(400);
    expect((await mint(owner, { expiresAt: inDays(-1) })).status).toBe(400);
    expect((await mint(owner, { expiresAt: inDays(91) })).status).toBe(400);
    expect((await mint(owner, { expiresAt: inDays(90) })).status).toBe(201);
  });

  it("rejects an unknown scope and ignores a caseId on an all-cases request", async () => {
    const { owner } = await world();
    expect((await mint(owner, { scope: "everything" })).status).toBe(400);
    const created = await mint(owner, { caseId: "x1" });
    expect(created.status).toBe(201);
    expect(created.body.caseId).toBe("");
    expect((await capture(created.body.token as string, "x1")).status).toBe(404);
  });

  it("needs a signed-in session with CSRF to mint, and a bearer token cannot mint or revoke", async () => {
    const { owner, token } = await world();
    const noCsrf = await owner.agent
      .post("/auth/service-tokens")
      .send({ name: "n", scope: "all-cases", permissions: ["capture"], expiresAt: inDays(5) });
    expect(noCsrf.status).toBe(403);
    const viaBearer = await request(app)
      .post("/auth/service-tokens")
      .set(bearer(token))
      .send({ name: "n", scope: "all-cases", permissions: ["capture"], expiresAt: inDays(5) });
    expect(viaBearer.status).toBe(401);
    const tokens = await owner.agent.get("/auth/service-tokens");
    const id = (tokens.body as Array<{ id: string }>)[0].id;
    expect((await request(app).delete(`/auth/service-tokens/${id}`).set(bearer(token))).status).toBe(401);
  });

  it("stops at closed and archived cases, including writes sessions may still make", async () => {
    const { admin, token } = await world();
    await admin.agent.patch("/cases/w1/status").set("X-DFIR-CSRF", admin.csrf).send({ status: "closed" });
    expect((await capture(token, "w1")).status).toBe(423);
    expect(
      (await request(app).post("/cases/w1/comments").set(bearer(token)).send({ text: "x" })).status,
    ).toBe(423);
    expect((await request(app).get("/cases/w1/state").set(bearer(token))).status).toBe(423);
    expect(await listed(token)).toEqual(["w2"]);

    await cases.archiveCaseFolder("w2", "archived");
    expect((await capture(token, "w2")).status).toBe(423);
    expect((await request(app).get("/cases/w2/state").set(bearer(token))).status).toBe(423);
    expect(await listed(token)).toEqual([]);
  });

  it("does not bypass a case password", async () => {
    const { admin, token } = await world();
    expect(
      (
        await admin.agent
          .post("/cases/w1/password")
          .set("X-DFIR-CSRF", admin.csrf)
          .send({ newPassword: "case-password-long-enough" })
      ).status,
    ).toBe(200);
    expect((await capture(token, "w1")).status).toBe(401);
    expect((await capture(token, "w1", { casePassword: "case-password-long-enough" })).status).toBe(400);
  });

  it("lets a capture-only all-cases token read the case list but not case data or cross-case IOCs", async () => {
    const { owner } = await world();
    const token = await mintToken(owner, { permissions: ["capture"] });
    expect([...(await listed(token))].sort()).toEqual(["w1", "w2"]);
    expect((await request(app).get("/cases/w1/state").set(bearer(token))).status).toBe(403);
    expect((await request(app).get("/global/iocs").set(bearer(token))).status).toBe(403);
    expect((await capture(token, "w1")).status).toBe(400);
  });

  it("audits every case request with the token, the case and the outcome", async () => {
    const { admin, token } = await world();
    await capture(token, "w1");
    await capture(token, "x1");
    const audit = (await admin.agent.get("/auth/audit")).body as Array<Record<string, string>>;
    const rows = audit.filter((event) => event.action === "service-token-request");
    expect(rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          caseId: "w1",
          detail: expect.stringMatching(/POST \/captures status=400/),
        }),
        expect.objectContaining({ caseId: "x1", detail: expect.stringMatching(/status=404/) }),
      ]),
    );
    expect(rows.every((event) => event.actorDisplayName === "capture extension")).toBe(true);
  });

  it("shows the scope plainly: owner sees theirs, others do not, admins see and revoke all", async () => {
    const { admin, owner, token } = await world();
    const mine = (await owner.agent.get("/auth/service-tokens")).body as Array<Record<string, unknown>>;
    expect(mine).toEqual([
      expect.objectContaining({
        scope: "all-cases",
        ownerIdentityId: owner.identityId,
        ownerDisplayName: "ANALYST",
      }),
    ]);
    const other = await userSession(admin, "bystander");
    expect((await other.agent.get("/auth/service-tokens")).body).toEqual([]);
    const id = mine[0].id as string;
    expect(
      (await other.agent.delete(`/auth/service-tokens/${id}`).set("X-DFIR-CSRF", other.csrf)).status,
    ).toBe(404);
    expect((await admin.agent.get("/auth/service-tokens")).body).toEqual(
      expect.arrayContaining([expect.objectContaining({ id, scope: "all-cases" })]),
    );
    expect(
      (await admin.agent.delete(`/auth/service-tokens/${id}`).set("X-DFIR-CSRF", admin.csrf)).status,
    ).toBe(204);
    expect((await capture(token, "w1")).status).toBe(401);
  });

  it("lets the owner revoke their own token", async () => {
    const { owner, token } = await world();
    const id = ((await owner.agent.get("/auth/service-tokens")).body as Array<{ id: string }>)[0].id;
    expect(
      (await owner.agent.delete(`/auth/service-tokens/${id}`).set("X-DFIR-CSRF", owner.csrf)).status,
    ).toBe(204);
    expect((await capture(token, "w1")).status).toBe(401);
  });

  it("does not delegate a global administrator's implicit access, only explicit write roles", async () => {
    const admin = await bootstrap();
    await createCase(admin, "made-by-admin");
    const owner = await userSession(admin, "someone");
    await createCase(owner, "theirs");
    const adminToken = await mintToken(admin);
    // The admin created "made-by-admin" and so holds an explicit administrator role on it.
    expect(await listed(adminToken)).toEqual(["made-by-admin"]);
    expect((await capture(adminToken, "theirs")).status).toBe(404);
  });
});
