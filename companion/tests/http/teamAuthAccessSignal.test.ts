import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2449: every auth route that can end someone's access tells TeamAuth listeners (the live hub)
// once the change has committed, so open live dashboards are re-checked at once. A refused request
// changed nothing and signals nothing.

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const PASSWORD = "a different sufficiently long password";

interface Session {
  agent: ReturnType<typeof request.agent>;
  csrf: string;
  identityId: string;
}

describe("auth routes signal access changes (#2449)", () => {
  let cases: CaseStore;
  let authStore: AuthStore;
  let auth: TeamAuth;
  let app: ReturnType<typeof createApp>;
  let signal: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-access-routes-"));
    cases = new CaseStore(join(root, "cases"));
    authStore = new AuthStore(join(root, "auth.sqlite"));
    auth = new TeamAuth({
      store: authStore,
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    app = createApp(cases, { teamAuth: auth });
    signal = vi.fn();
    auth.onAccessChanged(signal);
  });

  afterEach(() => authStore.close());

  async function withCsrf(agent: ReturnType<typeof request.agent>): Promise<Session> {
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
    return withCsrf(agent);
  }

  async function createMember(admin: Session, username: string): Promise<string> {
    const res = await admin.agent
      .post("/auth/users")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ username, password: PASSWORD, displayName: username });
    expect(res.status).toBe(201);
    return res.body.id as string;
  }

  it("signals after a sign-out", async () => {
    const admin = await bootstrap();
    signal.mockClear();
    const res = await admin.agent.post("/auth/logout").set("X-DFIR-CSRF", admin.csrf);
    expect(res.status).toBe(204);
    expect(signal).toHaveBeenCalledTimes(1);
  });

  it("signals after signing out other sessions", async () => {
    const admin = await bootstrap();
    signal.mockClear();
    const res = await admin.agent.delete("/auth/sessions/others").set("X-DFIR-CSRF", admin.csrf);
    expect(res.status).toBe(200);
    expect(signal).toHaveBeenCalledTimes(1);
  });

  it("signals after a user update and not after a refused one", async () => {
    const admin = await bootstrap();
    const member = await createMember(admin, "analyst");
    signal.mockClear();
    const refused = await admin.agent
      .patch(`/auth/users/${member}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ globalRole: "nonsense" });
    expect(refused.status).toBe(400);
    expect(signal).not.toHaveBeenCalled();
    const res = await admin.agent
      .patch(`/auth/users/${member}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ disabled: true });
    expect(res.status).toBe(200);
    expect(signal).toHaveBeenCalledTimes(1);
  });

  it("does not signal when the user update throws (last administrator)", async () => {
    const admin = await bootstrap();
    signal.mockClear();
    const res = await admin.agent
      .patch(`/auth/users/${admin.identityId}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ disabled: true });
    expect(res.status).toBe(400);
    expect(signal).not.toHaveBeenCalled();
  });

  it("signals after a case role is removed and not when there was none to remove", async () => {
    const admin = await bootstrap();
    const member = await createMember(admin, "analyst");
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    signal.mockClear();
    const missing = await admin.agent.delete(`/auth/cases/c1/roles/${member}`).set("X-DFIR-CSRF", admin.csrf);
    expect(missing.status).toBe(404);
    expect(signal).not.toHaveBeenCalled();

    const actor = authStore.getIdentity(admin.identityId)!;
    authStore.setCaseRole("c1", member, "reader", actor);
    const res = await admin.agent.delete(`/auth/cases/c1/roles/${member}`).set("X-DFIR-CSRF", admin.csrf);
    expect(res.status).toBe(204);
    expect(signal).toHaveBeenCalledTimes(1);
  });

  it("does not signal for a request refused before any change (no session)", async () => {
    await bootstrap();
    signal.mockClear();
    const res = await request(app).post("/auth/logout");
    expect(res.status).toBe(401);
    expect(signal).not.toHaveBeenCalled();
  });
});
