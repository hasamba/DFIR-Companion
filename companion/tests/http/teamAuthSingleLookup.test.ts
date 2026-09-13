import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

/**
 * One authenticated request resolves its session ONCE (#1003).
 *
 * Team mode authenticates twice on the way in: the pre-auth body gate (#681) asks "is this
 * someone?" before the parsers, and teamAuth.middleware() asks again, after them, to make the
 * authorization decision. Both asked the store, so every request paid the session lookup twice.
 * The gate now hands its answer forward and the middleware reuses it. Nothing between the two
 * touches the body's meaning for auth, so the second answer could never have differed.
 *
 * The refusal paths are pinned too: a stranger is still turned away by the gate, and an
 * authenticated caller with the wrong CSRF token is still refused by the middleware — reusing the
 * lookup must not skip the decision.
 */
const BOOTSTRAP_TOKEN = "single-lookup-bootstrap-token-with-entropy";

let authStore: AuthStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-single-lookup-"));
  const cases = new CaseStore(join(root, "cases"));
  authStore = new AuthStore(join(root, "auth.sqlite"));
  app = createApp(cases, {
    teamAuth: new TeamAuth({
      store: authStore,
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    }),
    stateLock: new StateLock(),
    stateStore: new StateStore(cases),
    activityLogStore: new ActivityLogStore(cases),
    commentsStore: new CommentsStore(cases),
    slashCommandChannelStore: new SlashCommandChannelStore(join(root, "slash.json")),
  });
});

async function admin(): Promise<{ agent: ReturnType<typeof request.agent>; csrf: string }> {
  const agent = request.agent(app);
  const created = await agent.post("/auth/bootstrap").send({
    bootstrapToken: BOOTSTRAP_TOKEN,
    username: "admin",
    password: "correct horse battery staple",
    displayName: "Primary Admin",
  });
  expect(created.status).toBe(201);
  const me = await agent.get("/auth/me");
  expect(me.status).toBe(200);
  return { agent, csrf: me.body.csrfToken as string };
}

describe("team mode resolves a session once per request", () => {
  it("looks the session up once for an authenticated POST on a protected route", async () => {
    const { agent, csrf } = await admin();
    const lookup = vi.spyOn(authStore, "authenticateSession");
    const res = await agent
      .post("/cases")
      .set("X-DFIR-CSRF", csrf)
      .send({ caseId: "c1", name: "n", investigator: "i" });
    expect(res.status).toBe(201);
    expect(lookup).toHaveBeenCalledTimes(1);
  });

  it("looks the session up once for an authenticated GET", async () => {
    const { agent } = await admin();
    const lookup = vi.spyOn(authStore, "authenticateSession");
    const res = await agent.get("/cases");
    expect(res.status).toBe(200);
    expect(lookup).toHaveBeenCalledTimes(1);
  });

  it("still refuses a wrong CSRF token — reusing the lookup does not skip the decision", async () => {
    const { agent } = await admin();
    const res = await agent
      .post("/cases")
      .set("X-DFIR-CSRF", "not-the-token")
      .send({ caseId: "c1", name: "n", investigator: "i" });
    expect(res.status).toBe(403);
  });

  it("still turns a stranger away at the gate", async () => {
    const res = await request(app).get("/cases");
    expect(res.status).toBe(401);
  });
});
