// AI Agent Forensics (#2690) under team authentication, through the real middleware. Rules are
// reference data; the sweep list is cut to the sweeps the caller may see; a launch is open to every
// analyst, but a launch INTO a case named in the body needs WRITE on that case.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const PASSWORD = "a different sufficiently long password";

interface Session {
  agent: ReturnType<typeof request.agent>;
  csrf: string;
}

describe("AI Agent Forensics routes under team authentication", () => {
  let cases: CaseStore;
  let app: ReturnType<typeof createApp>;
  let admin: Session;

  async function session(agent: ReturnType<typeof request.agent>): Promise<Session> {
    const me = await agent.get("/auth/me");
    expect(me.status).toBe(200);
    return { agent, csrf: me.body.csrfToken as string };
  }

  async function analyst(username: string, role?: string): Promise<Session> {
    const made = await admin.agent
      .post("/auth/users")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ username, password: PASSWORD, displayName: username });
    expect(made.status).toBe(201);
    if (role) {
      const granted = await admin.agent
        .put(`/auth/cases/c1/roles/${encodeURIComponent(made.body.id as string)}`)
        .set("X-DFIR-CSRF", admin.csrf)
        .send({ role });
      expect(granted.status).toBe(200);
    }
    const agent = request.agent(app);
    expect((await agent.post("/auth/local/login").send({ username, password: PASSWORD })).status).toBe(200);
    return session(agent);
  }

  // A launch that passes the gates reaches the run's own validation: no endpoint → 400.
  const launch = (s: Session, body: Record<string, unknown>) =>
    s.agent
      .post("/ai-agent/runs")
      .set("X-DFIR-CSRF", s.csrf)
      .send({ clientIds: [], ...body });

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-team-aiagent-"));
    cases = new CaseStore(join(root, "cases"));
    const auth = new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    app = createApp(cases, { teamAuth: auth, veloHuntStore: new VeloHuntStore(cases) });
    const agent = request.agent(app);
    const boot = await agent.post("/auth/bootstrap").send({
      bootstrapToken: BOOTSTRAP_TOKEN,
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Admin",
    });
    expect(boot.status).toBe(201);
    admin = await session(agent);
    expect(
      (await admin.agent.post("/cases").set("X-DFIR-CSRF", admin.csrf).send({ caseId: "c1", name: "Case" }))
        .status,
    ).toBe(201);
    await cases.createCase({
      caseId: "aiagent-sweep-a",
      name: "s",
      investigator: "x",
      aiProvider: null,
      kind: "sweep",
    });
  });

  it("administrator: reads rules and every sweep, and may launch into the case", async () => {
    expect((await admin.agent.get("/ai-agent/rules")).status).toBe(200);
    const sweeps = await admin.agent.get("/ai-agent/sweeps");
    expect(sweeps.status).toBe(200);
    expect(sweeps.body.sweeps.map((s: { caseId: string }) => s.caseId)).toEqual(["aiagent-sweep-a"]);
    expect((await launch(admin, { caseId: "c1" })).status).toBe(400);
  });

  it("analyst with write on the case: reads rules, sees no one else's sweep, and may launch into it", async () => {
    const inv = await analyst("investigator1", "investigator");
    expect((await inv.agent.get("/ai-agent/rules")).status).toBe(200);
    const sweeps = await inv.agent.get("/ai-agent/sweeps");
    expect(sweeps.status).toBe(200);
    expect(sweeps.body.sweeps).toEqual([]);
    expect((await launch(inv, { caseId: "c1" })).status).toBe(400);
    expect((await launch(inv, {})).status).toBe(400); // a case-less sweep is open to analysts
  });

  it("analyst with read-only access: refused a launch into the case", async () => {
    const reader = await analyst("reader1", "reader");
    expect((await reader.agent.get("/ai-agent/rules")).status).toBe(200);
    expect((await launch(reader, { caseId: "c1" })).status).toBe(403);
  });

  it("analyst without access: the case does not exist for them, and no sweep is listed", async () => {
    const outsider = await analyst("outsider1");
    expect((await launch(outsider, { caseId: "c1" })).status).toBe(404);
    expect((await outsider.agent.get("/ai-agent/sweeps")).body.sweeps).toEqual([]);
    expect((await launch(outsider, {})).status).toBe(400);
  });
});
