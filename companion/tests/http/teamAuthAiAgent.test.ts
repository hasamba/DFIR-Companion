// AI Agent Forensics (#2690) under team authentication, through the real middleware. Rules are
// reference data; the sweep list is cut to the sweeps the caller may see; a launch INTO a case named in
// the body needs WRITE on that case, and a launch with no case (a sweep) is the administrator's (#2725).
// The case's endpoint list is for case writers, and carries only the reduced fields (#2725).
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
import type { AppOptions } from "../../src/composition/appOptions.js";

// The case's set resolves to a Velociraptor server; its persisted inventory holds two synthetic clients.
// The second record carries a field the endpoint list must never pass through.
const INVENTORY = {
  updatedAt: "2026-11-01T00:00:00Z",
  clients: [
    {
      clientId: "C.aaa111",
      hostname: "WS-01",
      fqdn: "ws-01.lab.test",
      lastSeen: "1700000000",
      labels: ["dev"],
    },
    { clientId: "C.bbb222", hostname: "WS-02", fqdn: "ws-02.lab.test", secretNote: "not for analysts" },
  ],
};
const serverClients = {
  forCase: () => ({ ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: {} } }),
  forSet: () => ({ ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: {} } }),
  forDefault: () => ({ ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: {} } }),
  invalidate: () => undefined,
} as unknown as AppOptions["serverClients"];
const inventorySets: string[] = [];
const clientInventoryFor = ((setId: string) => {
  inventorySets.push(setId);
  return { load: async () => INVENTORY };
}) as unknown as AppOptions["clientInventoryFor"];

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

  const endpoints = (s: Session) => s.agent.get("/cases/c1/ai-agent/endpoints");

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-team-aiagent-"));
    cases = new CaseStore(join(root, "cases"));
    const auth = new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    inventorySets.length = 0;
    app = createApp(cases, {
      teamAuth: auth,
      veloHuntStore: new VeloHuntStore(cases),
      serverClients,
      clientInventoryFor,
    });
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
    expect((await launch(admin, {})).status).toBe(400); // a case-less sweep passes the gate for the admin
    expect((await endpoints(admin)).status).toBe(200);
  });

  it("analyst with write on the case: reads rules, sees no one else's sweep, and may launch into it", async () => {
    const inv = await analyst("investigator1", "investigator");
    expect((await inv.agent.get("/ai-agent/rules")).status).toBe(200);
    const sweeps = await inv.agent.get("/ai-agent/sweeps");
    expect(sweeps.status).toBe(200);
    expect(sweeps.body.sweeps).toEqual([]);
    expect((await launch(inv, { caseId: "c1" })).status).toBe(400);
  });

  it("analyst with write on the case: lists the case set's endpoints, reduced fields only", async () => {
    const inv = await analyst("investigator2", "investigator");
    const r = await endpoints(inv);
    expect(r.status).toBe(200);
    expect(inventorySets).toEqual(["set-1"]);
    expect(r.body.setName).toBe("Lab");
    expect(r.body.clients).toEqual([
      {
        clientId: "C.aaa111",
        hostname: "WS-01",
        fqdn: "ws-01.lab.test",
        lastSeen: "1700000000",
        labels: ["dev"],
      },
      { clientId: "C.bbb222", hostname: "WS-02", fqdn: "ws-02.lab.test", labels: [] },
    ]);
  });

  it("analyst with write on the case: refused a run with no case open (administrator only)", async () => {
    const inv = await analyst("investigator3", "investigator");
    const r = await launch(inv, { clientIds: ["C.aaa111"] });
    expect(r.status).toBe(403);
    expect(r.body.error).toMatch(/administrator/i);
  });

  it("analyst with read-only access: refused a launch into the case", async () => {
    const reader = await analyst("reader1", "reader");
    expect((await reader.agent.get("/ai-agent/rules")).status).toBe(200);
    expect((await launch(reader, { caseId: "c1" })).status).toBe(403);
    expect((await launch(reader, {})).status).toBe(403);
    const list = await endpoints(reader);
    expect(list.status).toBe(403);
    expect(list.body.error).toMatch(/write access/i);
  });

  it("analyst without access: the case does not exist for them, and no sweep is listed", async () => {
    const outsider = await analyst("outsider1");
    expect((await launch(outsider, { caseId: "c1" })).status).toBe(404);
    expect((await outsider.agent.get("/ai-agent/sweeps")).body.sweeps).toEqual([]);
    expect((await launch(outsider, {})).status).toBe(403);
    expect((await endpoints(outsider)).status).toBe(404);
  });
});
