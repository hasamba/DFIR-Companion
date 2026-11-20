// Threat-hunt routes (#2670) under team authentication, through the real middleware.
// D3: only the instance administrator edits a client profile; members see profile NAMES only, and
// earlier-hunt data only for the cases they can already open (team role AND case-password unlock).
// Linking a case to a client needs case-administrator rights.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { ClientProfileStore } from "../../src/analysis/clientProfileStore.js";
import { HuntClientLinkStore } from "../../src/analysis/huntClientLink.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const PASSWORD = "a different sufficiently long password";

interface Session {
  agent: ReturnType<typeof request.agent>;
  csrf: string;
}

describe("threat-hunt routes under team authentication (#2670)", () => {
  let app: ReturnType<typeof createApp>;
  let admin: Session;
  let links: HuntClientLinkStore;
  let incidentTypes: IncidentTypeStore;
  let clientId: string;

  async function session(agent: ReturnType<typeof request.agent>): Promise<Session> {
    const me = await agent.get("/auth/me");
    expect(me.status).toBe(200);
    return { agent, csrf: me.body.csrfToken as string };
  }

  async function grant(userId: string, caseId: string, role: string) {
    const r = await admin.agent
      .put(`/auth/cases/${caseId}/roles/${encodeURIComponent(userId)}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ role });
    expect(r.status).toBe(200);
  }

  async function member(username: string, role?: string): Promise<Session & { id: string }> {
    const made = await admin.agent
      .post("/auth/users")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ username, password: PASSWORD, displayName: username });
    expect(made.status).toBe(201);
    if (role) await grant(made.body.id as string, "c1", role);
    const agent = request.agent(app);
    expect((await agent.post("/auth/local/login").send({ username, password: PASSWORD })).status).toBe(200);
    return { ...(await session(agent)), id: made.body.id as string };
  }

  const post = (s: Session, url: string, body: unknown = {}) =>
    s.agent
      .post(url)
      .set("X-DFIR-CSRF", s.csrf)
      .send(body as object);

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-team-hunt-"));
    const cases = new CaseStore(join(root, "cases"));
    const auth = new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    links = new HuntClientLinkStore(cases);
    incidentTypes = new IncidentTypeStore(cases, join(root, "incident-types"));
    app = createApp(cases, {
      teamAuth: auth,
      stateStore: new StateStore(cases),
      veloHuntStore: new VeloHuntStore(cases),
      incidentTypeStore: incidentTypes,
      clientProfileStore: new ClientProfileStore(join(root, "client-profiles")),
      huntClientLinkStore: links,
      huntInventoryStore: new HuntInventoryStore(cases),
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
    for (const id of ["c1", "c2"])
      expect((await post(admin, "/cases", { caseId: id, name: `Hunt ${id}` })).status).toBe(201);
    await incidentTypes.saveRecord("c1", "threat-hunt");
    const made = await post(admin, "/client-profiles", { name: "Client A" });
    expect(made.status).toBe(201);
    clientId = made.body.id as string;
    await links.save("c2", { clientId, linkedAt: "2026-01-01T00:00:00Z", linkedBy: "admin" });
  });

  it("administrator: creates, reads and marks a profile, links a case, sees every earlier hunt", async () => {
    expect((await admin.agent.get(`/client-profiles/${clientId}`)).status).toBe(200);
    const marked = await post(admin, `/client-profiles/${clientId}/marks`, {
      source: "client email 2026-11-20",
      marks: [
        {
          verdict: "approved",
          family: "program",
          program: "7z.exe",
          pathPattern: "\\program files\\7-zip",
          sha256: ["a".repeat(64)],
        },
      ],
    });
    expect(marked.status).toBe(200);
    expect(marked.body.version).toBe(1);
    expect((await post(admin, "/cases/c1/hunt/client", { clientId })).status).toBe(200);
    const info = await admin.agent.get("/cases/c1/hunt/client");
    expect(info.body.earlierHunts.map((h: { caseId: string }) => h.caseId)).toEqual(["c2"]);
  });

  it("investigator: names only, no profile edit, no link, but reads and exports the case", async () => {
    const inv = await member("investigator1", "investigator");
    const list = await inv.agent.get("/client-profiles");
    expect(list.status).toBe(200);
    expect(list.body).toEqual([{ id: clientId, name: "Client A" }]);
    expect((await inv.agent.get(`/client-profiles/${clientId}`)).status).toBe(403);
    expect((await post(inv, "/client-profiles", { name: "Mine" })).status).toBe(403);
    expect((await post(inv, `/client-profiles/${clientId}/marks`, { source: "s", marks: [] })).status).toBe(
      403,
    );
    expect((await post(inv, "/cases/c1/hunt/client", { clientId })).status).toBe(403);
    expect((await inv.agent.get("/cases/c1/hunt/status")).status).toBe(200);
    expect((await inv.agent.get("/cases/c1/hunt/confirm-list.csv")).status).toBe(200);
  });

  it("case administrator: may link the case to a client", async () => {
    const owner = await member("owner1", "administrator");
    expect((await post(owner, "/cases/c1/hunt/client", { clientId })).status).toBe(200);
  });

  it("reader: reads status and the client link, cannot convert or re-grade", async () => {
    const reader = await member("reader1", "reader");
    expect((await reader.agent.get("/cases/c1/hunt/client")).status).toBe(200);
    expect((await post(reader, "/cases/c1/hunt/convert-to-incident")).status).toBe(403);
    expect((await post(reader, "/cases/c1/hunt/regrade")).status).toBe(403);
  });

  it("outsider: the hunt case does not exist for them", async () => {
    const outsider = await member("outsider1");
    expect((await outsider.agent.get("/cases/c1/hunt/status")).status).toBe(404);
    expect((await outsider.agent.get("/cases/c1/hunt/confirm-list.csv")).status).toBe(404);
  });

  it("earlier hunts: shown only while the member may open them — revoked or password-locked hides them", async () => {
    const owner = await member("owner2", "administrator");
    await links.save("c1", { clientId, linkedAt: "2026-02-01T00:00:00Z", linkedBy: "owner2" });
    const earlier = async () =>
      (await owner.agent.get("/cases/c1/hunt/client")).body.earlierHunts.map(
        (h: { caseId: string }) => h.caseId,
      );
    expect(await earlier()).toEqual([]); // no role on c2
    await grant(owner.id, "c2", "reader");
    expect(await earlier()).toEqual(["c2"]);
    const locked = await post(admin, "/cases/c2/password", { newPassword: "case-password-long-enough" });
    expect(locked.status).toBe(200);
    expect(await earlier()).toEqual([]); // locked, and this request carries no unlock
    expect(
      (await admin.agent.delete(`/auth/cases/c2/roles/${owner.id}`).set("X-DFIR-CSRF", admin.csrf)).status,
    ).toBe(204);
    expect(await earlier()).toEqual([]);
  });
});

describe("threat-hunt policy entries (#2670)", () => {
  it("classifies every new route explicitly", async () => {
    const { resolveRequestPolicy } = await import("../../src/auth/policy.js");
    expect(resolveRequestPolicy("GET", "/client-profiles")).toEqual({ kind: "authenticated" });
    for (const [m, p] of [
      ["POST", "/client-profiles"],
      ["GET", "/client-profiles/client-a-1"],
      ["PUT", "/client-profiles/client-a-1"],
      ["POST", "/client-profiles/client-a-1/marks"],
      ["POST", "/client-profiles/client-a-1/marks/import"],
      ["PUT", "/client-profiles/client-a-1/domains"],
    ])
      expect(resolveRequestPolicy(m, p), `${m} ${p}`).toEqual({ kind: "global", permission: "admin" });
    expect(resolveRequestPolicy("POST", "/cases/c1/hunt/client")).toMatchObject({ permission: "admin" });
    expect(resolveRequestPolicy("POST", "/cases/c1/hunt/client/")).toMatchObject({ permission: "admin" });
    expect(resolveRequestPolicy("GET", "/cases/c1/hunt/client")).toMatchObject({ permission: "read" });
    expect(resolveRequestPolicy("GET", "/cases/c1/hunt/confirm-list.csv")).toMatchObject({
      permission: "export",
    });
    expect(resolveRequestPolicy("GET", "/cases/c1/hunt/confirm-list.md")).toMatchObject({
      permission: "export",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/hunt/convert-to-incident")).toMatchObject({
      permission: "write",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/hunt/regrade")).toMatchObject({ permission: "write" });
  });
});
