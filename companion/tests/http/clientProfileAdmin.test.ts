// Edit, archive and delete a threat-hunt client (#2941), through the real team-auth middleware.
// Every action is the instance administrator's alone (like create); members get 403, whether or not
// the client exists. Archive keeps every byte and every link; delete is refused while any case — an
// archived case included — is linked, and the delete itself is written to the instance audit log.
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { ClientProfileStore } from "../../src/analysis/clientProfileStore.js";
import { HuntClientLinkStore } from "../../src/analysis/huntClientLink.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const PASSWORD = "a different sufficiently long password";

interface Session {
  agent: ReturnType<typeof request.agent>;
  csrf: string;
}

describe("client profile edit / archive / delete (#2941)", () => {
  let root: string;
  let app: ReturnType<typeof createApp>;
  let admin: Session;
  let cases: CaseStore;
  let links: HuntClientLinkStore;
  let profiles: ClientProfileStore;
  let clientId: string;

  async function session(agent: ReturnType<typeof request.agent>): Promise<Session> {
    const me = await agent.get("/auth/me");
    expect(me.status).toBe(200);
    return { agent, csrf: me.body.csrfToken as string };
  }

  const send = (s: Session, method: "post" | "put" | "delete", url: string, body: unknown = {}) =>
    s.agent[method](url)
      .set("X-DFIR-CSRF", s.csrf)
      .send(body as object);

  async function member(username: string, caseRole?: string): Promise<Session> {
    const made = await send(admin, "post", "/auth/users", {
      username,
      password: PASSWORD,
      displayName: username,
    });
    expect(made.status).toBe(201);
    if (caseRole) {
      const r = await send(admin, "put", `/auth/cases/c1/roles/${encodeURIComponent(made.body.id)}`, {
        role: caseRole,
      });
      expect(r.status).toBe(200);
    }
    const agent = request.agent(app);
    expect((await agent.post("/auth/local/login").send({ username, password: PASSWORD })).status).toBe(200);
    return session(agent);
  }

  const audit = async () =>
    (await admin.agent.get("/auth/audit")).body as Array<{
      action: string;
      target?: string;
      detail?: string;
    }>;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-client-admin-"));
    cases = new CaseStore(join(root, "cases"));
    const auth = new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    links = new HuntClientLinkStore(cases);
    profiles = new ClientProfileStore(join(root, "client-profiles"));
    const incidentTypes = new IncidentTypeStore(cases, join(root, "incident-types"));
    app = createApp(cases, {
      teamAuth: auth,
      stateStore: new StateStore(cases),
      veloHuntStore: new VeloHuntStore(cases),
      incidentTypeStore: incidentTypes,
      clientProfileStore: profiles,
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
      expect((await send(admin, "post", "/cases", { caseId: id, name: `Hunt ${id}` })).status).toBe(201);
    await incidentTypes.saveRecord("c1", "threat-hunt");
    const made = await send(admin, "post", "/client-profiles", { name: "Client A" });
    expect(made.status).toBe(201);
    clientId = made.body.id as string;
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("members get 403 for every new action — existing or unknown client, case administrator included", async () => {
    for (const s of [
      await member("investigator1", "investigator"),
      await member("owner1", "administrator"),
    ]) {
      for (const pid of [clientId, "no-such-client"]) {
        expect((await send(s, "put", `/client-profiles/${pid}`, { name: "X" })).status).toBe(403);
        expect((await send(s, "post", `/client-profiles/${pid}/archive`)).status).toBe(403);
        expect((await send(s, "post", `/client-profiles/${pid}/unarchive`)).status).toBe(403);
        expect((await send(s, "delete", `/client-profiles/${pid}`)).status).toBe(403);
      }
    }
    expect(await profiles.get(clientId)).not.toBeNull();
  });

  it("answers 404 for an unknown client", async () => {
    expect((await send(admin, "put", "/client-profiles/no-such-client", { name: "X" })).status).toBe(404);
    expect((await send(admin, "post", "/client-profiles/no-such-client/archive")).status).toBe(404);
    expect((await send(admin, "post", "/client-profiles/no-such-client/unarchive")).status).toBe(404);
    expect((await send(admin, "delete", "/client-profiles/no-such-client")).status).toBe(404);
  });

  it("edits the name and default server set, recorded in the client's audit trail", async () => {
    const r = await send(admin, "put", `/client-profiles/${clientId}`, {
      name: "Client B",
      defaultServerSetId: "set-1",
    });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ name: "Client B", defaultServerSetId: "set-1" });
    const last = r.body.audit[r.body.audit.length - 1];
    expect(last).toMatchObject({ by: "Admin", action: "profile" });
    expect(last.detail).toContain("Client A");
    expect(last.detail).toContain("Client B");
    expect(last.detail).toContain("set-1");
    const cleared = await send(admin, "put", `/client-profiles/${clientId}`, { name: "Client B" });
    expect(cleared.body.defaultServerSetId).toBeUndefined();
  });

  it("archive hides the client from both lists, keeps its data and link; unarchive restores it", async () => {
    await links.save("c1", { clientId, linkedAt: "2026-01-01T00:00:00Z", linkedBy: "admin" });
    const marked = await send(admin, "post", `/client-profiles/${clientId}/marks`, {
      source: "client email",
      marks: [{ verdict: "not-allowed", family: "program", program: "tool.exe" }],
    });
    expect(marked.status).toBe(200);
    const inv = await member("investigator2", "investigator");

    const archived = await send(admin, "post", `/client-profiles/${clientId}/archive`);
    expect(archived.status).toBe(200);
    expect(archived.body).toMatchObject({ id: clientId, archived: true });
    expect((await admin.agent.get("/client-profiles")).body).toEqual([]);
    expect((await inv.agent.get("/client-profiles")).body).toEqual([]);
    // The administrator can ask for archived clients; a member asking gets the active list only.
    expect((await admin.agent.get("/client-profiles?includeArchived=1")).body).toEqual([
      { id: clientId, name: "Client A", archived: true },
    ]);
    expect((await inv.agent.get("/client-profiles?includeArchived=1")).body).toEqual([]);

    const stored = await profiles.get(clientId);
    expect(stored?.version).toBe(1);
    expect(stored?.baseline.marks).toHaveLength(1);
    expect(stored?.audit.map((a) => a.action)).toEqual(["create", "marks", "archive"]);
    // The linked case keeps working and says the client is archived.
    const info = await admin.agent.get("/cases/c1/hunt/client");
    expect(info.body.client).toMatchObject({ id: clientId, name: "Client A", archived: true });
    const status = await admin.agent.get("/cases/c1/hunt/status");
    expect(status.body).toMatchObject({ clientName: "Client A", clientArchived: true });
    // Archiving twice changes nothing and adds no audit entry.
    expect((await send(admin, "post", `/client-profiles/${clientId}/archive`)).status).toBe(200);
    expect((await profiles.get(clientId))?.audit).toHaveLength(3);

    const back = await send(admin, "post", `/client-profiles/${clientId}/unarchive`);
    expect(back.status).toBe(200);
    expect(back.body.archived).toBeUndefined();
    expect((await inv.agent.get("/client-profiles")).body).toEqual([{ id: clientId, name: "Client A" }]);
    expect((await profiles.get(clientId))?.audit.map((a) => a.action)).toEqual([
      "create",
      "marks",
      "archive",
      "unarchive",
    ]);
    const actions = (await audit()).map((a) => a.action);
    expect(actions).toEqual(expect.arrayContaining(["client-profile-archived", "client-profile-unarchived"]));
  });

  it("refuses a new link to an archived client", async () => {
    await send(admin, "post", `/client-profiles/${clientId}/archive`);
    const r = await send(admin, "post", "/cases/c1/hunt/client", { clientId });
    expect(r.status).toBe(409);
    expect(r.body.error).toMatch(/archived/);
    expect(await links.load("c1")).toBeNull();
  });

  it("refuses to delete a linked client (409), naming every linked case — an archived case included", async () => {
    await links.save("c1", { clientId, linkedAt: "2026-01-01T00:00:00Z", linkedBy: "admin" });
    await links.save("c2", { clientId, linkedAt: "2026-01-02T00:00:00Z", linkedBy: "admin" });
    await cases.archiveCaseFolder("c2");
    const r = await send(admin, "delete", `/client-profiles/${clientId}`);
    expect(r.status).toBe(409);
    expect(r.body.error).toMatch(/archive/i);
    expect(r.body.linkedCases).toEqual(
      expect.arrayContaining([
        { caseId: "c1", name: "Hunt c1" },
        { caseId: "c2", name: "Hunt c2" },
      ]),
    );
    expect(r.body.linkedCases).toHaveLength(2);
    expect(await profiles.get(clientId)).not.toBeNull();
  });

  it("counts a case folder with a damaged case.json or an unreadable link file as linked", async () => {
    const stateDir = join(root, "cases", "broken-1", "state");
    await mkdir(stateDir, { recursive: true });
    await writeFile(join(root, "cases", "broken-1", "case.json"), "{not json");
    await writeFile(join(stateDir, "hunt-client.json"), JSON.stringify({ clientId }));
    const r1 = await send(admin, "delete", `/client-profiles/${clientId}`);
    expect(r1.status).toBe(409);
    expect(r1.body.linkedCases).toEqual([{ caseId: "broken-1", name: "broken-1" }]);
    await writeFile(join(stateDir, "hunt-client.json"), "{not json");
    const r2 = await send(admin, "delete", `/client-profiles/${clientId}`);
    expect(r2.status).toBe(409);
    expect(r2.body.linkedCases[0]).toMatchObject({ caseId: "broken-1", unreadable: true });
  });

  it("deletes an unlinked client and writes the delete to the instance audit log", async () => {
    await links.save("c1", {
      clientId: "some-other-client",
      linkedAt: "2026-01-01T00:00:00Z",
      linkedBy: "admin",
    });
    const r = await send(admin, "delete", `/client-profiles/${clientId}`);
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ deleted: clientId });
    expect(await profiles.get(clientId)).toBeNull();
    expect((await admin.agent.get(`/client-profiles/${clientId}`)).status).toBe(404);
    const row = (await audit()).find((a) => a.action === "client-profile-deleted");
    expect(row).toBeDefined();
    expect(JSON.stringify(row)).toContain(clientId);
    expect(JSON.stringify(row)).toContain("Client A");
  });

  it("orders link and delete on the client: delete-then-link 404, link-then-delete 409", async () => {
    const other = (await send(admin, "post", "/client-profiles", { name: "Client B" })).body.id as string;
    expect((await send(admin, "delete", `/client-profiles/${other}`)).status).toBe(200);
    expect((await send(admin, "post", "/cases/c1/hunt/client", { clientId: other })).status).toBe(404);
    expect((await send(admin, "post", "/cases/c1/hunt/client", { clientId })).status).toBe(200);
    expect((await send(admin, "delete", `/client-profiles/${clientId}`)).status).toBe(409);
  });

  it("a link and a delete fired together never leave a case linked to a deleted client", async () => {
    for (let i = 0; i < 5; i++) {
      const pid = (await send(admin, "post", "/client-profiles", { name: `Race ${i}` })).body.id as string;
      const [link, del] = await Promise.all([
        send(admin, "post", "/cases/c1/hunt/client", { clientId: pid }),
        send(admin, "delete", `/client-profiles/${pid}`),
      ]);
      const deleted = (await profiles.get(pid)) === null;
      const linked = (await links.load("c1"))?.clientId === pid;
      expect(deleted && linked).toBe(false);
      expect([link.status, del.status].sort()).toEqual(deleted ? [200, 404] : [200, 409]);
    }
  });
});

describe("client profile admin policy entries (#2941)", () => {
  it("leaves every new route with the instance administrator", async () => {
    const { resolveRequestPolicy } = await import("../../src/auth/policy.js");
    for (const [m, p] of [
      ["PUT", "/client-profiles/client-a-1"],
      ["POST", "/client-profiles/client-a-1/archive"],
      ["POST", "/client-profiles/client-a-1/unarchive"],
      ["DELETE", "/client-profiles/client-a-1"],
    ])
      expect(resolveRequestPolicy(m, p), `${m} ${p}`).toEqual({ kind: "global", permission: "admin" });
    expect(resolveRequestPolicy("GET", "/client-profiles")).toEqual({ kind: "authenticated" });
  });
});
