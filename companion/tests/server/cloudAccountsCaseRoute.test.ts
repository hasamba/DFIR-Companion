import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express, Request } from "express";
import request from "supertest";
import type TestAgent from "supertest/lib/agent.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import type { CaseRole } from "../../src/auth/types.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { openCloudAccountForCollect } from "../../src/routes/cloudAccountAccess.js";
import type { RouteContext } from "../../src/routes/context.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";

// #2308: cloud accounts per case. Any writer of a case may add and use its accounts; no one sees or
// touches them without write on that case; a shared credential is edited only by a writer of every
// attached case; a detach touches only the current case; the demo has no cloud routes at all.

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const PASSWORD = "a different sufficiently long password";

let dir: string;
let vault: CloudAccountVault;
let cases: CaseStore;
let store: AuthStore | undefined;
let logged: string[];
let sentinels: string[];

type Agent = { agent: TestAgent<request.Test>; csrf: string };

function expectNoSecret(text: string, where: string): void {
  for (const s of sentinels) expect(text, `${where} carried a secret`).not.toContain(s);
}

function secret(): string {
  const s = fakeAwsSecret();
  sentinels.push(s);
  return s;
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "cloud-case-route-"));
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(join(dir, "k", "vault.key")));
  cases = new CaseStore(join(dir, "cases"));
  for (const id of ["c1", "c2"])
    await cases.createCase({ caseId: id, name: `Case ${id}`, investigator: "i", aiProvider: null });
  logged = [];
  sentinels = [];
  const logger = getServerLogger();
  const keep = (m: string): void => void logged.push(String(m));
  vi.spyOn(logger, "info").mockImplementation(keep);
  vi.spyOn(logger, "warn").mockImplementation(keep);
  vi.spyOn(logger, "error").mockImplementation(keep);
  vi.spyOn(logger, "debug").mockImplementation(keep);
});
afterEach(() => {
  store?.close();
  store = undefined;
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

async function login(app: Express, username: string, password: string): Promise<Agent> {
  const agent = request.agent(app);
  await agent.post("/auth/local/login").send({ username, password });
  return { agent, csrf: (await agent.get("/auth/me")).body.csrfToken as string };
}

/** Team mode with an admin, and users holding the given roles per case. */
async function team(users: Record<string, Partial<Record<string, CaseRole>>>) {
  const auth = new AuthStore(join(dir, "auth.sqlite"));
  store = auth;
  const app = createApp(cases, {
    cloudAccountVault: vault,
    teamAuth: new TeamAuth({
      store: auth,
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 3_600_000,
    }),
  });
  const admin = await auth.bootstrapLocalAdministrator({
    username: "admin",
    displayName: "Admin",
    password: "correct horse battery staple",
  });
  const agents: Record<string, Agent> = {};
  for (const [username, roles] of Object.entries(users)) {
    const who = await auth.createLocalIdentity(
      { username, password: PASSWORD, displayName: username },
      admin,
    );
    for (const [caseId, role] of Object.entries(roles))
      auth.setCaseRole(caseId, who.id, role as CaseRole, admin);
    agents[username] = await login(app, username, PASSWORD);
  }
  agents.admin = await login(app, "admin", "correct horse battery staple");
  return { app, agents };
}

async function add(a: Agent, caseId: string, name: string): Promise<string> {
  const res = await a.agent
    .post(`/cases/${caseId}/cloud-accounts`)
    .set("X-DFIR-CSRF", a.csrf)
    .send(awsKeyInput(name, secret()));
  expect(res.status, res.text).toBe(201);
  expectNoSecret(res.text, "create");
  return res.body.account.id as string;
}

describe("cloud accounts per case (team mode)", () => {
  it("a case writer adds and lists; a reader and a stranger get no list", async () => {
    const { agents } = await team({
      alice: { c1: "investigator" },
      rita: { c1: "reader" },
      sam: { c2: "investigator" },
    });
    const { alice, rita, sam } = agents;
    const id = await add(alice, "c1", "AWS prod");
    const list = await alice.agent.get("/cases/c1/cloud-accounts");
    expect(list.status).toBe(200);
    expect(list.body.accounts.map((a: { id: string }) => a.id)).toEqual([id]);
    expect(list.body.accounts[0].caseIds).toEqual(["c1"]);
    expect(list.body.keyPath).toBeUndefined();
    expectNoSecret(list.text, "list");
    expect((await rita.agent.get("/cases/c1/cloud-accounts")).status).toBe(403);
    expect((await rita.agent.get(`/cases/c1/cloud-accounts/${id}`)).status).toBe(403);
    expect((await sam.agent.get("/cases/c1/cloud-accounts")).status).toBe(404);
    expect((await sam.agent.get("/cases/c2/cloud-accounts")).body.accounts).toEqual([]);
  });

  it("refuses cross-case list, read, use, edit, delete and attach with 404", async () => {
    const { agents } = await team({
      alice: { c1: "investigator", c2: "investigator" },
      bob: { c1: "investigator" },
    });
    const { alice, bob } = agents;
    const id = await add(alice, "c2", "Only c2");
    expect((await bob.agent.get("/cases/c1/cloud-accounts")).body.accounts).toEqual([]);
    const tries = [
      await bob.agent.get(`/cases/c1/cloud-accounts/${id}`),
      await bob.agent
        .put(`/cases/c1/cloud-accounts/${id}`)
        .set("X-DFIR-CSRF", bob.csrf)
        .send(awsKeyInput("X", "")),
      await bob.agent.delete(`/cases/c1/cloud-accounts/${id}`).set("X-DFIR-CSRF", bob.csrf),
      await bob.agent.post(`/cases/c1/cloud-accounts/${id}/detach`).set("X-DFIR-CSRF", bob.csrf),
      await bob.agent
        .post(`/cases/c1/cloud-accounts/${id}/attach`)
        .set("X-DFIR-CSRF", bob.csrf)
        .send({ caseId: "c1" }),
      await bob.agent.get(`/cases/c2/cloud-accounts/${id}`),
    ];
    for (const res of tries) expect(res.status, res.text).toBe(404);
    expect(vault.view(id).caseIds).toEqual(["c2"]);
    expect(vault.list()).toHaveLength(1);
  });

  it("attaching needs write on both cases", async () => {
    const { agents } = await team({
      alice: { c1: "investigator", c2: "investigator" },
      bob: { c1: "investigator", c2: "reader" },
    });
    const { alice, bob } = agents;
    const id = await add(bob, "c1", "Bob's");
    const refused = await bob.agent
      .post(`/cases/c1/cloud-accounts/${id}/attach`)
      .set("X-DFIR-CSRF", bob.csrf)
      .send({ caseId: "c2" });
    expect(refused.status).toBe(404);
    for (const bad of ["../x", "c1/../c2", ""]) {
      const res = await alice.agent
        .post(`/cases/c1/cloud-accounts/${id}/attach`)
        .set("X-DFIR-CSRF", alice.csrf)
        .send({ caseId: bad });
      expect(res.status, bad).toBe(400);
    }
    expect(vault.view(id).caseIds).toEqual(["c1"]);
    const ok = await alice.agent
      .post(`/cases/c1/cloud-accounts/${id}/attach`)
      .set("X-DFIR-CSRF", alice.csrf)
      .send({ caseId: "c2" });
    expect(ok.status).toBe(200);
    expect(ok.body.account.caseIds).toEqual(["c1", "c2"]);
    expect((await alice.agent.get("/cases/c2/cloud-accounts")).body.accounts).toHaveLength(1);
  });

  it("refuses a shared-credential edit or delete unless the user writes every attached case", async () => {
    const { agents } = await team({
      alice: { c1: "investigator", c2: "investigator" },
      bob: { c1: "investigator" },
    });
    const { alice, bob } = agents;
    const id = await add(alice, "c1", "Shared");
    await alice.agent
      .post(`/cases/c1/cloud-accounts/${id}/attach`)
      .set("X-DFIR-CSRF", alice.csrf)
      .send({ caseId: "c2" });
    // Bob sees it from c1, but not the case he cannot write.
    const seen = await bob.agent.get(`/cases/c1/cloud-accounts/${id}`);
    expect(seen.status).toBe(200);
    expect(seen.body.account.caseIds).toEqual(["c1"]);
    expect(seen.body.account.otherCases).toBe(1);
    const put = await bob.agent
      .put(`/cases/c1/cloud-accounts/${id}`)
      .set("X-DFIR-CSRF", bob.csrf)
      .send(awsKeyInput("Renamed by bob", secret()));
    expect(put.status).toBe(403);
    expect(put.body.error).toMatch(/shared with 1 other case/);
    expect(put.body.error).not.toContain("c2");
    const del = await bob.agent.delete(`/cases/c1/cloud-accounts/${id}`).set("X-DFIR-CSRF", bob.csrf);
    expect(del.status).toBe(403);
    expect(vault.view(id).name).toBe("Shared");
    const ok = await alice.agent
      .put(`/cases/c1/cloud-accounts/${id}`)
      .set("X-DFIR-CSRF", alice.csrf)
      .send(awsKeyInput("Renamed", secret()));
    expect(ok.status).toBe(200);
    expect(ok.body.account.caseIds).toEqual(["c1", "c2"]);
    expectNoSecret(ok.text, "edit");
    expect(
      (await alice.agent.delete(`/cases/c1/cloud-accounts/${id}`).set("X-DFIR-CSRF", alice.csrf)).status,
    ).toBe(204);
    expect(vault.list()).toEqual([]);
  });

  it("refuses an attach whose source case was detached while the target lookup was pending", async () => {
    const { agents } = await team({ alice: { c1: "investigator", c2: "investigator" } });
    const { alice } = agents;
    const id = await add(alice, "c1", "Raced");
    const realExists = cases.caseExists.bind(cases);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let pending!: () => void;
    const started = new Promise<void>((r) => (pending = r));
    vi.spyOn(cases, "caseExists").mockImplementation(async (caseId: string) => {
      if (caseId === "c2") {
        pending();
        await gate;
      }
      return realExists(caseId);
    });
    const attach = alice.agent
      .post(`/cases/c1/cloud-accounts/${id}/attach`)
      .set("X-DFIR-CSRF", alice.csrf)
      .send({ caseId: "c2" })
      .then((r) => r);
    await started;
    vault.detach(id, "c1");
    release();
    const res = await attach;
    expect(res.status).toBe(404);
    expect(vault.view(id).caseIds).toEqual([]);
  });

  it("a name used only in a case the user cannot write does not change their create", async () => {
    const { agents } = await team({ alice: { c1: "investigator" }, sam: { c2: "investigator" } });
    const { alice, sam } = agents;
    await add(sam, "c2", "AWS prod");
    // Same label in an unrelated case: created, no 409 that would reveal the hidden account.
    const id = await add(alice, "c1", "AWS prod");
    expect(vault.view(id).caseIds).toEqual(["c1"]);
    const clash = await alice.agent
      .post("/cases/c1/cloud-accounts")
      .set("X-DFIR-CSRF", alice.csrf)
      .send(awsKeyInput("aws PROD", secret()));
    expect(clash.status).toBe(409);
  });

  it("a detach leaves the other cases intact", async () => {
    const { agents } = await team({
      alice: { c1: "investigator", c2: "investigator" },
      bob: { c1: "investigator" },
    });
    const { alice, bob } = agents;
    const id = await add(alice, "c1", "Shared");
    await alice.agent
      .post(`/cases/c1/cloud-accounts/${id}/attach`)
      .set("X-DFIR-CSRF", alice.csrf)
      .send({ caseId: "c2" });
    const res = await bob.agent.post(`/cases/c1/cloud-accounts/${id}/detach`).set("X-DFIR-CSRF", bob.csrf);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ detached: true, otherCases: 1 });
    expect((await bob.agent.get("/cases/c1/cloud-accounts")).body.accounts).toEqual([]);
    const c2 = await alice.agent.get("/cases/c2/cloud-accounts");
    expect(c2.body.accounts.map((a: { id: string }) => a.id)).toEqual([id]);
    expect(c2.body.accounts[0].caseIds).toEqual(["c2"]);
  });

  it("the instance admin sees every account with its cases, never a secret; attaches an old one", async () => {
    const { agents } = await team({ alice: { c1: "investigator" } });
    const { alice, admin } = agents;
    await add(alice, "c1", "In c1");
    // An account stored before #2308 has no case.
    const old = vault.create(awsKeyInput("Before 2308", secret())).account;
    expect((await alice.agent.get("/cases/c1/cloud-accounts")).body.accounts).toHaveLength(1);
    // Since #2347 an analyst's list holds only the accounts of cases they write — never unattached ones.
    const mine = await alice.agent.get("/cloud-accounts");
    expect(mine.status).toBe(200);
    expect(mine.body.accounts.map((a: { name: string }) => a.name)).toEqual(["In c1"]);
    const all = await admin.agent.get("/cloud-accounts");
    expect(all.status).toBe(200);
    expect(all.body.accounts.map((a: { name: string; caseIds: string[] }) => [a.name, a.caseIds])).toEqual([
      ["In c1", ["c1"]],
      ["Before 2308", []],
    ]);
    expectNoSecret(all.text, "admin list");
    const attach = await admin.agent
      .post(`/cloud-accounts/${old.id}/attach`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId: "c1" });
    expect(attach.status).toBe(200);
    expect((await alice.agent.get("/cases/c1/cloud-accounts")).body.accounts).toHaveLength(2);
    const missing = await admin.agent
      .post(`/cloud-accounts/${old.id}/attach`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId: "nope" });
    expect(missing.status).toBe(404);
    const traversal = await admin.agent
      .post(`/cloud-accounts/${old.id}/attach`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId: "../.." });
    expect(traversal.status).toBe(400);
  });

  it("the audit log records add, edit, attach, detach and delete per case, with no secret", async () => {
    const { agents } = await team({ alice: { c1: "investigator", c2: "investigator" } });
    const { alice } = agents;
    const id = await add(alice, "c1", "Audited");
    const h = { "X-DFIR-CSRF": alice.csrf };
    await alice.agent.put(`/cases/c1/cloud-accounts/${id}`).set(h).send(awsKeyInput("Audited", secret()));
    await alice.agent.post(`/cases/c1/cloud-accounts/${id}/attach`).set(h).send({ caseId: "c2" });
    await alice.agent.post(`/cases/c2/cloud-accounts/${id}/detach`).set(h);
    await alice.agent.delete(`/cases/c1/cloud-accounts/${id}`).set(h);
    const rows = store!.listAudit().filter((r) => r.action.startsWith("cloud-account-"));
    expect(rows.map((r) => [r.action, r.caseId]).reverse()).toEqual([
      ["cloud-account-created", "c1"],
      ["cloud-account-updated", "c1"],
      ["cloud-account-attached", "c2"],
      ["cloud-account-detached", "c2"],
      ["cloud-account-deleted", "c1"],
    ]);
    expect(rows.every((r) => r.targetId === id && r.actorDisplayName === "alice")).toBe(true);
    expectNoSecret(JSON.stringify(rows), "audit log");
    expectNoSecret(logged.join("\n"), "server log");
  });
});

describe("cloud accounts per case (single-user mode)", () => {
  it("still scopes by attachment: an account of c1 is not listed or found under c2", async () => {
    const app = createApp(cases, { cloudAccountVault: vault });
    const res = await request(app).post("/cases/c1/cloud-accounts").send(awsKeyInput("C1", secret()));
    expect(res.status).toBe(201);
    const id = res.body.account.id as string;
    expect((await request(app).get("/cases/c2/cloud-accounts")).body.accounts).toEqual([]);
    expect((await request(app).get(`/cases/c2/cloud-accounts/${id}`)).status).toBe(404);
    expect(
      (await request(app).post("/cases/nope/cloud-accounts").send(awsKeyInput("N", secret()))).status,
    ).toBe(404);
  });

  it("opens an account for collect only from an attached case, and audits the collect", async () => {
    const id = vault.create(awsKeyInput("Collect", secret()), "c1").account.id;
    const ctx = (demoMode = false) =>
      ({
        options: { cloudAccountVault: vault, demoMode },
        store: cases,
        serverLogger: getServerLogger(),
      }) as unknown as RouteContext;
    const req = {} as Request;
    const ok = openCloudAccountForCollect(ctx(), req, "c1", id);
    expect(ok.ok && ok.value.provider).toBe("aws");
    expect(logged.some((l) => l.includes("cloud-account-collect") && l.includes('case="c1"'))).toBe(true);
    expect(openCloudAccountForCollect(ctx(), req, "c2", id)).toMatchObject({ ok: false, status: 404 });
    expect(openCloudAccountForCollect(ctx(true), req, "c1", id)).toMatchObject({ ok: false, status: 403 });
    expectNoSecret(logged.join("\n"), "server log");
  });
});

describe("cloud accounts on the public demo", () => {
  it("every cloud route returns 403, GET included", async () => {
    const id = vault.create(awsKeyInput("Demo", secret()), "c1").account.id;
    const app = createApp(cases, { cloudAccountVault: vault, demoMode: true });
    const gets = [
      "/cloud-accounts",
      "/CLOUD-ACCOUNTS/",
      "/cases/c1/cloud-accounts",
      `/cases/c1/cloud-accounts/${id}`,
      "/cases/c1/cloud-collect",
    ];
    for (const p of gets) {
      const res = await request(app).get(p);
      expect(res.status, p).toBe(403);
      expect(res.body.demo, p).toBe(true);
      expectNoSecret(res.text, p);
    }
    const posts = await request(app).post("/cases/c1/cloud-accounts").send(awsKeyInput("D", secret()));
    expect(posts.status).toBe(403);
    // Other GETs still pass the demo gate.
    expect((await request(app).get("/cases/c1/cloud-coverage")).status).not.toBe(403);
  });
});
