import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express } from "express";
import request from "supertest";
import type TestAgent from "supertest/lib/agent.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import type { CaseRole } from "../../src/auth/types.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import {
  awsKeyInput,
  awsRoleInput,
  fakeAwsSecret,
  gcpKeyInput,
  makeGcpKeyJson,
} from "../helpers/cloudAccountFixtures.js";

// #2347: cloud credentials end with the case. Close deletes them (or keeps them, on request), archive
// and delete always do; a shared account is only detached until its last case goes. The cloud
// accounts list shows each analyst what they may see, and every delete leaves an audit entry and a
// custody entry on every attached case — never a secret.

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const PASSWORD = "a different sufficiently long password";

let dir: string;
let vault: CloudAccountVault;
let cases: CaseStore;
let custody: CustodyStore;
let store: AuthStore | undefined;
let logged: string[];
let sentinels: string[];

function secret(): string {
  const s = fakeAwsSecret();
  sentinels.push(s);
  return s;
}

function expectNoSecret(text: string, where: string): void {
  for (const s of sentinels) expect(text, `${where} carried a secret`).not.toContain(s);
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "cloud-lifecycle-"));
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(join(dir, "k", "vault.key")));
  cases = new CaseStore(join(dir, "cases"));
  custody = new CustodyStore(cases);
  for (const id of ["c1", "c2", "c3"])
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

const soloApp = (extra: Record<string, unknown> = {}): Express =>
  createApp(cases, { cloudAccountVault: vault, custodyStore: custody, ...extra });

const close = (app: Express, caseId: string, body: Record<string, unknown> = {}) =>
  request(app)
    .patch(`/cases/${caseId}/status`)
    .send({ status: "closed", ...body });

async function credentialEntries(caseId: string) {
  return (await custody.load(caseId)).filter((r) => r.event === "credential-deleted");
}

async function detachedEntries(caseId: string) {
  return (await custody.load(caseId)).filter((r) => r.event === "credential-detached");
}

const VAULT_DOWN = () => {
  throw new Error("vault write failed");
};

describe("closing a case", () => {
  it("deletes an account only this case used, by default, with a custody entry", async () => {
    const s = secret();
    const sole = vault.create(awsRoleInput("Sole", s, secret()), "c1", {
      id: "u1",
      displayName: "Alice",
    }).account;
    const res = await close(soloApp(), "c1");
    expect(res.status, res.text).toBe(200);
    expect(res.body.status).toBe("closed");
    expect(res.body.cloudCredentials).toEqual({ deleted: 1, detached: 0 });
    expect(vault.list()).toEqual([]);
    expect(readFileSync(join(dir, "cloud-accounts", "accounts.json"), "utf8")).not.toContain(s);
    const [entry, ...rest] = await credentialEntries("c1");
    expect(rest).toEqual([]);
    expect(entry.credential).toMatchObject({
      accountId: sole.id,
      provider: "aws",
      identifier: "account 123456789012",
      addedBy: "Alice",
      addedAt: sole.createdAt,
      reason: "case closed",
    });
    expect(entry.trigger).toContain("case closed");
    expectNoSecret(JSON.stringify(entry), "custody entry");
    expectNoSecret(logged.join("\n"), "server log");
    // A deleted credential has no file: the integrity check must not call it missing.
    expect(await custody.verifyIntegrity("c1")).toEqual([]);
  });

  it("only detaches an account another case shares, and deletes it with its last case", async () => {
    const shared = vault.create(gcpKeyInput("Shared", makeGcpKeyJson()), "c1", {
      id: "u1",
      displayName: "Alice",
    }).account;
    vault.attach(shared.id, "c2");
    const app = soloApp();
    expect((await close(app, "c1")).body.cloudCredentials).toEqual({ deleted: 0, detached: 1 });
    expect(vault.view(shared.id).caseIds).toEqual(["c2"]);
    expect(await credentialEntries("c1")).toEqual([]);
    // The detached case keeps the provenance: which credential its evidence came through.
    const [detached, ...more] = await detachedEntries("c1");
    expect(more).toEqual([]);
    expect(detached.credential).toMatchObject({
      accountId: shared.id,
      provider: "gcp",
      identifier: "project test-project-01",
      addedBy: "Alice",
      addedAt: shared.createdAt,
      collections: [],
      reason: "case closed",
    });
    expect(detached.collectedBy).toBe("analyst");
    expect(detached.trigger).toContain("detached");
    expect(detached.artifactPath).toBe(`cloud-credential:gcp/${shared.id}`);
    expect(await detachedEntries("c2")).toEqual([]);
    expect(await custody.verifyIntegrity("c1")).toEqual([]);
    // No file stands behind it, so an export has nothing to re-hash or to claim it carried.
    expect(await custody.recordExport("c1", { exportedBy: "a", destination: "zip" })).toEqual([]);
    expectNoSecret(JSON.stringify(detached), "detached custody entry");
    expect((await close(app, "c2")).body.cloudCredentials).toEqual({ deleted: 1, detached: 0 });
    expect(vault.list()).toEqual([]);
    const [entry] = await credentialEntries("c2");
    expect(entry.credential?.identifier).toBe("project test-project-01");
  });

  it("keeps the credentials on request, and the list shows the case closed", async () => {
    const a = vault.create(awsKeyInput("Kept", secret()), "c1").account;
    const app = soloApp();
    const res = await close(app, "c1", { cloudCredentials: "keep" });
    expect(res.status).toBe(200);
    expect(res.body.cloudCredentials).toBeUndefined();
    expect(vault.view(a.id).caseIds).toEqual(["c1"]);
    const list = await request(app).get("/cloud-accounts");
    expect(list.body.accounts[0].cases).toEqual([{ caseId: "c1", status: "closed" }]);
  });

  it("refuses an unknown credential choice and changes nothing", async () => {
    vault.create(awsKeyInput("A", secret()), "c1");
    const res = await close(soloApp(), "c1", { cloudCredentials: "maybe" });
    expect(res.status).toBe(400);
    expect(vault.list()).toHaveLength(1);
    expect((await cases.getCaseMeta("c1"))?.status ?? "open").toBe("open");
  });

  it("is blocked while a cloud collection runs, with a clear message", async () => {
    vault.create(awsKeyInput("A", secret()), "c1");
    const jobManager = new JobManager({ perCaseConcurrency: 1 });
    const job = jobManager.register({ caseId: "c1", kind: "cloud-collect", label: "collect" });
    await job.ready;
    const app = soloApp({ jobManager });
    const res = await close(app, "c1");
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/cloud collection is running/i);
    expect(vault.list()).toHaveLength(1);
    const del = await request(app).post("/cases/c1/delete").send({ archiveFirst: "none" });
    expect([400, 409]).toContain(del.status);
    const archive = await request(app).post("/cases/c1/archive").send({ removeFromList: true });
    expect(archive.status).toBe(409);
    await jobManager.finish(job.jobId);
    expect((await close(app, "c1")).status).toBe(200);
  });

  it("records the detach before removing it: a failed custody write leaves the account attached", async () => {
    const shared = vault.create(awsKeyInput("Shared", secret()), "c1").account;
    vault.attach(shared.id, "c2");
    vi.spyOn(custody, "record").mockRejectedValue(new Error("custody disk full"));
    const res = await close(soloApp(), "c1");
    expect(res.status, res.text).toBe(200);
    expect(res.body.cloudCredentialsError).toMatch(/could not be deleted/i);
    expect(vault.view(shared.id).caseIds).toEqual(["c1", "c2"]);
  });

  it("a client cannot submit a credential custody event", async () => {
    const app = soloApp();
    for (const event of ["credential-deleted", "credential-detached"]) {
      const res = await request(app)
        .post("/cases/c1/custody")
        .send({ artifactPath: join(dir, "x"), event });
      expect(res.status, event).toBe(400);
      expect(res.body.error, event).toMatch(/event must be one of/);
    }
    expect(await custody.load("c1")).toEqual([]);
  });

  it("reopening a case does not bring deleted credentials back", async () => {
    vault.create(awsKeyInput("A", secret()), "c1");
    const app = soloApp();
    await close(app, "c1");
    const reopen = await request(app).patch("/cases/c1/status").send({ status: "open" });
    expect(reopen.status).toBe(200);
    expect(vault.listForCase("c1")).toEqual([]);
  });
});

describe("archiving and deleting a case", () => {
  it("archiving (removed from the list) deletes the credentials, kept ones included", async () => {
    vault.create(awsKeyInput("A", secret()), "c1");
    const app = soloApp();
    await close(app, "c1", { cloudCredentials: "keep" });
    const res = await request(app).post("/cases/c1/archive").send({ removeFromList: true });
    expect(res.status, res.text).toBe(200);
    expect(res.body.removedFromList).toBe(true);
    expect(vault.list()).toEqual([]);
    const [entry] = await credentialEntries("c1");
    expect(entry.credential?.reason).toBe("case archived");
  });

  it("deleting a case deletes its own credentials and detaches shared ones", async () => {
    vault.create(awsKeyInput("Own", secret()), "c1");
    const shared = vault.create(awsKeyInput("Shared", secret()), "c1").account;
    vault.attach(shared.id, "c2");
    const app = soloApp();
    await close(app, "c1", { cloudCredentials: "keep" });
    const res = await request(app).post("/cases/c1/delete").send({ archiveFirst: "none" });
    expect(res.status, res.text).toBe(200);
    expect(res.body.deleted).toBe(true);
    expect(res.body.cloudCredentials).toEqual({ deleted: 1, detached: 1 });
    expect(vault.list().map((a) => [a.name, a.caseIds])).toEqual([["Shared", ["c2"]]]);
  });
});

describe("a credential release that fails", () => {
  // The credentials go first, so a failed release leaves the case exactly where it was: closed, in the
  // active list, with its credentials. The analyst can retry.
  async function closedWithKeptCredentials() {
    const a = vault.create(awsKeyInput("A", secret()), "c1").account;
    const app = soloApp();
    expect((await close(app, "c1", { cloudCredentials: "keep" })).status).toBe(200);
    vi.spyOn(vault, "releaseCase").mockImplementation(VAULT_DOWN);
    return { app, a };
  }

  async function expectCaseLeftInPlace(accountId: string) {
    expect((await cases.getCaseMeta("c1"))?.status).toBe("closed");
    expect(cases.isInArchive("c1")).toBe(false);
    expect(vault.view(accountId).caseIds).toEqual(["c1"]);
    expect(await credentialEntries("c1")).toEqual([]);
  }

  it("archive builds the ZIP but does not remove the case from the list", async () => {
    const { app, a } = await closedWithKeptCredentials();
    const res = await request(app).post("/cases/c1/archive").send({ removeFromList: true });
    expect(res.status, res.text).toBe(200);
    expect(res.body.removedFromList).toBe(false);
    expect(res.body.removeFromListError).toMatch(/credentials could not be deleted.*left in place/i);
    await expectCaseLeftInPlace(a.id);
  });

  it("encrypted export does not remove the case from the list", async () => {
    const { app, a } = await closedWithKeptCredentials();
    const res = await request(app)
      .post("/cases/c1/export/encrypted")
      .send({ password: PASSWORD, removeFromList: true });
    expect(res.status, res.text).toBe(200);
    expect(res.headers["x-case-removed-from-list"]).toBe("false");
    expect(res.headers["x-case-remove-error"]).toBe("cloud-credentials");
    await expectCaseLeftInPlace(a.id);
  });

  it("plain delete refuses and deletes nothing", async () => {
    const { app, a } = await closedWithKeptCredentials();
    const res = await request(app).post("/cases/c1/delete").send({ archiveFirst: "none" });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/credentials could not be deleted.*left in place/i);
    expect(await cases.caseExists("c1")).toBe(true);
    await expectCaseLeftInPlace(a.id);
  });

  it("encrypted delete refuses with a JSON error, never an archive download", async () => {
    const { app, a } = await closedWithKeptCredentials();
    const res = await request(app)
      .post("/cases/c1/delete")
      .send({ archiveFirst: "encrypted", password: PASSWORD });
    expect(res.status).toBe(500);
    expect(res.headers["content-type"]).toMatch(/json/);
    expect(res.body.error).toMatch(/credentials could not be deleted/i);
    expect(await cases.caseExists("c1")).toBe(true);
    await expectCaseLeftInPlace(a.id);
  });
});

describe("an invalid delete request", () => {
  it("is refused before any credential changes: vault and custody log untouched", async () => {
    const own = vault.create(awsKeyInput("Own", secret()), "c1").account;
    const shared = vault.create(awsKeyInput("Shared", secret()), "c1").account;
    vault.attach(shared.id, "c2");
    const app = soloApp();
    await close(app, "c1", { cloudCredentials: "keep" });
    const before = await custody.load("c1");
    const vaultBefore = vault.list();
    for (const body of [
      { archiveFirst: "encrypted", password: "short" },
      { archiveFirst: "encrypted" },
      { archiveFirst: "bogus" },
    ]) {
      const res = await request(app).post("/cases/c1/delete").send(body);
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
    expect(vault.list()).toEqual(vaultBefore);
    expect(vault.view(own.id).caseIds).toEqual(["c1"]);
    expect(await custody.load("c1")).toEqual(before);
    expect(await cases.caseExists("c1")).toBe(true);
  });
});

describe("the cloud accounts list (team mode)", () => {
  type Agent = { agent: TestAgent<request.Test>; csrf: string };

  async function login(app: Express, username: string, password: string): Promise<Agent> {
    const agent = request.agent(app);
    await agent.post("/auth/local/login").send({ username, password });
    return { agent, csrf: (await agent.get("/auth/me")).body.csrfToken as string };
  }

  async function team(users: Record<string, Partial<Record<string, CaseRole>>>) {
    const auth = new AuthStore(join(dir, "auth.sqlite"));
    store = auth;
    const teamAuth = new TeamAuth({
      store: auth,
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 3_600_000,
    });
    const app = createApp(cases, { cloudAccountVault: vault, custodyStore: custody, teamAuth });
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
    return { app, agents, auth };
  }

  const names = (body: { accounts: { name: string }[] }) => body.accounts.map((a) => a.name).sort();

  it("an analyst sees the accounts of cases they write; the admin sees all, unattached included", async () => {
    const { agents } = await team({ alice: { c1: "investigator", c2: "reader" } });
    const added = await agents.alice.agent
      .post("/cases/c1/cloud-accounts")
      .set("X-DFIR-CSRF", agents.alice.csrf)
      .send(awsKeyInput("Mine", secret()));
    expect(added.status).toBe(201);
    const shared = vault.create(awsKeyInput("Shared", secret()), "c1").account;
    vault.attach(shared.id, "c3");
    vault.create(awsKeyInput("Read only", secret()), "c2");
    vault.create(awsKeyInput("Leftover", secret()));

    const mine = await agents.alice.agent.get("/cloud-accounts");
    expect(mine.status).toBe(200);
    expect(mine.body.admin).toBe(false);
    expect(names(mine.body)).toEqual(["Mine", "Shared"]);
    const sharedRow = mine.body.accounts.find((a: { name: string }) => a.name === "Shared");
    expect(sharedRow.caseIds).toEqual(["c1"]);
    expect(sharedRow.otherCases).toBe(1);
    expect(JSON.stringify(sharedRow)).not.toContain("c3");
    const mineRow = mine.body.accounts.find((a: { name: string }) => a.name === "Mine");
    expect(mineRow.createdBy.displayName).toBe("alice");
    expect(mineRow.cases).toEqual([{ caseId: "c1", status: "open" }]);
    expectNoSecret(mine.text, "analyst list");

    const all = await agents.admin.agent.get("/cloud-accounts");
    expect(all.body.admin).toBe(true);
    expect(names(all.body)).toEqual(["Leftover", "Mine", "Read only", "Shared"]);
    expect(all.body.accounts.find((a: { name: string }) => a.name === "Leftover").caseIds).toEqual([]);
    expectNoSecret(all.text, "admin list");
  });

  it("only the admin may delete an unattached account; a shared one needs write on every case", async () => {
    const { agents } = await team({ alice: { c1: "investigator" } });
    const leftover = vault.create(awsKeyInput("Leftover", secret())).account;
    const shared = vault.create(awsKeyInput("Shared", secret()), "c1").account;
    vault.attach(shared.id, "c3");
    const { agent, csrf } = agents.alice;
    expect((await agent.delete(`/cloud-accounts/${leftover.id}`).set("X-DFIR-CSRF", csrf)).status).toBe(404);
    const refused = await agent
      .post("/cloud-accounts/delete")
      .set("X-DFIR-CSRF", csrf)
      .send({ ids: [shared.id] });
    expect(refused.status).toBe(403);
    expect(refused.text).not.toContain("c3");
    expect(vault.list()).toHaveLength(2);
    const ok = await agents.admin.agent
      .delete(`/cloud-accounts/${leftover.id}`)
      .set("X-DFIR-CSRF", agents.admin.csrf);
    expect(ok.status).toBe(204);
    expect(vault.list().map((a) => a.name)).toEqual(["Shared"]);
  });

  it("multi-delete erases every picked account, all or none, with audit and custody entries", async () => {
    const { agents, auth } = await team({ alice: { c1: "investigator", c2: "investigator" } });
    const a = vault.create(awsKeyInput("A", secret()), "c1").account;
    const b = vault.create(awsKeyInput("B", secret()), "c1").account;
    vault.attach(b.id, "c2");
    const other = vault.create(awsKeyInput("Other", secret()), "c3").account;
    const { agent, csrf } = agents.alice;

    // One account she cannot see: nothing is deleted.
    const none = await agent
      .post("/cloud-accounts/delete")
      .set("X-DFIR-CSRF", csrf)
      .send({ ids: [a.id, other.id] });
    expect(none.status).toBe(404);
    expect(vault.list()).toHaveLength(3);

    const res = await agent
      .post("/cloud-accounts/delete")
      .set("X-DFIR-CSRF", csrf)
      .send({ ids: [a.id, b.id] });
    expect(res.status, res.text).toBe(200);
    expect(res.body.deleted).toBe(2);
    expect(vault.list().map((x) => x.name)).toEqual(["Other"]);
    expect((await credentialEntries("c1")).map((e) => e.credential?.accountId).sort()).toEqual(
      [a.id, b.id].sort(),
    );
    expect((await credentialEntries("c2")).map((e) => e.credential?.accountId)).toEqual([b.id]);
    const entry = (await credentialEntries("c2"))[0];
    expect(entry.collectedBy).toBe("alice");
    expect(entry.credential?.reason).toBe("deleted from the list");
    const audits = auth.listAudit(200).filter((r) => r.action === "cloud-account-deleted");
    expect(audits.map((r) => r.targetId).sort()).toEqual([a.id, b.id].sort());
    expectNoSecret(JSON.stringify(audits), "audit");
    expectNoSecret(JSON.stringify(await custody.load("c1")), "custody");
  });

  it("refuses a malformed multi-delete", async () => {
    const { agents } = await team({});
    const { agent, csrf } = agents.admin;
    for (const body of [{}, { ids: [] }, { ids: ["../x"] }, { ids: "a" }])
      expect((await agent.post("/cloud-accounts/delete").set("X-DFIR-CSRF", csrf).send(body)).status).toBe(
        400,
      );
  });
});

describe("demo mode", () => {
  it("keeps the list and every delete disabled", async () => {
    const a = vault.create(awsKeyInput("A", secret()), "c1").account;
    const app = soloApp({ demoMode: true });
    expect((await request(app).get("/cloud-accounts")).status).toBe(403);
    expect(
      (
        await request(app)
          .post("/cloud-accounts/delete")
          .send({ ids: [a.id] })
      ).status,
    ).toBe(403);
    expect(vault.list()).toHaveLength(1);
  });
});
