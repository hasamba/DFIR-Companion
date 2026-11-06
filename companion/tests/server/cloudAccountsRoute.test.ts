import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import {
  awsKeyInput,
  awsRoleInput,
  fakeAwsSecret,
  gcpKeyInput,
  makeCertPem,
  makeGcpKeyJson,
  microsoftPemInput,
} from "../helpers/cloudAccountFixtures.js";

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const USER_PASSWORD = "a different sufficiently long password";

let dir: string;
let keyPath: string;
let vault: CloudAccountVault;
let cases: CaseStore;
let logged: string[];
// Every secret this test hands the vault, and each line of every private key.
let sentinels: string[];

const remember = (...values: string[]): void => void sentinels.push(...values.filter(Boolean));

function captureLogs(): void {
  const logger = getServerLogger();
  const keep = (m: string): void => void logged.push(String(m));
  vi.spyOn(logger, "info").mockImplementation(keep);
  vi.spyOn(logger, "warn").mockImplementation(keep);
  vi.spyOn(logger, "error").mockImplementation(keep);
  vi.spyOn(logger, "debug").mockImplementation(keep);
}

const app = () => createApp(cases, { cloudAccountVault: vault });

function expectNoSecret(text: string, where: string): void {
  for (const s of sentinels) expect(text, `${where} carried a secret`).not.toContain(s);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-route-"));
  keyPath = join(dir, "vault-key", "cloud-vault.key");
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(keyPath));
  cases = new CaseStore(join(dir, "cases"));
  logged = [];
  sentinels = [];
  captureLogs();
});
const authStores: AuthStore[] = [];
afterEach(() => {
  for (const store of authStores.splice(0)) store.close();
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

describe("cloud account policy", () => {
  it("every /cloud-accounts change is global admin; the list and deletes are cut by the route (#2347)", () => {
    for (const [m, p] of [
      ["POST", "/cloud-accounts"],
      ["POST", "/cloud-accounts/reset"],
      ["PUT", "/cloud-accounts/a1"],
    ]) {
      expect(resolveRequestPolicy(m, p), `${m} ${p}`).toEqual({ kind: "global", permission: "admin" });
    }
  });

  it("a team member gets 403 on every change and an empty list; the admin gets through", async () => {
    await cases.createCase({ caseId: "c1", name: "Case c1", investigator: "i", aiProvider: null });
    const store = new AuthStore(join(dir, "auth.sqlite"));
    authStores.push(store);
    const teamApp = createApp(cases, {
      cloudAccountVault: vault,
      teamAuth: new TeamAuth({
        store,
        bootstrapToken: BOOTSTRAP_TOKEN,
        cookieSecure: false,
        sessionTtlMs: 60 * 60_000,
      }),
    });
    const admin = request.agent(teamApp);
    await admin.post("/auth/bootstrap").send({
      bootstrapToken: BOOTSTRAP_TOKEN,
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Admin",
    });
    const adminCsrf = (await admin.get("/auth/me")).body.csrfToken as string;
    await admin
      .post("/auth/users")
      .set("X-DFIR-CSRF", adminCsrf)
      .send({ username: "member", password: USER_PASSWORD, displayName: "Member" });
    const member = request.agent(teamApp);
    await member.post("/auth/local/login").send({ username: "member", password: USER_PASSWORD });
    const csrf = (await member.get("/auth/me")).body.csrfToken as string;
    const secret = fakeAwsSecret();
    remember(secret);
    for (const res of [
      await member.post("/cloud-accounts").set("X-DFIR-CSRF", csrf).send(awsKeyInput("M", secret)),
      await member.post("/cloud-accounts/reset").set("X-DFIR-CSRF", csrf).send({ confirm: true }),
      await member.put("/cloud-accounts/x").set("X-DFIR-CSRF", csrf).send(awsKeyInput("M", secret)),
    ]) {
      expect(res.status).toBe(403);
    }
    // The list answers everyone, cut to the cases they can write (none here); a delete of an
    // account they cannot see is a 404 (#2347).
    const list = await member.get("/cloud-accounts");
    expect(list.status).toBe(200);
    expect(list.body).toMatchObject({ admin: false, accounts: [] });
    expect(list.body.keyPath).toBeUndefined();
    expect((await member.delete("/cloud-accounts/x").set("X-DFIR-CSRF", csrf)).status).toBe(404);
    expect(existsSync(keyPath)).toBe(false);
    const ok = await admin
      .post("/cloud-accounts")
      .set("X-DFIR-CSRF", adminCsrf)
      .send(awsKeyInput("A", secret));
    expect(ok.status).toBe(201);
    expectNoSecret(ok.text, "admin create");
  });
});

describe("cloud account routes", () => {
  it("503 when no vault is wired", async () => {
    const res = await request(createApp(cases)).get("/cloud-accounts");
    expect(res.status).toBe(503);
  });

  it("first add creates the key and tells the analyst to keep it out of data backups", async () => {
    const secret = fakeAwsSecret();
    remember(secret);
    const res = await request(app()).post("/cloud-accounts").send(awsKeyInput("AWS prod", secret));
    expect(res.status).toBe(201);
    expect(res.body.keyCreated).toBe(true);
    expect(res.body.notice).toContain(keyPath);
    expect(res.body.notice).toMatch(/OUT of data-folder backups/);
    expect(res.body.account).toMatchObject({ name: "AWS prod", provider: "aws" });
    expect(res.body.account.storedSecrets).toEqual(["accessKeyId", "secretAccessKey"]);
    expect(logged.some((l) => l.includes("created the vault key") && l.includes(keyPath))).toBe(true);
    const second = await request(app()).post("/cloud-accounts").send(awsKeyInput("AWS dev", fakeAwsSecret()));
    expect(second.body.keyCreated).toBeUndefined();
  });

  it("no secret appears in any response or log line, on every route", async () => {
    const a = app();
    const awsSecret = fakeAwsSecret();
    const externalId = `ext-${fakeAwsSecret().replace(/[^\w]/g, "")}`;
    const keyJson = makeGcpKeyJson();
    const cert = makeCertPem();
    remember(awsSecret, externalId, ...cert.keyLines, cert.pem, keyJson);
    remember(
      ...(JSON.parse(keyJson).private_key as string).split("\n").filter((l) => l && !l.startsWith("-----")),
    );
    const responses: string[] = [];
    const add = async (input: object) => {
      const r = await request(a).post("/cloud-accounts").send(input);
      responses.push(r.text);
      return r;
    };
    const role = await add(awsRoleInput("Role", awsSecret, externalId));
    expect(role.status).toBe(201);
    const gcp = await add(gcpKeyInput("GCP", keyJson));
    expect(gcp.status).toBe(201);
    const ms = await add(microsoftPemInput("Tenant", cert.pem));
    expect(ms.status).toBe(201);
    // Refusals that involve a secret: a wrong-shaped key id, a duplicate name, a bad PEM.
    const badKey = await add({
      ...awsKeyInput("Bad", awsSecret),
      secrets: { accessKeyId: awsSecret, secretAccessKey: awsSecret },
    });
    expect(badKey.status).toBe(400);
    responses.push((await add(awsRoleInput("Role", awsSecret, externalId))).text);
    responses.push((await add(microsoftPemInput("Bad PEM", cert.keyLines.join("\n")))).text);

    const rotated = fakeAwsSecret();
    remember(rotated);
    const roleInput = awsRoleInput("Role 2", "", "");
    const put = await request(a)
      .put(`/cloud-accounts/${role.body.account.id}`)
      .send({ ...roleInput, secrets: { secretAccessKey: rotated } });
    expect(put.status).toBe(200);
    responses.push(put.text);
    responses.push((await request(a).put("/cloud-accounts/nope").send(roleInput)).text);
    const list = await request(a).get("/cloud-accounts");
    expect(list.body.accounts).toHaveLength(3);
    responses.push(list.text);
    const del = await request(a).delete(`/cloud-accounts/${gcp.body.account.id}`);
    expect(del.status).toBe(204);
    responses.push(del.text);
    responses.push((await request(a).post("/cloud-accounts/reset").send({})).text);
    responses.push((await request(a).post("/cloud-accounts/reset").send({ confirm: true })).text);

    for (const [i, text] of responses.entries()) expectNoSecret(text, `response ${i}`);
    expectNoSecret(logged.join("\n"), "server log");
    expect(logged.some((l) => l.includes("cloud-account-created"))).toBe(true);
  });

  it("a missing key: list shows Locked with the path, add refuses with 423, nothing is deleted", async () => {
    await request(app()).post("/cloud-accounts").send(awsKeyInput("AWS", fakeAwsSecret()));
    rmSync(keyPath);
    const list = await request(app()).get("/cloud-accounts");
    expect(list.body.keyState).toBe("missing");
    expect(list.body.keyPath).toBe(keyPath);
    expect(list.body.accounts[0].locked).toBe(`Locked — key file not found at ${keyPath}`);
    const add = await request(app()).post("/cloud-accounts").send(awsKeyInput("New", fakeAwsSecret()));
    expect(add.status).toBe(423);
    expect(add.body.locked).toBe(true);
    const edit = await request(app())
      .put(`/cloud-accounts/${list.body.accounts[0].id}`)
      .send(awsKeyInput("AWS", fakeAwsSecret()));
    expect(edit.status).toBe(423);
    expect((await request(app()).get("/cloud-accounts")).body.accounts).toHaveLength(1);
    expect(existsSync(keyPath)).toBe(false);
  });

  it("Reset vault needs confirm: true, and wipes the accounts but not the key", async () => {
    await request(app()).post("/cloud-accounts").send(awsKeyInput("AWS", fakeAwsSecret()));
    const key = readFileSync(keyPath);
    const refused = await request(app()).post("/cloud-accounts/reset").send({ confirm: "yes" });
    expect(refused.status).toBe(400);
    expect((await request(app()).get("/cloud-accounts")).body.accounts).toHaveLength(1);
    const ok = await request(app()).post("/cloud-accounts/reset").send({ confirm: true });
    expect(ok.body).toEqual({ removed: 1 });
    expect((await request(app()).get("/cloud-accounts")).body.accounts).toEqual([]);
    expect(readFileSync(keyPath).equals(key)).toBe(true);
  });

  it("keeps the store out of every case folder", async () => {
    await cases.createCase({ caseId: "c1", name: "Case", investigator: "i", aiProvider: null });
    const secret = fakeAwsSecret();
    remember(secret);
    await request(app()).post("/cloud-accounts").send(awsKeyInput("AWS", secret));
    const walk = (p: string): string[] =>
      readdirSync(p, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? walk(join(p, e.name)) : [join(p, e.name)],
      );
    for (const f of walk(join(dir, "cases"))) {
      expect(f).not.toMatch(/cloud-accounts|cloud-vault/);
      expectNoSecret(readFileSync(f, "latin1"), f);
    }
  });

  it("the support bundle redacts a cloud secret that reached a log line", async () => {
    const secret = fakeAwsSecret();
    remember(secret);
    await request(app()).post("/cloud-accounts").send(awsKeyInput("AWS", secret));
    const session = join(dir, "session.log");
    writeFileSync(session, `2026-11-06T10:00:00.000Z ERROR sts call failed with ${secret}\n`);
    const logger = getServerLogger();
    const originalPaths = logger.paths;
    logger.paths = () => ({ sessionLogPath: session, debugLog: null });
    try {
      const res = await request(app())
        .post("/diagnostics/support-bundle")
        .send({})
        .buffer(true)
        .parse((r, cb) => {
          const chunks: Buffer[] = [];
          r.on("data", (c: Buffer) => chunks.push(c));
          r.on("end", () => cb(null, Buffer.concat(chunks)));
        });
      expect(res.status).toBe(200);
      const entries = readZip(res.body as Buffer);
      expect(entries.some((e) => Buffer.from(e.data).toString("utf8").includes("sts call failed"))).toBe(
        true,
      );
      for (const e of entries) expectNoSecret(Buffer.from(e.data).toString("utf8"), e.path);
    } finally {
      logger.paths = originalPaths;
    }
  });
});
