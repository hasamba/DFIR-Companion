import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { cloudAccountStoreDir } from "../../src/integrations/cloudAccounts/storePath.js";
import {
  awsKeyInput,
  awsRoleInput,
  fakeAwsSecret,
  gcpKeyInput,
  makeCertPem,
  makeGcpKeyJson,
  makePfxBase64,
  microsoftPemInput,
} from "../helpers/cloudAccountFixtures.js";

// Assembled at runtime so the secret scanner does not read a PEM header in the source.
const KEY_MARKER = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");

let dir: string;
let keyPath: string;
let vault: CloudAccountVault;

const newVault = (storeDir = join(dir, "data", "cloud-accounts"), key = keyPath) =>
  new CloudAccountVault(storeDir, new VaultKeyFile(key));

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-vault-"));
  keyPath = join(dir, "keydir", "cloud-vault.key");
  vault = newVault();
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("cloud account store path", () => {
  it("sits beside the cases root, next to server-sets, never in a case folder", () => {
    expect(cloudAccountStoreDir(join("/data", "cases"))).toBe(join("/data", "cloud-accounts"));
  });
});

describe("cloud account vault", () => {
  it("creates the key on first use and round-trips every provider's secrets", () => {
    const awsSecret = fakeAwsSecret();
    const keyJson = makeGcpKeyJson();
    const { pem } = makeCertPem();
    expect(existsSync(keyPath)).toBe(false);
    const first = vault.create(awsKeyInput("AWS prod", awsSecret));
    expect(first.keyCreated).toBe(true);
    expect(existsSync(keyPath)).toBe(true);
    const gcp = vault.create(gcpKeyInput("GCP lab", keyJson));
    expect(gcp.keyCreated).toBe(false);
    const ms = vault.create(microsoftPemInput("Tenant", pem));

    expect(vault.open(first.account.id).secrets).toMatchObject({ secretAccessKey: awsSecret });
    expect(vault.open(gcp.account.id).secrets).toEqual({ serviceAccountKeyJson: keyJson });
    expect(vault.open(ms.account.id).secrets).toEqual({ certificatePem: pem });
    expect(gcp.account.settings).toMatchObject({ clientEmail: expect.stringContaining("@") });
    expect(ms.account.settings).toMatchObject({
      certificateThumbprint: expect.stringMatching(/^[0-9A-F]{40}$/),
    });
  });

  it("keeps secrets sealed on disk: accounts.json holds none of them", () => {
    const awsSecret = fakeAwsSecret();
    const { pem, keyLines } = makeCertPem();
    vault.create(awsKeyInput("AWS", awsSecret));
    vault.create(microsoftPemInput("Tenant", pem));
    const disk = readFileSync(join(dir, "data", "cloud-accounts", "accounts.json"), "utf8");
    expect(disk).not.toContain(awsSecret);
    for (const line of keyLines) expect(disk).not.toContain(line);
  });

  it.skipIf(process.platform === "win32")("writes accounts.json with mode 0600", () => {
    vault.create(awsKeyInput("AWS", fakeAwsSecret()));
    expect(statSync(join(dir, "data", "cloud-accounts", "accounts.json")).mode & 0o777).toBe(0o600);
  });

  it("a data-folder copy without the key file cannot decrypt", () => {
    const awsSecret = fakeAwsSecret();
    const made = vault.create(awsKeyInput("AWS", awsSecret)).account;
    const stolen = join(dir, "stolen", "cloud-accounts");
    cpSync(join(dir, "data", "cloud-accounts"), stolen, { recursive: true });
    // The thief's machine has its own (or no) key: neither opens the copy.
    const noKey = newVault(stolen, join(dir, "thief", "none.key"));
    expect(noKey.list()[0].locked).toMatch(/^Locked — key file not found at /);
    expect(() => noKey.open(made.id)).toThrow(/Locked/);
    const otherKey = join(dir, "thief", "own.key");
    new VaultKeyFile(otherKey).create();
    const wrong = newVault(stolen, otherKey);
    expect(wrong.list()[0].locked).toMatch(/does not open this account/);
    expect(() => wrong.open(made.id)).toThrow(/Locked/);
    expect(wrong.secretValues()).toEqual([]);
  });

  it("a missing key shows Locked with the path and deletes nothing", () => {
    vault.create(awsKeyInput("AWS", fakeAwsSecret()));
    vault.create(gcpKeyInput("GCP", makeGcpKeyJson()));
    rmSync(keyPath);
    const listed = vault.list();
    expect(listed).toHaveLength(2);
    for (const a of listed) expect(a.locked).toBe(`Locked — key file not found at ${keyPath}`);
    expect(vault.status()).toEqual({ keyPath, keyState: "missing", accounts: 2 });
    // Adding another account must not mint a new key that would orphan the stored two.
    expect(() => vault.create(awsKeyInput("Another", fakeAwsSecret()))).toThrow(/key file not found/);
    expect(existsSync(keyPath)).toBe(false);
    expect(vault.list()).toHaveLength(2);
  });

  it("a restored key file unlocks the accounts with no restart", () => {
    const made = vault.create(awsKeyInput("AWS", fakeAwsSecret())).account;
    const saved = readFileSync(keyPath);
    rmSync(keyPath);
    expect(vault.list()[0].locked).toBeTruthy();
    writeFileSync(keyPath, saved);
    expect(vault.list()[0].locked).toBeUndefined();
    expect(vault.open(made.id).secrets).toBeTruthy();
  });

  it("reset wipes the accounts only, and the next account reuses the existing key", () => {
    vault.create(awsKeyInput("AWS", fakeAwsSecret()));
    const keyBefore = readFileSync(keyPath);
    rmSync(keyPath);
    expect(vault.reset()).toBe(1);
    expect(vault.list()).toEqual([]);
    // With the store empty, first use makes a fresh key.
    expect(vault.create(awsKeyInput("AWS", fakeAwsSecret())).keyCreated).toBe(true);
    expect(readFileSync(keyPath).equals(keyBefore)).toBe(false);
    const keyNow = readFileSync(keyPath);
    expect(vault.reset()).toBe(1);
    expect(readFileSync(keyPath).equals(keyNow)).toBe(true);
  });

  it("delete overwrites the sealed entry and needs no key", () => {
    const a = vault.create(awsKeyInput("AWS", fakeAwsSecret())).account;
    const b = vault.create(awsKeyInput("Other", fakeAwsSecret())).account;
    rmSync(keyPath);
    expect(vault.remove(a.id)).toEqual({ id: a.id, name: "AWS", provider: "aws" });
    expect(vault.list().map((x) => x.id)).toEqual([b.id]);
    expect(() => vault.remove(a.id)).toThrow(/not found/);
  });

  it("edit keeps a secret the request leaves out, and replaces one it sends (rotation)", () => {
    const oldSecret = fakeAwsSecret();
    const made = vault.create(awsRoleInput("Role", oldSecret, "ext-id-1234")).account;
    const keep = vault.update(made.id, { ...awsRoleInput("Role renamed", "", ""), secrets: {} });
    expect(keep.name).toBe("Role renamed");
    expect(keep.revision).toBe(2);
    expect(vault.open(made.id).secrets).toMatchObject({
      secretAccessKey: oldSecret,
      externalId: "ext-id-1234",
    });
    const rotated = fakeAwsSecret();
    vault.update(made.id, { ...awsRoleInput("Role renamed", "", ""), secrets: { secretAccessKey: rotated } });
    expect(vault.open(made.id).secrets).toMatchObject({ secretAccessKey: rotated });
  });

  it("switching to an ambient base credential drops the stored access key", () => {
    const made = vault.create(awsRoleInput("Role", fakeAwsSecret(), "ext-id-1234")).account;
    const input = awsRoleInput("Role", "", "");
    const view = vault.update(made.id, {
      ...input,
      settings: { ...input.settings, baseCredential: "ambient" },
      secrets: {},
    });
    expect(view.storedSecrets).toEqual(["externalId"]);
    expect(vault.open(made.id).secrets).toEqual({ externalId: "ext-id-1234" });
  });

  it("refuses a duplicate name, a provider change, and a session over one hour", () => {
    const made = vault.create(awsKeyInput("AWS", fakeAwsSecret())).account;
    expect(() => vault.create(awsKeyInput("aws", fakeAwsSecret()))).toThrow(/name already used/);
    expect(() => vault.update(made.id, gcpKeyInput("AWS", makeGcpKeyJson()))).toThrow(
      /provider cannot change/,
    );
    const role = awsRoleInput("Long", fakeAwsSecret(), "ext-id-1234");
    expect(() => vault.create({ ...role, settings: { ...role.settings, sessionSeconds: 7200 } })).toThrow(
      /sessionSeconds/,
    );
  });

  it("an invalid request creates no key", () => {
    expect(() => vault.create(awsKeyInput("AWS", ""))).toThrow(/secretAccessKey required/);
    expect(existsSync(keyPath)).toBe(false);
  });

  it("refuses a certificate PEM whose private key belongs to another certificate", () => {
    const a = makeCertPem();
    const b = makeCertPem();
    const certOnly = a.pem.slice(0, a.pem.indexOf(KEY_MARKER));
    const otherKey = b.pem.slice(b.pem.indexOf(KEY_MARKER));
    expect(() => vault.create(microsoftPemInput("Mixed", certOnly + otherKey))).toThrow(/does not belong/);
    expect(() => vault.create(microsoftPemInput("NoKey", certOnly))).toThrow(/private key/);
  });

  it("accepts a PFX with its password and refuses a wrong one, never quoting either", () => {
    const { pem } = makeCertPem();
    const pfx = makePfxBase64(pem, "pfx-pass-sentinel");
    if (!pfx) return; // openssl not installed here: nothing to build a PFX with
    const input = (password: string) => ({
      name: "PFX tenant",
      provider: "microsoft" as const,
      settings: {
        tenantId: "contoso.onmicrosoft.example",
        clientId: "00000000-0000-4000-8000-000000000002",
        certificateFormat: "pfx",
      },
      secrets: { pfxBase64: pfx, pfxPassword: password },
    });
    let refusal = "";
    try {
      vault.create(input("wrong-password"));
    } catch (err) {
      refusal = (err as Error).message;
    }
    expect(refusal).toMatch(/cannot be opened with that password/);
    expect(refusal).not.toContain("wrong-password");
    const made = vault.create(input("pfx-pass-sentinel")).account;
    expect(vault.open(made.id).secrets).toEqual({ pfxBase64: pfx, pfxPassword: "pfx-pass-sentinel" });
  });

  it("secretValues lists every secret, including each line of a private key", () => {
    const awsSecret = fakeAwsSecret();
    const { pem, keyLines } = makeCertPem();
    vault.create(awsKeyInput("AWS", awsSecret));
    vault.create(microsoftPemInput("Tenant", pem));
    const values = vault.secretValues();
    expect(values).toContain(awsSecret);
    for (const line of keyLines) expect(values).toContain(line);
  });
});
