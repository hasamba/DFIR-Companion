import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";

// #2308: an account is attached to the cases that may use it. The list is plain metadata beside the
// sealed secrets, never part of them.

let dir: string;
let vault: CloudAccountVault;
const storeFile = () => join(dir, "cloud-accounts", "accounts.json");

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-cases-"));
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(join(dir, "k", "vault.key")));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("cloud account case attachment", () => {
  it("attaches a new account to the case it was added in; no case leaves it unattached", () => {
    const inCase = vault.create(awsKeyInput("In case", fakeAwsSecret()), "c1").account;
    const global = vault.create(awsKeyInput("Global", fakeAwsSecret())).account;
    expect(inCase.caseIds).toEqual(["c1"]);
    expect(global.caseIds).toEqual([]);
    expect(vault.listForCase("c1").map((a) => a.name)).toEqual(["In case"]);
    expect(vault.listForCase("c2")).toEqual([]);
    expect(vault.list().map((a) => a.caseIds)).toEqual([["c1"], []]);
  });

  it("reads an account stored before #2308 (no case list) as unattached", () => {
    vault.create(awsKeyInput("Old", fakeAwsSecret()), "c1");
    const raw = JSON.parse(readFileSync(storeFile(), "utf8")) as { accounts: Record<string, unknown>[] };
    delete raw.accounts[0].caseIds;
    writeFileSync(storeFile(), JSON.stringify(raw));
    expect(vault.list()[0].caseIds).toEqual([]);
    expect(vault.listForCase("c1")).toEqual([]);
  });

  it("attach adds a case once; detach removes only that case and keeps the account", () => {
    const { id } = vault.create(awsKeyInput("Shared", fakeAwsSecret()), "c1").account;
    expect(vault.attach(id, "c2").caseIds).toEqual(["c1", "c2"]);
    expect(vault.attach(id, "c2").caseIds).toEqual(["c1", "c2"]);
    expect(vault.detach(id, "c1").caseIds).toEqual(["c2"]);
    expect(vault.listForCase("c2").map((a) => a.id)).toEqual([id]);
    expect(vault.listForCase("c1")).toEqual([]);
    expect(vault.detach(id, "c2").caseIds).toEqual([]);
    expect(vault.list()).toHaveLength(1);
  });

  it("detachCase drops a deleted case from every account", () => {
    const a = vault.create(awsKeyInput("A", fakeAwsSecret()), "gone").account;
    const b = vault.create(awsKeyInput("B", fakeAwsSecret()), "keep").account;
    vault.attach(b.id, "gone");
    expect(vault.detachCase("gone")).toBe(2);
    expect(vault.view(a.id).caseIds).toEqual([]);
    expect(vault.view(b.id).caseIds).toEqual(["keep"]);
    expect(vault.detachCase("gone")).toBe(0);
  });

  it("an edit keeps the case list, and the list never enters the sealed secrets", () => {
    const secret = fakeAwsSecret();
    const { id } = vault.create(awsKeyInput("Edit", secret), "c1").account;
    vault.attach(id, "c2");
    const edited = vault.update(id, awsKeyInput("Edited", ""));
    expect(edited.caseIds).toEqual(["c1", "c2"]);
    const text = readFileSync(storeFile(), "utf8");
    expect(text).toContain('"caseIds"');
    expect(text).not.toContain(secret);
  });

  it("view reads one account without its secrets; an unknown id is not-found", () => {
    const secret = fakeAwsSecret();
    const { id } = vault.create(awsKeyInput("One", secret), "c1").account;
    const view = vault.view(id);
    expect(view).toMatchObject({ id, name: "One", caseIds: ["c1"] });
    expect(JSON.stringify(view)).not.toContain(secret);
    expect(() => vault.view("nope")).toThrow(/not found/);
    expect(() => vault.attach("nope", "c1")).toThrow(/not found/);
  });

  it("attach with an expected source case refuses once that case is detached", () => {
    const { id } = vault.create(awsKeyInput("Raced", fakeAwsSecret()), "c1").account;
    vault.detach(id, "c1");
    expect(() => vault.attach(id, "c2", "c1")).toThrow(/not found/);
    expect(vault.view(id).caseIds).toEqual([]);
  });

  it("scopes name uniqueness to the case: two cases may share a label, one case may not", () => {
    vault.create(awsKeyInput("Prod", fakeAwsSecret()), "c1");
    expect(vault.create(awsKeyInput("prod", fakeAwsSecret()), "c2").account.caseIds).toEqual(["c2"]);
    expect(() => vault.create(awsKeyInput("PROD", fakeAwsSecret()), "c1")).toThrow(/name already used/);
    // Unattached (instance-admin) accounts are their own scope.
    vault.create(awsKeyInput("Prod", fakeAwsSecret()));
    expect(() => vault.create(awsKeyInput("Prod", fakeAwsSecret()))).toThrow(/name already used/);
  });

  it("attach refuses a name already used in the target case; edit checks every attached case", () => {
    const a = vault.create(awsKeyInput("Prod", fakeAwsSecret()), "c1").account;
    const b = vault.create(awsKeyInput("Prod", fakeAwsSecret()), "c2").account;
    expect(() => vault.attach(a.id, "c2", "c1")).toThrow(/name already used in that case/);
    expect(vault.view(a.id).caseIds).toEqual(["c1"]);
    const c = vault.create(awsKeyInput("Other", fakeAwsSecret()), "c1").account;
    vault.attach(c.id, "c3", "c1");
    vault.create(awsKeyInput("Taken", fakeAwsSecret()), "c3");
    expect(() => vault.update(c.id, awsKeyInput("taken", ""))).toThrow(/name already used/);
    expect(vault.update(b.id, awsKeyInput("Other", "")).name).toBe("Other");
  });
});
