import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";

// #2347: credentials end with the case. The vault records who added an account and when it was last
// used, and releases a case's accounts in one pass: an account only that case used is erased, a
// shared one is detached from it.

let dir: string;
let vault: CloudAccountVault;
const storeFile = () => join(dir, "cloud-accounts", "accounts.json");

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-release-"));
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(join(dir, "k", "vault.key")));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("who added an account and when it was last used", () => {
  it("records the adder on create and keeps it across an edit; an old account has none", () => {
    const secret = fakeAwsSecret();
    const made = vault.create(awsKeyInput("A", secret), "c1", { id: "u1", displayName: "Alice" }).account;
    expect(made.createdBy).toEqual({ id: "u1", displayName: "Alice" });
    expect(made.lastUsedAt).toBeUndefined();
    const edited = vault.update(made.id, awsKeyInput("A2", ""));
    expect(edited.createdBy).toEqual({ id: "u1", displayName: "Alice" });
    const old = vault.create(awsKeyInput("Old", fakeAwsSecret())).account;
    expect(old.createdBy).toBeUndefined();
  });

  it("markUsed stamps lastUsedAt, and an edit keeps it", () => {
    const { id } = vault.create(awsKeyInput("A", fakeAwsSecret()), "c1").account;
    vault.markUsed(id);
    const stamped = vault.view(id).lastUsedAt;
    expect(stamped).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(vault.update(id, awsKeyInput("A", "")).lastUsedAt).toBe(stamped);
  });

  it("markUsed on a gone account does not throw", () => {
    expect(() => vault.markUsed("nope")).not.toThrow();
  });
});

describe("releaseCase", () => {
  it("erases an account only this case used and detaches a shared one", () => {
    const soleSecret = fakeAwsSecret();
    const sole = vault.create(awsKeyInput("Sole", soleSecret), "c1", { id: "u1", displayName: "Al" }).account;
    const shared = vault.create(awsKeyInput("Shared", fakeAwsSecret()), "c1").account;
    vault.attach(shared.id, "c2");
    const other = vault.create(awsKeyInput("Other", fakeAwsSecret()), "c2").account;

    const out = vault.releaseCase("c1");

    expect(out.deleted.map((a) => a.id)).toEqual([sole.id]);
    expect(out.deleted[0]).toMatchObject({ name: "Sole", provider: "aws", createdBy: { displayName: "Al" } });
    expect(out.deleted[0]).not.toHaveProperty("sealed");
    expect(out.detached.map((a) => a.id)).toEqual([shared.id]);
    expect(out.detached[0].caseIds).toEqual(["c2"]);
    expect(
      vault
        .list()
        .map((a) => a.id)
        .sort(),
    ).toEqual([shared.id, other.id].sort());
    expect(vault.view(shared.id).caseIds).toEqual(["c2"]);
    expect(readFileSync(storeFile(), "utf8")).not.toContain(soleSecret);
  });

  it("sharedWith previews the accounts releaseCase would detach, and changes nothing", () => {
    vault.create(awsKeyInput("Sole", fakeAwsSecret()), "c1");
    const shared = vault.create(awsKeyInput("Shared", fakeAwsSecret()), "c1").account;
    vault.attach(shared.id, "c2");
    const before = readFileSync(storeFile(), "utf8");
    const preview = vault.sharedWith("c1");
    expect(preview.map((a) => a.id)).toEqual([shared.id]);
    expect(preview[0].caseIds).toEqual(["c1", "c2"]);
    expect(preview[0]).not.toHaveProperty("sealed");
    expect(readFileSync(storeFile(), "utf8")).toBe(before);
    expect(vault.sharedWith("c3")).toEqual([]);
  });

  it("is a no-op for a case with no accounts", () => {
    vault.create(awsKeyInput("A", fakeAwsSecret()), "c2");
    expect(vault.releaseCase("c1")).toEqual({ deleted: [], detached: [] });
    expect(vault.list()).toHaveLength(1);
  });

  it("removeMany erases each named account and returns what it erased", () => {
    const a = vault.create(awsKeyInput("A", fakeAwsSecret()), "c1").account;
    const b = vault.create(awsKeyInput("B", fakeAwsSecret())).account;
    const c = vault.create(awsKeyInput("C", fakeAwsSecret()), "c2").account;
    const gone = vault.removeMany([a.id, b.id]);
    expect(gone.map((g) => g.id)).toEqual([a.id, b.id]);
    expect(gone[0].caseIds).toEqual(["c1"]);
    expect(vault.list().map((x) => x.id)).toEqual([c.id]);
  });
});

// #2371: the release and the record of its detaches come from one snapshot, under the vault lock.
describe("releaseCaseRecorded", () => {
  function sharedAndSole() {
    const shared = vault.create(awsKeyInput("S", fakeAwsSecret()), "c1").account;
    vault.attach(shared.id, "c2");
    const sole = vault.create(awsKeyInput("A", fakeAwsSecret()), "c1").account;
    return { shared, sole };
  }

  it("hands the shared accounts to the recorder, then releases exactly those as detached", async () => {
    const { shared, sole } = sharedAndSole();
    const recorded: string[] = [];
    const out = await vault.releaseCaseRecorded("c1", async (accounts) => {
      recorded.push(...accounts.map((a) => a.id));
    });
    expect(recorded).toEqual([shared.id]);
    expect(out.detached.map((a) => a.id)).toEqual([shared.id]);
    expect(out.deleted.map((a) => a.id)).toEqual([sole.id]);
  });

  it("a recorder that throws part-way leaves the vault unchanged, and the lock is free again", async () => {
    const { shared } = sharedAndSole();
    const other = vault.create(awsKeyInput("T", fakeAwsSecret()), "c1").account;
    vault.attach(other.id, "c3");
    const before = readFileSync(storeFile(), "utf8");
    let writes = 0;
    await expect(
      vault.releaseCaseRecorded("c1", async (accounts) => {
        for (const _ of accounts) if (++writes === 2) throw new Error("custody disk full");
      }),
    ).rejects.toThrow("custody disk full");
    expect(readFileSync(storeFile(), "utf8")).toBe(before);
    // A retry records both again and releases.
    const retry = await vault.releaseCaseRecorded("c1", async () => {});
    expect(retry.detached.map((a) => a.id).sort()).toEqual([shared.id, other.id].sort());
  });

  it("a locked change waits for the release instead of landing inside it", async () => {
    const { shared } = sharedAndSole();
    let open!: () => void;
    const gate = new Promise<void>((resolve) => (open = resolve));
    const release = vault.releaseCaseRecorded("c1", () => gate);
    const detach = vault.exclusive(() => vault.detach(shared.id, "c2"));
    open();
    const out = await release;
    expect(out.detached.map((a) => a.id)).toEqual([shared.id]);
    expect((await detach).caseIds).toEqual([]);
  });

  it("refuses, releasing nothing, when a writer outside the lock changed the plan", async () => {
    const { shared } = sharedAndSole();
    await expect(
      vault.releaseCaseRecorded("c1", async () => {
        vault.detach(shared.id, "c2"); // bypasses the lock: shared -> sole
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(vault.listForCase("c1")).toHaveLength(2);
  });
});
