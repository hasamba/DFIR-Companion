import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2342: a failed write or rename of the sealed-secret stores must not leave a `.tmp` copy behind.
const fault = vi.hoisted(() => ({ rename: false, write: false }));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const isTmp = (p: unknown) => typeof p === "string" && p.endsWith(".tmp");
  return {
    ...actual,
    renameSync: (from: string, to: string) => {
      if (fault.rename && isTmp(from))
        throw Object.assign(new Error("EPERM: rename blocked"), { code: "EPERM" });
      return actual.renameSync(from, to);
    },
    writeFileSync: (...args: Parameters<typeof actual.writeFileSync>) => {
      if (fault.write && isTmp(args[0])) {
        actual.writeFileSync(args[0], "partial");
        throw Object.assign(new Error("ENOSPC: no space left"), { code: "ENOSPC" });
      }
      return actual.writeFileSync(...args);
    },
  };
});

const { CloudAccountVault } = await import("../../src/integrations/cloudAccounts/cloudAccountVault.js");
const { VaultKeyFile } = await import("../../src/integrations/cloudAccounts/vaultKeyFile.js");
const { ServerSetStore } = await import("../../src/integrations/serverSets/serverSetStore.js");
const { awsKeyInput, fakeAwsSecret } = await import("../helpers/cloudAccountFixtures.js");

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "atomic-sync-"));
  fault.rename = false;
  fault.write = false;
});
afterEach(() => {
  fault.rename = false;
  fault.write = false;
  rmSync(dir, { recursive: true, force: true });
});

const tmpFiles = (d: string) => readdirSync(d).filter((n) => n.endsWith(".tmp"));

describe.each([
  ["renameSync", "rename", /EPERM/],
  ["writeFileSync", "write", /ENOSPC/],
] as const)("when %s fails", (_name, kind, message) => {
  it("the cloud account vault rethrows, removes the temp file and keeps accounts.json", () => {
    const storeDir = join(dir, "cloud-accounts");
    const vault = new CloudAccountVault(storeDir, new VaultKeyFile(join(dir, "key", "vault.key")));
    vault.create(awsKeyInput("AWS prod", fakeAwsSecret()));
    const before = readFileSync(join(storeDir, "accounts.json"), "utf8");

    fault[kind] = true;
    expect(() => vault.create(awsKeyInput("AWS lab", fakeAwsSecret()))).toThrow(message);

    expect(tmpFiles(storeDir)).toEqual([]);
    expect(readFileSync(join(storeDir, "accounts.json"), "utf8")).toBe(before);
  });

  it("the server-set store rethrows, removes the temp file and keeps sets.json", () => {
    const store = new ServerSetStore(dir, Buffer.alloc(32, 7));
    store.create({ name: "lab" });
    const before = readFileSync(join(dir, "sets.json"), "utf8");

    fault[kind] = true;
    expect(() => store.create({ name: "prod" })).toThrow(message);

    expect(tmpFiles(dir)).toEqual([]);
    expect(readFileSync(join(dir, "sets.json"), "utf8")).toBe(before);
  });
});
