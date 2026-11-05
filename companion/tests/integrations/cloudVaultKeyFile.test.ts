import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  VAULT_KEY_BYTES,
  VaultKeyFile,
  defaultVaultKeyPath,
} from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-vault-key-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("default vault key path", () => {
  it("uses DFIR_CLOUD_VAULT_KEY_FILE when it is set", () => {
    const env = { DFIR_CLOUD_VAULT_KEY_FILE: "/run/dfir-vault/cloud-vault.key" };
    expect(defaultVaultKeyPath(env, "linux", "/home/a")).toBe("/run/dfir-vault/cloud-vault.key");
  });

  it("uses %APPDATA%\\DFIR-Companion on Windows", () => {
    const p = defaultVaultKeyPath({ APPDATA: "C:\\Users\\a\\AppData\\Roaming" }, "win32", "C:\\Users\\a");
    expect(p.replace(/\\/g, "/")).toBe("C:/Users/a/AppData/Roaming/DFIR-Companion/cloud-vault.key");
  });

  it("uses $XDG_CONFIG_HOME/dfir-companion on Linux", () => {
    expect(defaultVaultKeyPath({ XDG_CONFIG_HOME: "/home/a/.cfg" }, "linux", "/home/a")).toBe(
      join("/home/a/.cfg", "dfir-companion", "cloud-vault.key"),
    );
  });

  it("falls back to ~/.config/dfir-companion when XDG_CONFIG_HOME is not set", () => {
    expect(defaultVaultKeyPath({}, "linux", "/home/a")).toBe(
      join("/home/a", ".config", "dfir-companion", "cloud-vault.key"),
    );
  });

  it("ignores a blank override", () => {
    expect(defaultVaultKeyPath({ DFIR_CLOUD_VAULT_KEY_FILE: "  " }, "linux", "/home/a")).toBe(
      join("/home/a", ".config", "dfir-companion", "cloud-vault.key"),
    );
  });
});

describe("vault key file", () => {
  it("reports a missing key without creating it", () => {
    const key = new VaultKeyFile(join(dir, "sub", "cloud-vault.key"));
    expect(key.read()).toEqual({ state: "missing" });
    expect(existsSync(key.path)).toBe(false);
  });

  it("creates 32 random bytes, and reads them back", () => {
    const key = new VaultKeyFile(join(dir, "sub", "cloud-vault.key"));
    const made = key.create();
    expect(made.length).toBe(VAULT_KEY_BYTES);
    expect(readFileSync(key.path).equals(made)).toBe(true);
    const read = key.read();
    expect(read.state).toBe("present");
    expect(read.state === "present" && read.key.equals(made)).toBe(true);
  });

  it("two keys are never the same", () => {
    const a = new VaultKeyFile(join(dir, "a.key")).create();
    const b = new VaultKeyFile(join(dir, "b.key")).create();
    expect(a.equals(b)).toBe(false);
  });

  it.skipIf(process.platform === "win32")("writes the key file with mode 0600", () => {
    const key = new VaultKeyFile(join(dir, "sub", "cloud-vault.key"));
    key.create();
    expect(statSync(key.path).mode & 0o777).toBe(0o600);
  });

  it.skipIf(process.platform === "win32")("creates a missing key folder owner-only (0700)", () => {
    const key = new VaultKeyFile(join(dir, "fresh", "cloud-vault.key"));
    key.create();
    expect(statSync(join(dir, "fresh")).mode & 0o777).toBe(0o700);
  });

  it("never overwrites an existing key", () => {
    const key = new VaultKeyFile(join(dir, "cloud-vault.key"));
    const first = key.create();
    const second = key.create();
    expect(second.equals(first)).toBe(true);
    expect(readFileSync(key.path).equals(first)).toBe(true);
  });

  it("calls a key of the wrong length invalid and leaves it alone", () => {
    const path = join(dir, "cloud-vault.key");
    writeFileSync(path, Buffer.alloc(16, 1));
    const key = new VaultKeyFile(path);
    expect(key.read()).toEqual({ state: "invalid" });
    expect(() => key.create()).toThrow(/not a valid vault key/);
    expect(readFileSync(path).length).toBe(16);
  });
});

describe("vault key durability (review)", () => {
  it("fsyncs the new key file before reporting it made", () => {
    const synced: number[] = [];
    const key = new VaultKeyFile(join(dir, "cloud-vault.key"), undefined, {
      ...fs,
      fsyncSync: (fd: number) => {
        synced.push(fd);
        fs.fsyncSync(fd);
      },
    });
    key.create();
    // the key file's own fd, then (on POSIX) its folder
    expect(synced.length).toBeGreaterThanOrEqual(1);
  });

  it("a failed fsync aborts: no key is left behind and the vault saves nothing", () => {
    const keyPath = join(dir, "k", "cloud-vault.key");
    const failing = new VaultKeyFile(keyPath, undefined, {
      ...fs,
      fsyncSync: () => {
        throw Object.assign(new Error("EIO: i/o error"), { code: "EIO" });
      },
    });
    expect(() => failing.create()).toThrow(/EIO/);
    expect(existsSync(keyPath)).toBe(false);
    const vault = new CloudAccountVault(join(dir, "store"), failing);
    expect(() => vault.create(awsKeyInput("AWS", fakeAwsSecret()))).toThrow();
    expect(existsSync(join(dir, "store", "accounts.json"))).toBe(false);
    expect(existsSync(keyPath)).toBe(false);
  });

  it("ignores a folder fsync the platform cannot do (EISDIR / EPERM / EINVAL)", () => {
    for (const code of ["EISDIR", "EPERM", "EINVAL"]) {
      let calls = 0;
      const path = join(dir, code, "cloud-vault.key");
      const key = new VaultKeyFile(path, undefined, {
        ...fs,
        fsyncSync: (fd: number) => {
          calls++;
          if (calls > 1) throw Object.assign(new Error(code), { code });
          fs.fsyncSync(fd);
        },
      });
      expect(key.create().length).toBe(VAULT_KEY_BYTES);
      expect(existsSync(path)).toBe(true);
    }
  });
});

describe.skipIf(process.platform === "win32")("vault key permissions (review)", () => {
  it("narrows a restored 0644 key to 0600 and unlocks", () => {
    const path = join(dir, "cloud-vault.key");
    writeFileSync(path, Buffer.alloc(VAULT_KEY_BYTES, 3), { mode: 0o644 });
    chmodSync(path, 0o644);
    const read = new VaultKeyFile(path).read();
    expect(read.state).toBe("present");
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("refuses to unlock when the mode cannot be narrowed, and deletes nothing", () => {
    const path = join(dir, "cloud-vault.key");
    writeFileSync(path, Buffer.alloc(VAULT_KEY_BYTES, 3));
    chmodSync(path, 0o640);
    const key = new VaultKeyFile(path, undefined, {
      ...fs,
      fchmodSync: () => {
        throw Object.assign(new Error("EPERM"), { code: "EPERM" });
      },
    });
    expect(key.read()).toEqual({ state: "insecure" });
    expect(() => key.create()).toThrow(/permissions too open/);
    const store = join(dir, "store");
    new CloudAccountVault(store, new VaultKeyFile(path)).create(awsKeyInput("AWS", fakeAwsSecret()));
    chmodSync(path, 0o640);
    const locked = new CloudAccountVault(store, key);
    expect(locked.list()[0].locked).toBe(`Locked — key file permissions too open at ${path}`);
    expect(locked.status().keyState).toBe("insecure");
    expect(locked.list()).toHaveLength(1);
    expect(existsSync(path)).toBe(true);
  });

  it("refuses a directory, or a symlink to one, at the key path", () => {
    const asDir = join(dir, "dir.key");
    mkdirSync(asDir);
    expect(new VaultKeyFile(asDir).read()).toEqual({ state: "invalid" });
    expect(() => new VaultKeyFile(asDir).create()).toThrow(/not a valid vault key/);
    const link = join(dir, "link.key");
    symlinkSync(asDir, link);
    expect(new VaultKeyFile(link).read()).toEqual({ state: "invalid" });
  });
});
