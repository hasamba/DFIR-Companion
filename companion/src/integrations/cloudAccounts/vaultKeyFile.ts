import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as nodeFs from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, join, win32 } from "node:path";

// The cloud account vault key: 32 random bytes in a file OUTSIDE the data folder, so a stolen
// data-folder backup holds the sealed secrets but never the key that opens them (#2307). Not the
// instance secret: that one sits under the cases root, beside the data it would protect.

export const VAULT_KEY_BYTES = 32;
export const VAULT_KEY_ENV = "DFIR_CLOUD_VAULT_KEY_FILE";
const KEY_NAME = "cloud-vault.key";

export type VaultKeyRead =
  { state: "present"; key: Buffer } | { state: "missing" } | { state: "invalid" } | { state: "insecure" };

/** The file calls the key needs, injectable so a test can fail an fsync or an fchmod. */
export type VaultFs = Pick<
  typeof nodeFs,
  | "openSync"
  | "closeSync"
  | "fstatSync"
  | "fchmodSync"
  | "fsyncSync"
  | "readSync"
  | "writeSync"
  | "mkdirSync"
  | "unlinkSync"
>;

// A folder fsync the platform cannot do (Windows, some filesystems) is not a failure.
export const DIR_FSYNC_UNSUPPORTED: ReadonlySet<string> = new Set([
  "EISDIR",
  "EPERM",
  "EINVAL",
  "ENOTSUP",
  "EBADF",
]);
const POSIX = process.platform !== "win32";

/**
 * Where the key lives: `DFIR_CLOUD_VAULT_KEY_FILE`, else `%APPDATA%\DFIR-Companion` on Windows,
 * else `$XDG_CONFIG_HOME/dfir-companion` (default `~/.config`). The Docker image sets the variable
 * to its dedicated `/run/dfir-vault` mount.
 */
export function defaultVaultKeyPath(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform = process.platform,
  home: string = homedir(),
): string {
  const override = env[VAULT_KEY_ENV]?.trim();
  if (override) return override;
  if (platform === "win32") {
    const appData = env.APPDATA?.trim() || win32.join(home, "AppData", "Roaming");
    return win32.join(appData, "DFIR-Companion", KEY_NAME);
  }
  const config = env.XDG_CONFIG_HOME?.trim() || join(home, ".config");
  return join(config, "dfir-companion", KEY_NAME);
}

// Best effort on Windows: drop inherited entries and grant the current user alone. A failure is
// returned, not thrown — the key is still written; the caller logs that the ACL was not narrowed.
function restrictWindowsAcl(path: string): string | undefined {
  try {
    const user = userInfo().username;
    execFileSync("icacls", [path, "/inheritance:r", "/grant:r", `${user}:F`], {
      stdio: "ignore",
      windowsHide: true,
    });
    return undefined;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code ?? "icacls failed";
  }
}

export class VaultKeyFile {
  constructor(
    readonly path: string,
    private readonly log: (line: string) => void = () => undefined,
    private readonly fs: VaultFs = nodeFs,
  ) {}

  /**
   * The key as it is on disk now. Re-read on every call, so a restored key file works at once.
   * Only a regular file counts. On POSIX a key readable by group or others is narrowed to 0600
   * first; when that is impossible the vault stays locked ("insecure") and nothing is deleted.
   * Windows: the ACL is narrowed best effort when the key is made (icacls), and not re-checked.
   */
  read(): VaultKeyRead {
    let fd: number;
    try {
      fd = this.fs.openSync(this.path, "r");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { state: "missing" };
      return { state: "invalid" };
    }
    try {
      const st = this.fs.fstatSync(fd);
      if (!st.isFile() || st.size !== VAULT_KEY_BYTES) return { state: "invalid" };
      if (POSIX && (st.mode & 0o077) !== 0) {
        try {
          this.fs.fchmodSync(fd, 0o600);
          this.log(`[cloud-accounts] narrowed the vault key at ${this.path} to mode 0600`);
        } catch {
          return { state: "insecure" };
        }
      }
      const key = Buffer.alloc(VAULT_KEY_BYTES);
      let got = 0;
      while (got < key.length) {
        const n = this.fs.readSync(fd, key, got, key.length - got, got);
        if (n === 0) return { state: "invalid" };
        got += n;
      }
      return { state: "present", key };
    } catch {
      return { state: "invalid" };
    } finally {
      this.fs.closeSync(fd);
    }
  }

  /**
   * Creates the key and returns it: exclusive create (mode 0600) in an owner-only folder, every
   * byte written, the file fsynced, then its folder. Only then may a caller seal an account with
   * it — a key lost to a power cut would orphan every credential. Any failure removes the
   * half-made key and throws. An existing key is never overwritten: a second key would lock every
   * account.
   */
  create(): Buffer {
    const now = this.read();
    if (now.state === "present") return now.key;
    if (now.state === "insecure") throw new Error(`Key file permissions too open at ${this.path}.`);
    if (now.state === "invalid") throw new Error(`The key file at ${this.path} is not a valid vault key.`);
    this.fs.mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const key = randomBytes(VAULT_KEY_BYTES);
    let fd: number;
    try {
      fd = this.fs.openSync(this.path, "wx", 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      return this.create(); // another request made it first: use that key
    }
    try {
      this.writeAll(fd, key);
      this.fs.fsyncSync(fd);
    } catch (err) {
      this.discard(fd);
      throw err;
    }
    this.fs.closeSync(fd);
    try {
      this.syncFolder();
    } catch (err) {
      this.discard();
      throw err;
    }
    this.narrowPermissions();
    return key;
  }

  private writeAll(fd: number, data: Buffer): void {
    let done = 0;
    while (done < data.length) done += this.fs.writeSync(fd, data, done, data.length - done, done);
  }

  // Removes a key this call made but could not make durable. No account was sealed with it yet.
  private discard(fd?: number): void {
    try {
      if (fd !== undefined) this.fs.closeSync(fd);
    } catch {
      /* already closed */
    }
    try {
      this.fs.unlinkSync(this.path);
    } catch {
      /* nothing to remove */
    }
  }

  private syncFolder(): void {
    let dirFd: number;
    try {
      dirFd = this.fs.openSync(dirname(this.path), "r");
    } catch (err) {
      if (DIR_FSYNC_UNSUPPORTED.has((err as NodeJS.ErrnoException).code ?? "")) return;
      throw err;
    }
    try {
      this.fs.fsyncSync(dirFd);
    } catch (err) {
      if (!DIR_FSYNC_UNSUPPORTED.has((err as NodeJS.ErrnoException).code ?? "")) throw err;
    } finally {
      this.fs.closeSync(dirFd);
    }
  }

  private narrowPermissions(): void {
    if (!POSIX) {
      const why = restrictWindowsAcl(this.path);
      if (why) this.log(`[cloud-accounts] could not limit the vault key ACL to this user (${why})`);
      return;
    }
    try {
      nodeFs.chmodSync(this.path, 0o600); // a umask cannot widen it, but an odd filesystem might
    } catch {
      this.log("[cloud-accounts] could not set mode 0600 on the vault key file");
    }
  }
}
