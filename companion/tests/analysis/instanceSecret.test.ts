import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile, chmod, stat } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOrCreateInstanceSecret } from "../../src/analysis/instanceSecret.js";

// POSIX modes are not meaningful on Windows, where chmod only toggles the read-only bit.
const onPosix = it.skipIf(process.platform === "win32");

describe("loadOrCreateInstanceSecret", () => {
  it("creates a 32-byte secret file on first call", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-secret-"));
    const secret = loadOrCreateInstanceSecret(root);
    expect(secret.length).toBe(32);
    const onDisk = await readFile(join(root, ".instance-secret"), "utf8");
    expect(Buffer.from(onDisk.trim(), "hex").length).toBe(32);
  });

  it("returns the SAME secret on a second call (persisted, not regenerated)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-secret-"));
    const first = loadOrCreateInstanceSecret(root);
    const second = loadOrCreateInstanceSecret(root);
    expect(second.equals(first)).toBe(true);
  });

  it("creates the cases root directory if it doesn't exist yet", async () => {
    const root = join(await mkdtemp(join(tmpdir(), "dfir-secret-")), "nested", "cases");
    const secret = loadOrCreateInstanceSecret(root);
    expect(secret.length).toBe(32);
  });

  onPosix("creates the secret file readable only by its owner", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-secret-"));
    loadOrCreateInstanceSecret(root);
    const mode = (await stat(join(root, ".instance-secret"))).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  // The upgrade case, and the whole point of doing this on the LOAD path: an install that first
  // ran before the mode was set on write has a world-readable secret and will never take the
  // create path again. It must be tightened in place, WITHOUT regenerating — regenerating would
  // invalidate every outstanding unlock cookie on what is otherwise a routine restart.
  onPosix("tightens an existing world-readable secret file without regenerating it", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-secret-"));
    const path = join(root, ".instance-secret");
    const existing = randomBytes(32).toString("hex");
    await writeFile(path, existing, "utf8");
    await chmod(path, 0o644); // what the old code left behind under a typical umask

    const secret = loadOrCreateInstanceSecret(root);

    expect(secret.toString("hex")).toBe(existing);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });
});
