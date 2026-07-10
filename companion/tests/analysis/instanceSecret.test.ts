import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOrCreateInstanceSecret } from "../../src/analysis/instanceSecret.js";

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
});
