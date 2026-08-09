import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { updateEnv } from "../../src/settings/envManager.js";

/**
 * updateEnv is a read-modify-write over one file (#510).
 *
 * Two saves in flight at once — the setup wizard and the Settings modal, or two browser tabs —
 * both read the same baseline before either writes, so the second atomicWrite replaced the first
 * caller's keys wholesale. The request had already returned 200, so the loss was silent.
 *
 * These use the real filesystem (no fs mock) via the DFIR_ENV_FILE override, because the bug is
 * entirely about the ordering of real reads and writes.
 */
describe("updateEnv — concurrent saves", () => {
  const originalEnv = { ...process.env };
  let envFile: string;

  beforeEach(async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-envlock-"));
    envFile = join(dir, ".env");
    await writeFile(envFile, "# managed by dfir-companion\nDFIR_EXISTING=keep-me\n", "utf8");
    process.env.DFIR_ENV_FILE = envFile;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("keeps both callers' keys when two saves overlap", async () => {
    await Promise.all([updateEnv({ DFIR_FIRST: "one" }), updateEnv({ DFIR_SECOND: "two" })]);

    const written = await readFile(envFile, "utf8");
    expect(written).toContain("DFIR_FIRST=one");
    expect(written).toContain("DFIR_SECOND=two");
    expect(written).toContain("DFIR_EXISTING=keep-me");
  });

  it("applies the later value when two saves race on the SAME key", async () => {
    await Promise.all([updateEnv({ DFIR_RACED: "first" }), updateEnv({ DFIR_RACED: "second" })]);

    const written = await readFile(envFile, "utf8");
    // One winner, not two lines for one key: the loser's write was read and replaced, not skipped.
    expect(written.match(/^DFIR_RACED=/gm)).toHaveLength(1);
    expect(written).toMatch(/DFIR_RACED=(first|second)/);
  });

  it("survives a burst without dropping anyone", async () => {
    const keys = Array.from({ length: 8 }, (_, i) => `DFIR_BURST_${i}`);
    await Promise.all(keys.map((key) => updateEnv({ [key]: "set" })));

    const written = await readFile(envFile, "utf8");
    for (const key of keys) expect(written).toContain(`${key}=set`);
  });
});
