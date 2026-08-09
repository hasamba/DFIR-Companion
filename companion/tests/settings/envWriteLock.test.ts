import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
    // And a specific winner: the queue is FIFO and these were enqueued left to right, so the save
    // that arrived second is the one left standing. Accepting either value would pass even if the
    // ordering were reversed, which is the property worth pinning.
    expect(written).toContain("DFIR_RACED=second");
  });

  // The anti-wedge property: a save whose write throws must reject its own caller and must not stop
  // the ones queued behind it. Without that, one EACCES would strand every later save in the process.
  it("rejects the failed save without wedging the queue behind it", async () => {
    // Fail the write by nesting the target under a regular FILE, which yields ENOTDIR. Removing
    // directory permissions would not do it: CI often runs as root, where the mode bits are ignored
    // and the "failing" write would quietly succeed, leaving this test green and meaningless.
    const blocker = join(dirname(envFile), "not-a-directory");
    await writeFile(blocker, "", "utf8");
    process.env.DFIR_ENV_FILE = join(blocker, ".env");

    await expect(updateEnv({ DFIR_WILL_FAIL: "x" })).rejects.toThrow();

    process.env.DFIR_ENV_FILE = envFile;
    // The queue still runs: a save enqueued after the failure completes normally.
    await updateEnv({ DFIR_AFTER_FAILURE: "ok" });

    const written = await readFile(envFile, "utf8");
    expect(written).toContain("DFIR_AFTER_FAILURE=ok");
    expect(written).not.toContain("DFIR_WILL_FAIL");
  });

  it("survives a burst without dropping anyone", async () => {
    const keys = Array.from({ length: 8 }, (_, i) => `DFIR_BURST_${i}`);
    await Promise.all(keys.map((key) => updateEnv({ [key]: "set" })));

    const written = await readFile(envFile, "utf8");
    for (const key of keys) expect(written).toContain(`${key}=set`);
  });
});
