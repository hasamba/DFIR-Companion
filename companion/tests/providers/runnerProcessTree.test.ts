import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it, expect, vi } from "vitest";
import { defaultClaudeRunner } from "../../src/providers/claudeRunner.js";
import { defaultCodexRunner } from "../../src/providers/codexRunner.js";

// #1627, against real processes: the CLI child starts a helper that inherits its stdout/stderr (as
// an MCP server does). Cancelling the call must kill the helper too, and the call must not wait
// for the helper to exit on its own. Runs on both Linux and Windows CI.

const HELPER_LIFE_MS = 30_000;

// The "CLI": starts a long-lived helper sharing its stdio, records the helper's pid, then idles.
// `detachHelper` puts the helper in its own session, which escapes a POSIX group kill.
const cliScript = (pidFile: string, detachHelper: boolean) =>
  `const { spawn } = require("node:child_process");` +
  `const fs = require("node:fs");` +
  `const h = spawn(process.execPath, ["-e", "setTimeout(() => {}, ${HELPER_LIFE_MS})"],` +
  ` { stdio: "inherit", detached: ${detachHelper} });` +
  `fs.writeFileSync(${JSON.stringify(pidFile)}, String(h.pid));` +
  `setTimeout(() => {}, ${HELPER_LIFE_MS});`;

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

const waitFor = async (check: () => boolean, deadlineMs: number): Promise<boolean> => {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return check();
};

const strays: number[] = [];
afterEach(() => {
  for (const pid of strays.splice(0)) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* already gone */
    }
  }
  vi.restoreAllMocks();
});

const runners = [
  ["defaultClaudeRunner", defaultClaudeRunner],
  ["defaultCodexRunner", defaultCodexRunner],
] as const;

describe.each(runners)("%s process-tree cancellation (#1627)", (_name, runner) => {
  it("kills the helper the CLI started and settles without waiting for it", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const pidFile = join(mkdtempSync(join(tmpdir(), "tree-")), "helper.pid");
    const ac = new AbortController();
    const run = runner({
      bin: process.execPath,
      args: ["-e", cliScript(pidFile, false)],
      stdin: "",
      timeoutMs: 60_000,
      signal: ac.signal,
    });

    expect(await waitFor(() => existsSync(pidFile) && readFileSync(pidFile, "utf8") !== "", 10_000)).toBe(
      true,
    );
    const helperPid = Number(readFileSync(pidFile, "utf8"));
    strays.push(helperPid);

    ac.abort();
    const r = await run;

    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
    // Settled by the tree kill closing the pipes, not by the forced-settle fallback, which warns.
    expect(warn).not.toHaveBeenCalled();
    expect(await waitFor(() => !isAlive(helperPid), 5_000)).toBe(true);
  }, 30_000);
});

describe.skipIf(process.platform === "win32")("forced settle when a helper escapes the group (#1627)", () => {
  it.each(runners)(
    "%s settles after the grace and logs that the kill was not confirmed",
    async (_n, runner) => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const pidFile = join(mkdtempSync(join(tmpdir(), "tree-")), "helper.pid");
      const ac = new AbortController();
      const run = runner({
        bin: process.execPath,
        args: ["-e", cliScript(pidFile, true)],
        stdin: "",
        timeoutMs: 60_000,
        signal: ac.signal,
      });
      expect(await waitFor(() => existsSync(pidFile) && readFileSync(pidFile, "utf8") !== "", 10_000)).toBe(
        true,
      );
      strays.push(Number(readFileSync(pidFile, "utf8")));

      ac.abort();
      const r = await run;

      expect(r.timedOut).toBe(true);
      expect(r.code).toBeNull();
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0]?.[0])).toContain("may still be running");
    },
    30_000,
  );
});
