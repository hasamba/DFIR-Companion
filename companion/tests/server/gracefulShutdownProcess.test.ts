import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

// #2142, process level: a real server sent SIGTERM must drain and exit 0 within the deadline, and
// its session log must end with a complete "[shutdown] complete" line. Windows cannot deliver a
// SIGTERM the same way, so this runs on Linux and macOS only.

const companionDir = resolve(__dirname, "../..");
const tmpRoot = mkdtempSync(join(tmpdir(), "dfir-shutdown-"));

afterAll(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

const freePort = (): Promise<number> =>
  new Promise((ok, fail) => {
    const s = createServer();
    s.once("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      s.close(() => ok(port));
    });
  });

const waitForHealth = async (port: number, child: ChildProcess, timeoutMs: number): Promise<void> => {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (child.exitCode !== null) throw new Error(`server exited early with ${child.exitCode}`);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("server never became healthy");
};

describe.skipIf(process.platform === "win32")("graceful shutdown (real process)", () => {
  it("drains on SIGTERM: exits 0 within the deadline and the session log ends complete", async () => {
    const port = await freePort();
    const casesRoot = join(tmpRoot, "cases");
    const logDir = join(tmpRoot, "logs");
    const envFile = join(tmpRoot, "empty.env");
    writeFileSync(envFile, "");
    const child = spawn(process.execPath, ["--import", "tsx/esm", "src/server.ts"], {
      cwd: companionDir,
      env: {
        ...process.env,
        DFIR_ENV_FILE: envFile,
        DFIR_CASES_ROOT: casesRoot,
        DFIR_LOG_DIR: logDir,
        DFIR_PORT: String(port),
        DFIR_HOST: "127.0.0.1",
        DFIR_DEBUG_LOG_MAX_MB: "0",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout?.on("data", (d) => (output += String(d)));
    child.stderr?.on("data", (d) => (output += String(d)));
    try {
      await waitForHealth(port, child, 45_000);
      const exited = new Promise<number | null>((ok) => child.once("exit", (code) => ok(code)));
      const sentAt = Date.now();
      child.kill("SIGTERM");
      const code = await exited;
      const tookMs = Date.now() - sentAt;
      expect(code, output).toBe(0);
      expect(tookMs).toBeLessThan(6000);
      const sessionLogs = readdirSync(logDir).filter((f) => f.startsWith("session-"));
      expect(sessionLogs).toHaveLength(1);
      const text = readFileSync(join(logDir, sessionLogs[0]!), "utf8");
      expect(text.endsWith("\n")).toBe(true);
      const last = text.trimEnd().split("\n").at(-1) ?? "";
      expect(last).toContain("[shutdown] complete");
    } finally {
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  }, 60_000);
});
