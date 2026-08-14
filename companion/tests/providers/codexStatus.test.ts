import { describe, it, expect, vi } from "vitest";
import { getCodexStatus, startCodexLogin } from "../../src/providers/codexStatus.js";
import type { CodexRunOptions, CodexRunResult } from "../../src/providers/codexRunner.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SPLIT_UTF8_TEXT, splitUtf8Script, writeNodeShim } from "../helpers/splitUtf8.js";

function runnerReturning(r: Partial<CodexRunResult>) {
  return vi.fn(async (_o: CodexRunOptions): Promise<CodexRunResult> => ({
    code: 0,
    stdout: "",
    stderr: "",
    ...r,
  }));
}

describe("getCodexStatus", () => {
  it("reports not_installed on ENOENT", async () => {
    const runner = runnerReturning({
      code: null,
      spawnError: Object.assign(new Error("x"), { code: "ENOENT" }),
    });
    const s = await getCodexStatus({ runner, env: {}, authFileExists: () => false });
    expect(s.state).toBe("not_installed");
  });

  it("reports connected via an environment API key", async () => {
    const runner = runnerReturning({ stdout: "codex-cli 0.99.0" });
    const s = await getCodexStatus({
      runner,
      env: { OPENAI_API_KEY: "sk-xxx" },
      authFileExists: () => false,
    });
    expect(s.state).toBe("connected");
    expect(s.authMethod).toBe("api_key");
  });

  it("reports connected via ~/.codex/auth.json", async () => {
    const runner = runnerReturning({ stdout: "codex-cli 0.99.0" });
    const s = await getCodexStatus({ runner, env: {}, authFileExists: () => true });
    expect(s.state).toBe("connected");
    expect(s.authMethod).toBe("codex login");
  });

  it("reports not_connected when installed but no key and no auth file", async () => {
    const runner = runnerReturning({ stdout: "codex-cli 0.99.0" });
    const s = await getCodexStatus({ runner, env: {}, authFileExists: () => false });
    expect(s.state).toBe("not_connected");
    expect(s.message).toMatch(/codex login|OPENAI_API_KEY/);
  });

  it("checks the binary with `codex --version`", async () => {
    let captured: CodexRunOptions | undefined;
    const runner = vi.fn(async (o: CodexRunOptions): Promise<CodexRunResult> => {
      captured = o;
      return { code: 0, stdout: "v", stderr: "" };
    });
    await getCodexStatus({ runner, env: { OPENAI_API_KEY: "k" }, authFileExists: () => false });
    expect(captured!.args).toEqual(["--version"]);
  });
});

describe("startCodexLogin", () => {
  it("returns started:false with an error when the binary is missing", async () => {
    const r = await startCodexLogin({ bin: "definitely-not-a-real-binary-xyz", captureMs: 500 });
    expect(r.started).toBe(false);
    expect(r.error).toBeTruthy();
  });

  // The captured banner goes straight to the dashboard. Relies on the OS reading the shebang to
  // exec the shim, which only POSIX does.
  it.skipIf(process.platform === "win32")(
    "reassembles a character split across two output chunks",
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "codex-login-utf8-"));
      const shim = writeNodeShim(
        join(dir, "codex"),
        splitUtf8Script({ before: "Signing in as ", after: "\n" }),
      );
      const r = await startCodexLogin({ bin: shim, captureMs: 3000 });
      expect(r.output).toBe(`Signing in as ${SPLIT_UTF8_TEXT}\n`);
    },
  );
});
