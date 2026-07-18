import { describe, it, expect, vi } from "vitest";
import { writeFileSync, chmodSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getClaudeCodeStatus, startClaudeLogin } from "../../src/providers/claudeCodeStatus.js";
import type { ClaudeRunOptions, ClaudeRunResult } from "../../src/providers/claudeRunner.js";

function runnerReturning(r: Partial<ClaudeRunResult>) {
  return vi.fn(async (_o: ClaudeRunOptions): Promise<ClaudeRunResult> => ({ code: 0, stdout: "", stderr: "", ...r }));
}

describe("getClaudeCodeStatus", () => {
  it("reports connected with email and plan", async () => {
    const runner = runnerReturning({ stdout: JSON.stringify({ loggedIn: true, email: "a@b.com", subscriptionType: "max", authMethod: "claude.ai" }) });
    const s = await getClaudeCodeStatus({ runner });
    expect(s.state).toBe("connected");
    expect(s.email).toBe("a@b.com");
    expect(s.subscriptionType).toBe("max");
    expect(s.message).toMatch(/a@b\.com/);
  });

  it("reports not_connected when loggedIn is false", async () => {
    const runner = runnerReturning({ stdout: JSON.stringify({ loggedIn: false }) });
    const s = await getClaudeCodeStatus({ runner });
    expect(s.state).toBe("not_connected");
    expect(s.message).toMatch(/claude auth login/);
  });

  it("reports not_installed on ENOENT", async () => {
    const runner = runnerReturning({ code: null, spawnError: Object.assign(new Error("x"), { code: "ENOENT" }) });
    const s = await getClaudeCodeStatus({ runner });
    expect(s.state).toBe("not_installed");
  });

  it("runs the auth status --json subcommand", async () => {
    let captured: ClaudeRunOptions | undefined;
    const runner = vi.fn(async (o: ClaudeRunOptions): Promise<ClaudeRunResult> => { captured = o; return { code: 0, stdout: JSON.stringify({ loggedIn: true }), stderr: "" }; });
    await getClaudeCodeStatus({ runner });
    expect(captured!.args).toEqual(["auth", "status", "--json"]);
  });
});

describe("startClaudeLogin", () => {
  it("returns started:false with an error when the binary is missing", async () => {
    const r = await startClaudeLogin({ bin: "definitely-not-a-real-binary-xyz", captureMs: 500 });
    expect(r.started).toBe(false);
    expect(r.error).toBeTruthy();
  });

  // Relies on the OS reading the "#!/bin/sh" shebang to exec the shim, which only POSIX does.
  it.skipIf(process.platform === "win32")("captures a printed URL and resolves started:true via finish()", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cc-login-"));
    const shim = join(dir, "claude");
    // Ignores its args ("auth login"), prints a URL, exits immediately.
    writeFileSync(shim, '#!/bin/sh\necho "Visit https://example.com/oauth?code=abc to sign in"\n');
    chmodSync(shim, 0o755);
    const r = await startClaudeLogin({ bin: shim, captureMs: 3000 });
    expect(r.started).toBe(true);
    expect(r.url).toBe("https://example.com/oauth?code=abc");
  });
});
