import { spawn } from "node:child_process";
import { type ClaudeRunner, defaultClaudeRunner } from "./claudeRunner.js";

export type ClaudeAuthState = "not_installed" | "not_connected" | "connected";

export interface ClaudeCodeStatus {
  state: ClaudeAuthState;
  email?: string;
  subscriptionType?: string;
  authMethod?: string;
  message: string;
}

// Detect whether Claude Code is installed and signed in. Never throws — a spawn/parse failure
// resolves to a not_installed / not_connected state with a human message.
export async function getClaudeCodeStatus(
  opts: { bin?: string; runner?: ClaudeRunner; timeoutMs?: number } = {},
): Promise<ClaudeCodeStatus> {
  const bin = opts.bin?.trim() || "claude";
  const runner = opts.runner ?? defaultClaudeRunner;
  const run = await runner({ bin, args: ["auth", "status", "--json"], stdin: "", timeoutMs: opts.timeoutMs ?? 15_000 });

  if (run.spawnError) {
    const msg = run.spawnError.code === "ENOENT"
      ? "Claude Code isn't installed on this machine. Install it from https://claude.com/claude-code, then click Re-check."
      : `Claude Code could not be run: ${run.spawnError.message}`;
    return { state: "not_installed", message: msg };
  }

  let parsed: { loggedIn?: boolean; email?: string; subscriptionType?: string; authMethod?: string } = {};
  try { parsed = JSON.parse(run.stdout.trim()) as typeof parsed; } catch { /* treat unparseable output as not connected */ }

  if (parsed.loggedIn) {
    const tail = `${parsed.email ? ` as ${parsed.email}` : ""}${parsed.subscriptionType ? ` · ${parsed.subscriptionType} plan` : ""}`;
    return {
      state: "connected",
      ...(parsed.email ? { email: parsed.email } : {}),
      ...(parsed.subscriptionType ? { subscriptionType: parsed.subscriptionType } : {}),
      ...(parsed.authMethod ? { authMethod: parsed.authMethod } : {}),
      message: `Signed in${tail}.`,
    };
  }
  return {
    state: "not_connected",
    message: "Claude Code is installed but not signed in. Run `claude auth login` on this machine (or `claude setup-token` for headless/Docker), then click Re-check.",
  };
}

// child.stdout/stderr are typed as Readable | null, but when spawned with stdio: "pipe" they are
// actually net.Socket-like handles that support unref() at runtime. Narrow with a type guard
// instead of `any` so we can safely unref them and let the event loop exit.
function unrefIfPossible(stream: unknown): void {
  if (
    typeof stream === "object" &&
    stream !== null &&
    "unref" in stream &&
    typeof (stream as { unref: unknown }).unref === "function"
  ) {
    (stream as { unref: () => void }).unref();
  }
}

// Best-effort: start the interactive `claude auth login` on the host and capture whatever it
// prints for up to captureMs, extracting the first URL so the UI can show it. The process is
// detached and left running so the operator can complete the browser OAuth; the reliable
// confirmation is a subsequent getClaudeCodeStatus() (the dashboard's Re-check button).
export async function startClaudeLogin(
  opts: { bin?: string; captureMs?: number } = {},
): Promise<{ started: boolean; url?: string; output: string; error?: string }> {
  const bin = opts.bin?.trim() || "claude";
  const captureMs = opts.captureMs ?? 8000;
  return new Promise((resolve) => {
    let output = "";
    let settled = false;
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(bin, ["auth", "login"], { stdio: ["ignore", "pipe", "pipe"], detached: true });
    } catch (err) {
      resolve({ started: false, output: "", error: (err as Error).message });
      return;
    }
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const m = output.match(/https?:\/\/\S+/);
      child.unref();
      unrefIfPossible(child.stdout);
      unrefIfPossible(child.stderr);
      resolve({ started: true, output: output.slice(0, 2000), ...(m ? { url: m[0] } : {}) });
    };
    const timer = setTimeout(finish, captureMs);
    child.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ started: false, output, error: err.code === "ENOENT" ? "Claude Code CLI not found" : err.message });
    });
    child.stdout?.on("data", (d) => { output += d.toString(); });
    child.stderr?.on("data", (d) => { output += d.toString(); });
    child.on("close", finish);
  });
}
