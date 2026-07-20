import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
// cross-spawn: see codexRunner.ts — resolves the Windows `.cmd` shim without a raw shell string.
import spawn from "cross-spawn";
import { type CodexRunner, defaultCodexRunner } from "./codexRunner.js";

export type CodexAuthState = "not_installed" | "not_connected" | "connected";

export interface CodexStatus {
  state: CodexAuthState;
  authMethod?: string;
  message: string;
}

export interface GetCodexStatusOptions {
  bin?: string;
  runner?: CodexRunner;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  authFileExists?: () => boolean; // injected in tests; defaults to checking ~/.codex/auth.json
}

function defaultAuthFileExists(env: NodeJS.ProcessEnv): boolean {
  const home = env.CODEX_HOME && env.CODEX_HOME.trim() ? env.CODEX_HOME : join(homedir(), ".codex");
  return existsSync(join(home, "auth.json"));
}

// Detect whether Codex is installed and authenticated. There is no `codex auth status --json`, so
// this mirrors the gstack probe: binary presence + (env API key OR ~/.codex/auth.json). Never throws.
export async function getCodexStatus(opts: GetCodexStatusOptions = {}): Promise<CodexStatus> {
  const bin = opts.bin?.trim() || "codex";
  const runner = opts.runner ?? defaultCodexRunner;
  const env = opts.env ?? process.env;
  const authFileExists = opts.authFileExists ?? (() => defaultAuthFileExists(env));

  const run = await runner({ bin, args: ["--version"], stdin: "", timeoutMs: opts.timeoutMs ?? 10_000 });
  if (run.spawnError) {
    const msg = run.spawnError.code === "ENOENT"
      ? "Codex CLI isn't installed on this machine. Install it (`npm i -g @openai/codex`), then click Re-check."
      : `Codex could not be run: ${run.spawnError.message}`;
    return { state: "not_installed", message: msg };
  }

  const envKey = (env.OPENAI_API_KEY || env.CODEX_API_KEY || "").trim();
  if (envKey) {
    return { state: "connected", authMethod: "api_key", message: "Codex is ready (using an API key from the environment)." };
  }
  if (authFileExists()) {
    return { state: "connected", authMethod: "codex login", message: "Codex is ready (signed in via `codex login`)." };
  }
  return {
    state: "not_connected",
    message: "Codex is installed but not signed in. Run `codex login` (or set OPENAI_API_KEY), then click Re-check.",
  };
}

// Best-effort: start the interactive `codex login` on the host and capture whatever it prints for
// up to captureMs, extracting the first URL so the UI can show it. The process is detached and its
// pipe streams are unref'd so it can't keep the server process alive; the reliable confirmation is
// a subsequent getCodexStatus() (the dashboard's Re-check button).
export async function startCodexLogin(
  opts: { bin?: string; captureMs?: number } = {},
): Promise<{ started: boolean; url?: string; output: string; error?: string }> {
  const bin = opts.bin?.trim() || "codex";
  const captureMs = opts.captureMs ?? 8000;
  return new Promise((resolve) => {
    let output = "";
    let settled = false;
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(bin, ["login"], { stdio: ["ignore", "pipe", "pipe"], detached: true });
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
      resolve({ started: false, output, error: err.code === "ENOENT" ? "Codex CLI not found" : err.message });
    });
    child.stdout?.on("data", (d) => { output += d.toString(); });
    child.stderr?.on("data", (d) => { output += d.toString(); });
    child.on("close", finish);
  });
}

// child.stdout/stderr are typed Readable (no unref in the type) but are net.Socket-like handles
// that support unref() at runtime. Narrow with a type guard instead of `any` so we can safely
// unref them and let the event loop exit.
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
