// cross-spawn, NOT node:child_process directly: on Windows, an npm-installed CLI (like `codex`) is a
// `.cmd` shim, and Node refuses to spawn `.cmd`/`.bat` files without `shell: true` (CVE-2024-27980).
// Naively adding `shell: true` here would be a command-injection hole, since argv is the forensic-
// evidence prompt (attacker-controlled text) — cross-spawn resolves the shim AND safely quotes each
// argument instead of using a raw shell string, matching this codebase's no-raw-shell convention
// (see toolRunner.ts / velociraptorApi.ts) while still working on Windows.
import spawn from "cross-spawn";

// Result of one Codex CLI invocation. Process-level failures (missing binary, timeout/abort) come
// back as fields rather than rejections, so the provider maps them to ProviderError uniformly.
export interface CodexRunResult {
  code: number | null;                 // exit code; null when the process was killed
  stdout: string;
  stderr: string;
  spawnError?: NodeJS.ErrnoException;  // set when the process could not be spawned (e.g. ENOENT)
  timedOut?: boolean;                  // true when killed by the timeout or the external signal
}

export interface CodexRunOptions {
  bin: string;
  args: string[];       // the prompt is passed as an argument, NOT via stdin (see below)
  timeoutMs: number;
  signal?: AbortSignal; // external cancellation
  cwd?: string;
}

export type CodexRunner = (opts: CodexRunOptions) => Promise<CodexRunResult>;

// Default runner: spawn the codex CLI, collect stdout/stderr, resolve on close. stdin is IGNORED
// (not piped) on purpose — some Codex CLI versions deadlock reading stdin, so the prompt is passed
// as an argument and the child's stdin is closed (/dev/null-like) from the start.
export const defaultCodexRunner: CodexRunner = (opts) =>
  new Promise<CodexRunResult>((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const child = spawn(opts.bin, opts.args, {
      stdio: ["ignore", "pipe", "pipe"],
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
    });

    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, opts.timeoutMs);
    const onAbort = () => { timedOut = true; child.kill("SIGKILL"); };
    if (opts.signal) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener("abort", onAbort, { once: true });
    }
    const cleanup = () => {
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
    };
    const done = (r: CodexRunResult) => { if (!settled) { settled = true; cleanup(); resolve(r); } };

    child.on("error", (err: NodeJS.ErrnoException) => done({ code: null, stdout, stderr, spawnError: err }));
    // Non-null: stdio: ["ignore", "pipe", "pipe"] above guarantees these pipes exist; cross-spawn's
    // return type is the generic ChildProcess (stdout/stderr typed nullable for other stdio configs).
    child.stdout!.on("data", (d) => { stdout += d.toString(); });
    child.stderr!.on("data", (d) => { stderr += d.toString(); });
    child.on("close", (code) => done({ code, stdout, stderr, ...(timedOut ? { timedOut: true } : {}) }));
  });
