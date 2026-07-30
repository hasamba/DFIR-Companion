import { spawn } from "node:child_process";

// Result of one CLI invocation. Process-level failures (missing binary, timeout/abort) come
// back as fields rather than rejections, so the provider maps them to ProviderError uniformly.
export interface ClaudeRunResult {
  code: number | null;                 // exit code; null when the process was killed
  stdout: string;
  stderr: string;
  spawnError?: NodeJS.ErrnoException;  // set when the process could not be spawned (e.g. ENOENT)
  timedOut?: boolean;                  // true when killed by the timeout or the external signal
}

export interface ClaudeRunOptions {
  bin: string;
  args: string[];
  stdin: string;      // written to the child's stdin, which is then closed
  timeoutMs: number;
  signal?: AbortSignal; // external cancellation (#225)
  /** Optional live stream taps. Callers must not persist raw chunks without sanitizing them. */
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

export type ClaudeRunner = (opts: ClaudeRunOptions) => Promise<ClaudeRunResult>;

// Default runner: spawn the claude CLI, feed stdin, collect stdout/stderr, resolve on close.
export const defaultClaudeRunner: ClaudeRunner = (opts) =>
  new Promise<ClaudeRunResult>((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const child = spawn(opts.bin, opts.args, { stdio: ["pipe", "pipe", "pipe"] });

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
    const done = (r: ClaudeRunResult) => { if (!settled) { settled = true; cleanup(); resolve(r); } };

    child.on("error", (err: NodeJS.ErrnoException) => done({ code: null, stdout, stderr, spawnError: err }));
    child.stdout.on("data", (d) => {
      const chunk = d.toString();
      stdout += chunk;
      opts.onStdout?.(chunk);
    });
    child.stderr.on("data", (d) => {
      const chunk = d.toString();
      stderr += chunk;
      opts.onStderr?.(chunk);
    });
    child.on("close", (code) => done({ code, stdout, stderr, ...(timedOut ? { timedOut: true } : {}) }));

    child.stdin.on("error", () => { /* ignore EPIPE if the child exits before we finish writing */ });
    child.stdin.end(opts.stdin);
  });
