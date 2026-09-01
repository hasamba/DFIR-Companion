// cross-spawn, NOT node:child_process directly: on Windows, an npm-installed CLI (like `codex`) is a
// `.cmd` shim, and Node refuses to spawn `.cmd`/`.bat` files without `shell: true` (CVE-2024-27980).
// Naively adding `shell: true` here would be a command-injection hole, since argv is the forensic-
// evidence prompt (attacker-controlled text) — cross-spawn resolves the shim AND safely quotes each
// argument instead of using a raw shell string, matching this codebase's no-raw-shell convention
// (see toolRunner.ts / velociraptorApi.ts) while still working on Windows.
import spawn from "cross-spawn";
import { DEFAULT_MAX_STDERR_BYTES, DEFAULT_MAX_STDOUT_BYTES, StreamTail } from "./childStreamTail.js";

// Result of one Codex CLI invocation. Process-level failures (missing binary, timeout/abort) come
// back as fields rather than rejections, so the provider maps them to ProviderError uniformly.
export interface CodexRunResult {
  code: number | null; // exit code; null when the process was killed
  stdout: string;
  stderr: string;
  spawnError?: NodeJS.ErrnoException; // set when the process could not be spawned (e.g. ENOENT)
  timedOut?: boolean; // true when killed by the timeout or the external signal
}

export interface CodexRunOptions {
  bin: string;
  args: string[];
  stdin: string; // the prompt, written to the child's stdin and then closed (see below)
  timeoutMs: number;
  signal?: AbortSignal; // external cancellation
  cwd?: string;
  /**
   * Cap on the stdout retained in the result, in bytes. Oldest output is dropped once the cap is
   * reached, so what survives is the TAIL. Unset means DEFAULT_MAX_STDOUT_BYTES; pass `Infinity` to
   * retain the whole stream.
   *
   * `codex exec --json` emits one event per turn over evidence the runner does not control, so the
   * stream has no length this code can assume (#763). The consumer reads the LAST event and skips
   * lines that do not parse, so a truncated first line costs nothing.
   */
  maxStdoutBytes?: number;
  /**
   * Cap on the stderr retained in the result, in bytes, with the same tail-drop semantics. Unset
   * means DEFAULT_MAX_STDERR_BYTES. The consumer takes a 300-character snippet for an error
   * message, so the tail is all it reads.
   */
  maxStderrBytes?: number;
}

export type CodexRunner = (opts: CodexRunOptions) => Promise<CodexRunResult>;

// Default runner: spawn the codex CLI, feed the prompt via stdin, collect stdout/stderr, resolve on
// close. The prompt goes over stdin — NOT argv — because `.cmd`-shimmed CLIs (npm-installed `codex`
// on Windows) run through cmd.exe, whose command-line length limit (~8KB) is far below a typical
// DFIR synthesis prompt (routinely 20-30K+ chars); `codex exec --help` documents stdin as exactly
// this large-input path when no PROMPT argument is given. Live-verified this doesn't deadlock on a
// real `codex exec --json` invocation with a 29K-char stdin payload.
export const defaultCodexRunner: CodexRunner = (opts) =>
  new Promise<CodexRunResult>((resolve) => {
    // Bounded by default, like claudeRunner: `stdout += chunk` retains a runaway run's whole output
    // until the heap gives out, and this runner had no cap to pass even if a caller wanted one
    // (#763). `Infinity` is the explicit opt-out.
    const stdout = new StreamTail(opts.maxStdoutBytes ?? DEFAULT_MAX_STDOUT_BYTES);
    const stderr = new StreamTail(opts.maxStderrBytes ?? DEFAULT_MAX_STDERR_BYTES);
    let settled = false;
    let timedOut = false;

    const child = spawn(opts.bin, opts.args, {
      stdio: ["pipe", "pipe", "pipe"],
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, opts.timeoutMs);
    const onAbort = () => {
      timedOut = true;
      child.kill("SIGKILL");
    };
    if (opts.signal) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener("abort", onAbort, { once: true });
    }
    const cleanup = () => {
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
    };
    const done = (r: CodexRunResult) => {
      if (!settled) {
        settled = true;
        cleanup();
        resolve(r);
      }
    };

    child.on("error", (err: NodeJS.ErrnoException) =>
      done({ code: null, stdout: stdout.text(), stderr: stderr.text(), spawnError: err }),
    );
    // Non-null: stdio: ["pipe", "pipe", "pipe"] above guarantees these pipes exist; cross-spawn's
    // return type is the generic ChildProcess (stdout/stderr/stdin typed nullable for other stdio configs).
    // setEncoding, not per-chunk toString(): the stream's StringDecoder holds a partial multi-byte
    // sequence until the rest arrives, so a character split across a ~64 KB pipe chunk survives
    // instead of decoding to two unrecoverable U+FFFDs (#515).
    child.stdout!.setEncoding("utf8");
    child.stderr!.setEncoding("utf8");
    child.stdout!.on("data", (chunk: string) => {
      stdout.push(chunk);
    });
    child.stderr!.on("data", (chunk: string) => {
      stderr.push(chunk);
    });
    child.on("close", (code) =>
      done({
        code,
        stdout: stdout.text(),
        stderr: stderr.text(),
        ...(timedOut ? { timedOut: true } : {}),
      }),
    );

    child.stdin!.on("error", () => {
      /* ignore EPIPE if the child exits before we finish writing */
    });
    child.stdin!.end(opts.stdin);
  });
