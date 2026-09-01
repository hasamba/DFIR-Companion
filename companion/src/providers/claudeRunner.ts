import { spawn } from "node:child_process";
import {
  DEFAULT_MAX_STDERR_HEAD_BYTES,
  DEFAULT_MAX_STDERR_TAIL_BYTES,
  DEFAULT_MAX_STDOUT_BYTES,
  StreamEnds,
  StreamTail,
} from "./childStreamBuffer.js";

// Result of one CLI invocation. Process-level failures (missing binary, timeout/abort) come
// back as fields rather than rejections, so the provider maps them to ProviderError uniformly.
export interface ClaudeRunResult {
  code: number | null; // exit code; null when the process was killed
  stdout: string;
  stderr: string;
  spawnError?: NodeJS.ErrnoException; // set when the process could not be spawned (e.g. ENOENT)
  timedOut?: boolean; // true when killed by the timeout or the external signal
}

export interface ClaudeRunOptions {
  bin: string;
  args: string[];
  stdin: string; // written to the child's stdin, which is then closed
  timeoutMs: number;
  signal?: AbortSignal; // external cancellation (#225)
  /** Optional live stream taps. Callers must not persist raw chunks without sanitizing them. */
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
  /**
   * Cap on the stdout retained in the result, in bytes. Oldest output is dropped once the cap is
   * reached, so what survives is the TAIL. Unset means DEFAULT_MAX_STDOUT_BYTES; pass `Infinity` to
   * retain the whole stream.
   *
   * For a long agent run the retained buffer would otherwise grow without end: `--output-format
   * stream-json` emits every tool result as an event, and a 40-turn investigation over a memory
   * image can carry far more of them than any consumer reads back (#518). Lower this where the
   * consumer reads the end of the stream — both `terminalResult` and `finalText` scan for the LAST
   * `result` event and already skip lines that do not parse, so a truncated first line costs
   * nothing.
   */
  maxStdoutBytes?: number;
  /**
   * Caps on the stderr retained in the result, in bytes. Unset means the DEFAULT_MAX_STDERR_*
   * constants. stderr keeps BOTH ENDS and discards the middle, because its two readers want
   * opposite parts: claudeCode.ts and finalText slice the first 200 characters into the error they
   * throw, while the kind an error is classified as can turn on a line printed at the very end.
   */
  maxStderrHeadBytes?: number;
  maxStderrTailBytes?: number;
}

export type ClaudeRunner = (opts: ClaudeRunOptions) => Promise<ClaudeRunResult>;

// Default runner: spawn the claude CLI, feed stdin, collect stdout/stderr, resolve on close.
export const defaultClaudeRunner: ClaudeRunner = (opts) =>
  new Promise<ClaudeRunResult>((resolve) => {
    // Both streams are bounded by default. A cap only the caller can ask for is one every new call
    // site re-opens by forgetting it, which is the whole of #762 — so the fallback is a finite
    // ceiling and `Infinity` is the explicit opt-out.
    const stdout = new StreamTail(opts.maxStdoutBytes ?? DEFAULT_MAX_STDOUT_BYTES);
    const stderr = new StreamEnds(
      opts.maxStderrHeadBytes ?? DEFAULT_MAX_STDERR_HEAD_BYTES,
      opts.maxStderrTailBytes ?? DEFAULT_MAX_STDERR_TAIL_BYTES,
    );
    let settled = false;
    let timedOut = false;

    const child = spawn(opts.bin, opts.args, { stdio: ["pipe", "pipe", "pipe"] });

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
    const done = (r: ClaudeRunResult) => {
      if (!settled) {
        settled = true;
        cleanup();
        resolve(r);
      }
    };

    child.on("error", (err: NodeJS.ErrnoException) =>
      done({ code: null, stdout: stdout.text(), stderr: stderr.text(), spawnError: err }),
    );
    // Decode through the stream's own StringDecoder, which holds a partial multi-byte sequence back
    // until the rest arrives. Calling toString() on each Buffer instead turns any character split
    // across a ~64 KB pipe chunk into two U+FFFDs that concatenation cannot repair — corrupting
    // non-ASCII evidence and breaking JSON.parse on stream-json lines (#515).
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout.push(chunk);
      // The tap gets every chunk whatever the cap drops: it feeds the live stream in the UI, which
      // consumes output as it arrives rather than reading the buffer back.
      opts.onStdout?.(chunk);
    });
    child.stderr.on("data", (chunk: string) => {
      stderr.push(chunk);
      opts.onStderr?.(chunk);
    });
    child.on("close", (code) =>
      done({
        code,
        stdout: stdout.text(),
        stderr: stderr.text(),
        ...(timedOut ? { timedOut: true } : {}),
      }),
    );

    child.stdin.on("error", () => {
      /* ignore EPIPE if the child exits before we finish writing */
    });
    child.stdin.end(opts.stdin);
  });
