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
  /**
   * Cap on the stdout retained in the result, in bytes. Oldest output is dropped once the cap is
   * reached, so what survives is the TAIL. Unset means keep everything.
   *
   * For a long agent run the retained buffer is otherwise unbounded: `--output-format stream-json`
   * emits every tool result as an event, and a 40-turn investigation over a memory image can carry
   * far more of them than any consumer reads back (#518). Only set this where the consumer reads
   * the end of the stream — both `terminalResult` and `finalText` scan for the LAST `result` event
   * and already skip lines that do not parse, so a truncated first line costs nothing.
   */
  maxStdoutBytes?: number;
}

export type ClaudeRunner = (opts: ClaudeRunOptions) => Promise<ClaudeRunResult>;

// Default runner: spawn the claude CLI, feed stdin, collect stdout/stderr, resolve on close.
export const defaultClaudeRunner: ClaudeRunner = (opts) =>
  new Promise<ClaudeRunResult>((resolve) => {
    // Retained as chunks rather than one growing string so the cap can drop the oldest ones without
    // rebuilding the whole buffer on every event. Each chunk's UTF-8 size is kept alongside it:
    // String.length counts UTF-16 code units, which undercounts every non-ASCII character — and
    // non-ASCII is exactly what this output carries (hostnames, filenames, quoted log text), so a
    // byte cap measured in code units would let the buffer run several times over its limit.
    const stdoutChunks: string[] = [];
    const stdoutChunkBytes: number[] = [];
    let stdoutBytes = 0;
    const maxStdoutBytes = opts.maxStdoutBytes ?? Infinity;
    const stdoutText = () => stdoutChunks.join("");
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

    child.on("error", (err: NodeJS.ErrnoException) => done({ code: null, stdout: stdoutText(), stderr, spawnError: err }));
    // Decode through the stream's own StringDecoder, which holds a partial multi-byte sequence back
    // until the rest arrives. Calling toString() on each Buffer instead turns any character split
    // across a ~64 KB pipe chunk into two U+FFFDs that concatenation cannot repair — corrupting
    // non-ASCII evidence and breaking JSON.parse on stream-json lines (#515).
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdoutChunks.push(chunk);
      const chunkBytes = Buffer.byteLength(chunk, "utf8");
      stdoutChunkBytes.push(chunkBytes);
      stdoutBytes += chunkBytes;
      // Keep at least the newest chunk, however large it is: a cap must never yield empty output.
      while (stdoutBytes > maxStdoutBytes && stdoutChunks.length > 1) {
        stdoutChunks.shift();
        stdoutBytes -= stdoutChunkBytes.shift()!;
      }
      opts.onStdout?.(chunk);
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
      opts.onStderr?.(chunk);
    });
    child.on("close", (code) => done({ code, stdout: stdoutText(), stderr, ...(timedOut ? { timedOut: true } : {}) }));

    child.stdin.on("error", () => { /* ignore EPIPE if the child exits before we finish writing */ });
    child.stdin.end(opts.stdin);
  });
