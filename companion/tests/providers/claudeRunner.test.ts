import { describe, it, expect } from "vitest";
import { defaultClaudeRunner } from "../../src/providers/claudeRunner.js";
import { SPLIT_UTF8_TEXT, splitUtf8Script } from "../helpers/splitUtf8.js";

// A tiny node program that echoes its stdin back with a prefix, so we exercise the real
// spawn + stdin-write + stdout-collect path without depending on the `claude` binary.
const ECHO =
  'let d="";process.stdin.on("data",x=>d+=x);process.stdin.on("end",()=>process.stdout.write("GOT:"+d));';

describe("defaultClaudeRunner", () => {
  it("feeds stdin and collects stdout with exit code 0", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", ECHO],
      stdin: "hello",
      timeoutMs: 10_000,
    });
    expect(r.spawnError).toBeUndefined();
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("GOT:hello");
  });

  // A pipe delivers ~64 KB per data event, wherever that lands in the byte stream. Decoding each
  // Buffer on its own splits any multi-byte character straddling the boundary into two U+FFFDs that
  // concatenation cannot repair — mangling non-ASCII evidence (hostnames, filenames) or breaking
  // JSON.parse on a stream-json line, which the MCP runner then silently skips (#515).
  it("reassembles multi-byte UTF-8 split across pipe chunk boundaries", async () => {
    // Split one character across two writes explicitly rather than relying on where a ~64 KB pipe
    // boundary happens to land — that is platform- and scheduling-dependent, so a size-based test
    // can pass against the unfixed code on a kernel that happens to align the reads.
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: [
        "-e",
        'const b=Buffer.from("\\u20ac","utf8");process.stdout.write(b.subarray(0,1));setTimeout(()=>process.stdout.write(b.subarray(1)),50);',
      ],
      stdin: "",
      timeoutMs: 30_000,
    });
    expect(r.stdout).not.toContain("�");
    expect(r.stdout).toBe("€");
  });

  // maxStdoutBytes exists so a long agent run does not retain every tool_result event for the life
  // of the process. What matters is WHICH end survives: consumers scan for the LAST result line
  // (#518), so the cap has to drop the oldest output, not the newest.
  it("keeps the tail of stdout when maxStdoutBytes is set", async () => {
    const script =
      'for (let i = 0; i < 200; i++) process.stdout.write("x".repeat(1000) + "\\n");' +
      'process.stdout.write(JSON.stringify({ type: "result", result: "the answer" }) + "\\n");';
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", script],
      stdin: "",
      timeoutMs: 30_000,
      maxStdoutBytes: 16_000,
    });

    expect(r.code).toBe(0);
    expect(r.stdout.length).toBeLessThan(200_000); // the full stream is ~200 KB
    // The end survived: the result line a consumer needs is still there.
    expect(r.stdout).toContain('"result":"the answer"');
  });

  // The cap is named in bytes, so it has to be measured in bytes. String.length counts UTF-16 code
  // units, which undercounts every non-ASCII character — and this output carries plenty of them, so
  // a cap measured that way would let the buffer run to several times its stated limit.
  it("measures the cap in UTF-8 bytes, not UTF-16 code units", async () => {
    // "€" is one UTF-16 code unit but three UTF-8 bytes, so 300k of them is 300k units and 900 KB.
    // Counting units against a 200 KB cap would retain 200k of them — 600 KB, three times the cap.
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", 'process.stdout.write("\\u20ac".repeat(300000))'],
      stdin: "",
      timeoutMs: 30_000,
      maxStdoutBytes: 200_000,
    });

    // The cap plus at most one whole chunk, which is always retained however large it is.
    expect(Buffer.byteLength(r.stdout, "utf8")).toBeLessThanOrEqual(300_000);
    expect(r.stdout).not.toContain("�"); // the tail is still whole characters
  });

  it("keeps everything when the stream is far under the default cap", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", 'process.stdout.write("y".repeat(100000))'],
      stdin: "",
      timeoutMs: 30_000,
    });
    expect(r.stdout.length).toBe(100_000);
  });

  // stderr was the stream nobody was watching: unbounded until the child exited, so a runaway agent
  // could exhaust the heap through it alone (#762). Bounding it must cost neither reader: the front
  // is what claudeCode.ts and finalText slice into the error they throw, and the back is where an
  // error printed after a flood of progress output ends up.
  it("bounds stderr while keeping the error at the front AND the one at the back", async () => {
    const script =
      'process.stderr.write("Error: not logged in\\n");' +
      'for (let i = 0; i < 200; i++) process.stderr.write("x".repeat(1000) + "\\n");' +
      'process.stderr.write("429 rate limit exceeded\\n");';
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", script],
      stdin: "",
      timeoutMs: 30_000,
      maxStderrHeadBytes: 16_000,
      maxStderrTailBytes: 8_000,
    });

    expect(Buffer.byteLength(r.stderr, "utf8")).toBeLessThan(200_000);
    // The front, which the reader slices into its message.
    expect(r.stderr.slice(0, 200)).toContain("Error: not logged in");
    // The back, which decides the error KIND — and so whether the call is retried into the same
    // wall. A head-only cap dropped this line and downgraded the kind to a retryable one.
    expect(r.stderr).toContain("429 rate limit exceeded");
    expect(r.stderr).toContain("stderr truncated");
  });

  it("reports a non-zero exit code", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", "process.exit(3)"],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.code).toBe(3);
  });

  it("returns spawnError ENOENT when the binary is missing", async () => {
    const r = await defaultClaudeRunner({
      bin: "definitely-not-a-real-binary-xyz",
      args: [],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.spawnError?.code).toBe("ENOENT");
  });

  it("kills the process and sets timedOut when the signal aborts", async () => {
    const ac = new AbortController();
    const p = defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", "setTimeout(()=>{},60000)"],
      stdin: "",
      timeoutMs: 60_000,
      signal: ac.signal,
    });
    setTimeout(() => ac.abort(), 50);
    const r = await p;
    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
  });

  it("sets timedOut when timeoutMs elapses", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", "setTimeout(()=>{},60000)"],
      stdin: "",
      timeoutMs: 80,
    });
    expect(r.timedOut).toBe(true);
  });

  // The model's answer is JSON. One U+FFFD inside it and the whole response fails to parse — see
  // tests/helpers/splitUtf8.ts for why a chunk boundary lands mid-character in the first place.
  it("reassembles a character split across two stdout chunks", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", splitUtf8Script()],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.stdout).toBe(SPLIT_UTF8_TEXT);
  });

  it("reassembles a character split across two stderr chunks", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", splitUtf8Script({ stream: "stderr" })],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.stderr).toBe(SPLIT_UTF8_TEXT);
  });

  // The tap feeds the live stream in the UI, so it must be handed decoded text — not the raw
  // per-chunk decode that the accumulated string is built from.
  it("hands the stdout tap decoded chunks that rejoin into the original text", async () => {
    const seen: string[] = [];
    await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", splitUtf8Script()],
      stdin: "",
      timeoutMs: 10_000,
      onStdout: (c) => seen.push(c),
    });
    expect(seen.join("")).toBe(SPLIT_UTF8_TEXT);
  });
});
