import { describe, it, expect } from "vitest";
import { defaultCodexRunner } from "../../src/providers/codexRunner.js";
import { SPLIT_UTF8_TEXT, splitUtf8Script } from "../helpers/splitUtf8.js";

// codex's stdin is intentionally ignored (deadlock avoidance), so the child gets its input from
// argv. These tests spawn a real `node` subprocess to exercise the actual spawn/collect/kill path
// without depending on the `codex` binary.
describe("defaultCodexRunner", () => {
  it("collects stdout with exit code 0", async () => {
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", "process.stdout.write('HELLO')"],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.spawnError).toBeUndefined();
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("HELLO");
  });

  // Same hazard as claudeRunner: the two halves of one character arrive in separate data events,
  // and decoding each Buffer on its own strands them as two U+FFFDs (#515).
  it("reassembles multi-byte UTF-8 split across pipe chunk boundaries", async () => {
    const r = await defaultCodexRunner({
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

  it("captures stderr and a non-zero exit code", async () => {
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", "process.stderr.write('boom');process.exit(2)"],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("boom");
  });

  it("returns spawnError ENOENT when the binary is missing", async () => {
    const r = await defaultCodexRunner({
      bin: "definitely-not-a-real-binary-xyz",
      args: [],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.spawnError?.code).toBe("ENOENT");
  });

  it("kills the process and sets timedOut when the signal aborts", async () => {
    const ac = new AbortController();
    const p = defaultCodexRunner({
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
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", "setTimeout(()=>{},60000)"],
      stdin: "",
      timeoutMs: 80,
    });
    expect(r.timedOut).toBe(true);
  });

  // `codex exec --json` emits JSON, so a U+FFFD from a mis-decoded chunk boundary costs the whole
  // response. See tests/helpers/splitUtf8.ts.
  it("reassembles a character split across two stdout chunks", async () => {
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", splitUtf8Script()],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.stdout).toBe(SPLIT_UTF8_TEXT);
  });

  it("reassembles a character split across two stderr chunks", async () => {
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", splitUtf8Script({ stream: "stderr" })],
      stdin: "",
      timeoutMs: 10_000,
    });
    expect(r.stderr).toBe(SPLIT_UTF8_TEXT);
  });

  // The cap #518 gave claudeRunner, which codexRunner never got (#763). What matters is WHICH end
  // survives: `codex exec --json` emits one event per turn and the consumer reads the last one, so
  // the cap has to drop the oldest output, not the newest.
  it("keeps the tail of stdout when maxStdoutBytes is set", async () => {
    const script =
      'for (let i = 0; i < 200; i++) process.stdout.write("x".repeat(1000) + "\\n");' +
      'process.stdout.write(JSON.stringify({ type: "item.completed", text: "the answer" }) + "\\n");';
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", script],
      stdin: "",
      timeoutMs: 30_000,
      maxStdoutBytes: 16_000,
    });

    expect(r.code).toBe(0);
    expect(r.stdout.length).toBeLessThan(200_000); // the full stream is ~200 KB
    expect(r.stdout).toContain('"text":"the answer"');
  });

  // A cap named in bytes measured in UTF-16 code units undercounts every non-ASCII character, and
  // this output carries plenty of them.
  it("measures the stdout cap in UTF-8 bytes, not UTF-16 code units", async () => {
    // "€" is one UTF-16 code unit but three UTF-8 bytes: 300k of them is 300k units and 900 KB.
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", 'process.stdout.write("\\u20ac".repeat(300000))'],
      stdin: "",
      timeoutMs: 30_000,
      maxStdoutBytes: 200_000,
    });

    // The cap plus at most one whole chunk, which is always retained however large it is.
    expect(Buffer.byteLength(r.stdout, "utf8")).toBeLessThanOrEqual(300_000);
    expect(r.stdout).not.toContain("\ufffd"); // the tail is still whole characters
  });

  // stderr was the stream nobody was watching: unbounded until the child exited, so a tool that
  // logs endlessly could exhaust the heap on its own. Bounding it must cost neither reader: codex.ts
  // slices the first 300 characters into what it throws, AND classifies the error kind from the
  // whole text — and analysis/ai/retry.ts will retry a call whose rate limit it could not see.
  it("bounds stderr while keeping the error at the front AND the one at the back", async () => {
    const script =
      'process.stderr.write("Error: not logged in\\n");' +
      'for (let i = 0; i < 200; i++) process.stderr.write("x".repeat(1000) + "\\n");' +
      'process.stderr.write("429 rate limit exceeded\\n");';
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", script],
      stdin: "",
      timeoutMs: 30_000,
      maxStderrHeadBytes: 16_000,
      maxStderrTailBytes: 8_000,
    });

    expect(Buffer.byteLength(r.stderr, "utf8")).toBeLessThan(200_000);
    // The front, which the reader slices into its message.
    expect(r.stderr.slice(0, 300)).toContain("Error: not logged in");
    // The back, which decides the error KIND — and so whether the call is retried into the same
    // wall. A head-only cap dropped this line and downgraded the kind to a retryable one.
    expect(r.stderr).toContain("429 rate limit exceeded");
    expect(r.stderr).toContain("stderr truncated");
  });
});
