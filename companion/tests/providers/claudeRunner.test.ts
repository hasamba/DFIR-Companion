import { describe, it, expect } from "vitest";
import { defaultClaudeRunner } from "../../src/providers/claudeRunner.js";

// A tiny node program that echoes its stdin back with a prefix, so we exercise the real
// spawn + stdin-write + stdout-collect path without depending on the `claude` binary.
const ECHO = 'let d="";process.stdin.on("data",x=>d+=x);process.stdin.on("end",()=>process.stdout.write("GOT:"+d));';

describe("defaultClaudeRunner", () => {
  it("feeds stdin and collects stdout with exit code 0", async () => {
    const r = await defaultClaudeRunner({ bin: process.execPath, args: ["-e", ECHO], stdin: "hello", timeoutMs: 10_000 });
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

  it("reports a non-zero exit code", async () => {
    const r = await defaultClaudeRunner({ bin: process.execPath, args: ["-e", "process.exit(3)"], stdin: "", timeoutMs: 10_000 });
    expect(r.code).toBe(3);
  });

  it("returns spawnError ENOENT when the binary is missing", async () => {
    const r = await defaultClaudeRunner({ bin: "definitely-not-a-real-binary-xyz", args: [], stdin: "", timeoutMs: 10_000 });
    expect(r.spawnError?.code).toBe("ENOENT");
  });

  it("kills the process and sets timedOut when the signal aborts", async () => {
    const ac = new AbortController();
    const p = defaultClaudeRunner({ bin: process.execPath, args: ["-e", "setTimeout(()=>{},60000)"], stdin: "", timeoutMs: 60_000, signal: ac.signal });
    setTimeout(() => ac.abort(), 50);
    const r = await p;
    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
  });

  it("sets timedOut when timeoutMs elapses", async () => {
    const r = await defaultClaudeRunner({ bin: process.execPath, args: ["-e", "setTimeout(()=>{},60000)"], stdin: "", timeoutMs: 80 });
    expect(r.timedOut).toBe(true);
  });
});
