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
    // A 3-byte character on purpose: the 64 KB boundary is not a multiple of 3, so a split is
    // guaranteed. A 2-byte character would align with the boundary and never reproduce the bug.
    const EXPECTED = "€".repeat(70_000); // 210 KB
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", 'process.stdout.write("\\u20ac".repeat(70000))'],
      stdin: "",
      timeoutMs: 30_000,
    });
    expect(r.stdout).not.toContain("�");
    expect(r.stdout).toBe(EXPECTED);
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
