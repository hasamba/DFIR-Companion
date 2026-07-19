import { describe, it, expect } from "vitest";
import { defaultCodexRunner } from "../../src/providers/codexRunner.js";

// codex's stdin is intentionally ignored (deadlock avoidance), so the child gets its input from
// argv. These tests spawn a real `node` subprocess to exercise the actual spawn/collect/kill path
// without depending on the `codex` binary.
describe("defaultCodexRunner", () => {
  it("collects stdout with exit code 0", async () => {
    const r = await defaultCodexRunner({ bin: process.execPath, args: ["-e", "process.stdout.write('HELLO')"], stdin: "", timeoutMs: 10_000 });
    expect(r.spawnError).toBeUndefined();
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("HELLO");
  });

  it("captures stderr and a non-zero exit code", async () => {
    const r = await defaultCodexRunner({ bin: process.execPath, args: ["-e", "process.stderr.write('boom');process.exit(2)"], stdin: "", timeoutMs: 10_000 });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("boom");
  });

  it("returns spawnError ENOENT when the binary is missing", async () => {
    const r = await defaultCodexRunner({ bin: "definitely-not-a-real-binary-xyz", args: [], stdin: "", timeoutMs: 10_000 });
    expect(r.spawnError?.code).toBe("ENOENT");
  });

  it("kills the process and sets timedOut when the signal aborts", async () => {
    const ac = new AbortController();
    const p = defaultCodexRunner({ bin: process.execPath, args: ["-e", "setTimeout(()=>{},60000)"], stdin: "", timeoutMs: 60_000, signal: ac.signal });
    setTimeout(() => ac.abort(), 50);
    const r = await p;
    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
  });

  it("sets timedOut when timeoutMs elapses", async () => {
    const r = await defaultCodexRunner({ bin: process.execPath, args: ["-e", "setTimeout(()=>{},60000)"], stdin: "", timeoutMs: 80 });
    expect(r.timedOut).toBe(true);
  });
});
