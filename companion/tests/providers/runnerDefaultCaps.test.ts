import { describe, it, expect, vi } from "vitest";

// The two provider runners buffer a coding agent's output, and that output is attacker-influenced:
// the agent runs over forensic evidence and emits one event per tool result. Before #762/#763 the
// fallback was Infinity for claudeRunner and no cap at all for codexRunner, so every call site that
// forgot to pass a limit re-opened the unbounded-buffer hole #518 had closed for the one that
// remembered.
//
// Substituting small ceilings is the only way to watch the FALLBACK work without pushing 64 MB
// through a pipe. It also proves each runner reads the shared constants rather than hardcoding a
// limit of its own — a runner that ignored them would keep the whole stream and fail here.
vi.mock("../../src/providers/childStreamBuffer.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/providers/childStreamBuffer.js")>();
  return { ...actual, DEFAULT_MAX_STDOUT_BYTES: 16_000, DEFAULT_MAX_STDERR_BYTES: 8_000 };
});

import { defaultClaudeRunner } from "../../src/providers/claudeRunner.js";
import { defaultCodexRunner } from "../../src/providers/codexRunner.js";

/**
 * Three separated writes to `stream`, ~20 KB each, so the parent sees three distinct data events.
 * Relying on a single large write would leave the chunk boundaries to the kernel, and one chunk is
 * always retained whole — a size-based test could then pass against the uncapped code.
 */
const burstScript = (stream: "stdout" | "stderr"): string =>
  `const w = (s) => process.${stream}.write(s);` +
  `w("HEAD-MARKER" + "a".repeat(20000) + "\\n");` +
  `setTimeout(() => { w("b".repeat(20000) + "\\n");` +
  `setTimeout(() => w("TAIL-MARKER\\n"), 40); }, 40);`;

describe("provider runners cap their buffers with no cap passed", () => {
  it("claudeRunner drops the oldest stdout and keeps the tail", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", burstScript("stdout")],
      stdin: "",
      timeoutMs: 30_000,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("TAIL-MARKER");
    expect(r.stdout).not.toContain("HEAD-MARKER");
  });

  it("claudeRunner keeps the head of stderr, which is the end its readers slice", async () => {
    const r = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", burstScript("stderr")],
      stdin: "",
      timeoutMs: 30_000,
    });
    // The opposite end from stdout, and deliberately: claudeCode.ts, codex.ts and finalText all
    // slice the FIRST 200-300 characters of stderr into the error message they raise, and codex.ts
    // orders its errors so the real cause is not pushed past that truncation.
    expect(r.stderr).toContain("HEAD-MARKER");
    expect(r.stderr).not.toContain("TAIL-MARKER");
  });

  it("codexRunner drops the oldest stdout and keeps the tail", async () => {
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", burstScript("stdout")],
      stdin: "",
      timeoutMs: 30_000,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("TAIL-MARKER");
    expect(r.stdout).not.toContain("HEAD-MARKER");
  });

  it("codexRunner keeps the head of stderr, which is the end its readers slice", async () => {
    const r = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", burstScript("stderr")],
      stdin: "",
      timeoutMs: 30_000,
    });
    // The opposite end from stdout, and deliberately: claudeCode.ts, codex.ts and finalText all
    // slice the FIRST 200-300 characters of stderr into the error message they raise, and codex.ts
    // orders its errors so the real cause is not pushed past that truncation.
    expect(r.stderr).toContain("HEAD-MARKER");
    expect(r.stderr).not.toContain("TAIL-MARKER");
  });

  // The opt-out has to stay available and has to read as deliberate at the call site: a consumer
  // that genuinely needs the whole stream passes Infinity rather than silently getting it.
  it("keeps the whole stream when a caller passes Infinity", async () => {
    const claude = await defaultClaudeRunner({
      bin: process.execPath,
      args: ["-e", burstScript("stdout")],
      stdin: "",
      timeoutMs: 30_000,
      maxStdoutBytes: Infinity,
    });
    expect(claude.stdout).toContain("HEAD-MARKER");
    expect(claude.stdout).toContain("TAIL-MARKER");

    const codex = await defaultCodexRunner({
      bin: process.execPath,
      args: ["-e", burstScript("stdout")],
      stdin: "",
      timeoutMs: 30_000,
      maxStdoutBytes: Infinity,
    });
    expect(codex.stdout).toContain("HEAD-MARKER");
    expect(codex.stdout).toContain("TAIL-MARKER");
  });
});
