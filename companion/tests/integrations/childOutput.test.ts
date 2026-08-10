import { describe, it, expect } from "vitest";
import { ChildOutputCollector, DEFAULT_STDERR_TAIL_BYTES } from "../../src/integrations/childOutput.js";

// Two defects this collector exists to prevent, both of which shipped in BOTH child-process runners:
// an unbounded stderr that a hostile or malfunctioning forensic tool could use to exhaust the heap,
// and a "maxOutputBytes" cap that actually counted UTF-16 string length.

describe("ChildOutputCollector — stdout budget", () => {
  it("does not signal while the budget is intact", () => {
    const out = new ChildOutputCollector(10);
    expect(out.pushStdout(Buffer.from("12345"))).toBe(false);
    expect(out.pushStdout(Buffer.from("67890"))).toBe(false);
    expect(out.stdoutByteLength).toBe(10);
  });

  it("signals as soon as the budget is exceeded", () => {
    const out = new ChildOutputCollector(4);
    expect(out.pushStdout(Buffer.from("abcd"))).toBe(false);
    expect(out.pushStdout(Buffer.from("e"))).toBe(true);
  });

  // The bug: "€" is 1 JavaScript string unit but 3 UTF-8 bytes, so a string-length cap let output
  // run to three times the limit the operator configured.
  it("counts BYTES, not string length, for multibyte output", () => {
    const out = new ChildOutputCollector(6);
    const euro = Buffer.from("€€€", "utf8"); // 9 bytes, 3 string units

    expect(euro.byteLength).toBe(9);
    expect(euro.toString("utf8").length).toBe(3);
    expect(out.pushStdout(euro)).toBe(true); // a length-based cap would have said false
    expect(out.stdoutByteLength).toBe(9);
  });

  // The other half: decoding each chunk as it arrived turned a character split across a chunk
  // boundary into replacement characters, silently corrupting what an importer then parsed.
  it("decodes once, so a character split across chunks survives", () => {
    const out = new ChildOutputCollector(1024);
    const euro = Buffer.from("€", "utf8");

    out.pushStdout(euro.subarray(0, 1));
    out.pushStdout(euro.subarray(1));

    expect(out.text().stdout).toBe("€");
    expect(out.text().stdout).not.toContain("�");
  });
});

describe("ChildOutputCollector — stderr tail", () => {
  it("keeps stderr whole while it fits the tail budget", () => {
    const out = new ChildOutputCollector(1024, 32);
    out.pushStderr(Buffer.from("warning: one\n"));
    out.pushStderr(Buffer.from("warning: two\n"));
    expect(out.text().stderr).toBe("warning: one\nwarning: two\n");
  });

  // A tool that logs forever must not grow the heap. It also must not cost us the END of the log,
  // which is the part that explains the failure.
  it("bounds a flood and retains the tail, not the head", () => {
    const out = new ChildOutputCollector(1024, 64);
    for (let i = 0; i < 1000; i++) out.pushStderr(Buffer.from(`line ${i}\n`));

    expect(out.stderrByteLength).toBeLessThanOrEqual(64);
    expect(out.text().stderr).toContain("line 999");
    expect(out.text().stderr).not.toContain("line 0\n");
  });

  it("cuts a single write larger than the whole tail budget", () => {
    const out = new ChildOutputCollector(1024, 16);
    out.pushStderr(Buffer.from("x".repeat(1000) + "END"));

    expect(out.stderrByteLength).toBe(16);
    expect(out.text().stderr.endsWith("END")).toBe(true);
  });

  // stderr is diagnostics: a verbose tool is normal, so the tail must never be the reason a run dies.
  it("never signals fatal, however much arrives", () => {
    const out = new ChildOutputCollector(4, 8);
    for (let i = 0; i < 100; i++) out.pushStderr(Buffer.from("noise noise noise\n"));

    expect(out.pushStdout(Buffer.from("ab"))).toBe(false);
    expect(out.stdoutByteLength).toBe(2);
  });

  it("defaults the tail to a bounded size rather than unlimited", () => {
    const out = new ChildOutputCollector(1024);
    for (let i = 0; i < 200; i++) out.pushStderr(Buffer.alloc(4096, 0x61));

    expect(DEFAULT_STDERR_TAIL_BYTES).toBeGreaterThan(0);
    expect(out.stderrByteLength).toBeLessThanOrEqual(DEFAULT_STDERR_TAIL_BYTES);
  });
});

describe("ChildOutputCollector — combined", () => {
  it("keeps the two streams separate", () => {
    const out = new ChildOutputCollector(1024, 1024);
    out.pushStdout(Buffer.from("result"));
    out.pushStderr(Buffer.from("diagnostic"));

    expect(out.text()).toEqual({ stdout: "result", stderr: "diagnostic" });
  });

  it("reports empty strings when the child wrote nothing", () => {
    expect(new ChildOutputCollector(16).text()).toEqual({ stdout: "", stderr: "" });
  });
});
