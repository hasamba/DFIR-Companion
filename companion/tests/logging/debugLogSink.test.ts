import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createRotatingDebugLog,
  parseDebugLogMaxMb,
  truncateLine,
  DEFAULT_DEBUG_LOG_MAX_MB,
  type DebugLogFs,
} from "../../src/logging/debugLogSink.js";

const realFs = fs as unknown as DebugLogFs;

function sizeOf(path: string): number {
  return existsSync(path) ? statSync(path).size : 0;
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "debuglog-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("parseDebugLogMaxMb", () => {
  it("defaults to 50 when absent or invalid", () => {
    expect(DEFAULT_DEBUG_LOG_MAX_MB).toBe(50);
    expect(parseDebugLogMaxMb(undefined)).toBe(50);
    expect(parseDebugLogMaxMb("")).toBe(50);
    expect(parseDebugLogMaxMb("  ")).toBe(50);
    expect(parseDebugLogMaxMb("lots")).toBe(50);
    expect(parseDebugLogMaxMb("-5")).toBe(50);
    expect(parseDebugLogMaxMb("Infinity")).toBe(50);
  });
  it("treats 0 as off", () => {
    expect(parseDebugLogMaxMb("0")).toBe(0);
    expect(parseDebugLogMaxMb(" 0 ")).toBe(0);
  });
  it("clamps to 1..1024", () => {
    expect(parseDebugLogMaxMb("0.5")).toBe(1);
    expect(parseDebugLogMaxMb("1")).toBe(1);
    expect(parseDebugLogMaxMb("75")).toBe(75);
    expect(parseDebugLogMaxMb("5000")).toBe(1024);
  });
});

describe("createRotatingDebugLog", () => {
  it("returns null when maxBytes is 0 or negative", () => {
    expect(createRotatingDebugLog({ dir, maxBytes: 0 })).toBeNull();
    expect(createRotatingDebugLog({ dir, maxBytes: -1 })).toBeNull();
    expect(readdirSync(dir)).toEqual([]);
  });

  it("appends lines synchronously to debug.log in the given dir", () => {
    const sink = createRotatingDebugLog({ dir: join(dir, "logs"), maxBytes: 10_000 })!;
    sink.write("one");
    sink.write("two");
    const { current, previous } = sink.files();
    expect(current).toBe(join(dir, "logs", "debug.log"));
    expect(previous).toBe(join(dir, "logs", "debug.1.log"));
    // No close needed: writes are synchronous.
    expect(readFileSync(current, "utf8")).toBe("one\ntwo\n");
    sink.close();
  });

  it("creates the file with owner-only permissions on POSIX", () => {
    if (process.platform === "win32") return;
    const sink = createRotatingDebugLog({ dir: join(dir, "logs"), maxBytes: 10_000 })!;
    sink.write("x");
    expect(statSync(sink.files().current).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, "logs")).mode & 0o777).toBe(0o700);
    sink.close();
  });

  it("rotates so total disk use never passes the cap over many writes", () => {
    const maxBytes = 1000;
    const sink = createRotatingDebugLog({ dir, maxBytes })!;
    const { current, previous } = sink.files();
    for (let i = 0; i < 500; i++) {
      sink.write(`line ${i} ${"x".repeat(i % 37)}`);
      expect(sizeOf(current) + sizeOf(previous)).toBeLessThanOrEqual(maxBytes);
      expect(sizeOf(current)).toBeLessThanOrEqual(maxBytes / 2);
    }
    expect(existsSync(previous)).toBe(true);
    // The newest line is always in the current file.
    expect(readFileSync(current, "utf8")).toContain("line 499 ");
    sink.close();
  });

  it("counts bytes, not characters, for multi-byte text", () => {
    const maxBytes = 400;
    const sink = createRotatingDebugLog({ dir, maxBytes })!;
    const { current, previous } = sink.files();
    for (let i = 0; i < 200; i++) {
      sink.write("שלום 日本語 🎉🎉");
      expect(sizeOf(current)).toBeLessThanOrEqual(maxBytes / 2);
      expect(sizeOf(current) + sizeOf(previous)).toBeLessThanOrEqual(maxBytes);
    }
    sink.close();
  });

  it("truncates a line over maxBytes/4 with a marker, on a UTF-8 boundary", () => {
    const maxBytes = 400;
    const sink = createRotatingDebugLog({ dir, maxBytes })!;
    sink.write("é".repeat(500)); // 1000 bytes
    const text = readFileSync(sink.files().current, "utf8");
    expect(Buffer.byteLength(text, "utf8")).toBeLessThanOrEqual(maxBytes / 4);
    expect(text).toMatch(/ …\[truncated \d+ bytes\]\n$/);
    expect(text).not.toContain("�");
    const kept = text.split(" …")[0];
    const dropped = Number(/truncated (\d+) bytes/.exec(text)![1]);
    expect(Buffer.byteLength(kept, "utf8") + dropped).toBe(1000);
    sink.close();
  });

  it("leaves a line that fits untouched", () => {
    expect(truncateLine("short", 100)).toBe("short");
  });

  it("resumes the size of an existing debug.log across a restart", () => {
    const maxBytes = 200;
    const first = createRotatingDebugLog({ dir, maxBytes })!;
    first.write("a".repeat(45));
    first.write("a".repeat(45));
    first.close();
    const second = createRotatingDebugLog({ dir, maxBytes })!;
    second.write("b".repeat(45)); // 92 + 46 > 100 → rotate
    const { current, previous } = second.files();
    expect(readFileSync(previous, "utf8")).toBe(("a".repeat(45) + "\n").repeat(2));
    expect(readFileSync(current, "utf8")).toBe("b".repeat(45) + "\n");
    second.close();
  });

  it("honours a cap lowered across a restart", () => {
    const big = createRotatingDebugLog({ dir, maxBytes: 100_000 })!;
    for (let i = 0; i < 2000; i++) big.write(`old line ${i}`);
    big.close();
    const { current, previous } = big.files();
    expect(sizeOf(current) + sizeOf(previous)).toBeGreaterThan(1000);
    const small = createRotatingDebugLog({ dir, maxBytes: 1000 })!;
    expect(sizeOf(current) + sizeOf(previous)).toBeLessThanOrEqual(1000);
    small.write("new");
    expect(sizeOf(current) + sizeOf(previous)).toBeLessThanOrEqual(1000);
    small.close();
  });

  it("reconciles pre-existing oversized files at startup", () => {
    writeFileSync(join(dir, "debug.1.log"), "p".repeat(5000));
    writeFileSync(join(dir, "debug.log"), "c".repeat(5000));
    const sink = createRotatingDebugLog({ dir, maxBytes: 1000 })!;
    const { current, previous } = sink.files();
    expect(sizeOf(previous)).toBeLessThanOrEqual(500);
    expect(sizeOf(current)).toBeLessThanOrEqual(500);
    sink.write("after");
    expect(readFileSync(current, "utf8")).toBe("after\n");
    sink.close();
  });

  it("empties debug.log when the rename fails, so the cap still holds", () => {
    const reports: string[] = [];
    const lockedFs: DebugLogFs = {
      ...realFs,
      renameSync: () => {
        throw Object.assign(new Error("EBUSY: resource busy or locked"), { code: "EBUSY" });
      },
    };
    const maxBytes = 400;
    const sink = createRotatingDebugLog({ dir, maxBytes, fs: lockedFs, report: (m) => reports.push(m) })!;
    const { current, previous } = sink.files();
    for (let i = 0; i < 100; i++) {
      sink.write(`locked ${i}`);
      expect(sizeOf(current) + sizeOf(previous)).toBeLessThanOrEqual(maxBytes);
    }
    expect(readFileSync(current, "utf8")).toContain("locked 99");
    expect(reports).toEqual([]);
    sink.close();
  });

  it("disables itself once on an fs error and never throws", () => {
    const reports: string[] = [];
    let calls = 0;
    const brokenFs: DebugLogFs = {
      ...realFs,
      writeSync: () => {
        calls++;
        throw new Error("ENOSPC: no space left on device");
      },
    };
    const sink = createRotatingDebugLog({
      dir,
      maxBytes: 1000,
      fs: brokenFs,
      report: (m) => reports.push(m),
    })!;
    expect(() => {
      sink.write("a");
      sink.write("b");
      sink.write("c");
    }).not.toThrow();
    expect(calls).toBe(1);
    expect(reports).toHaveLength(1);
    expect(reports[0]).toContain("ENOSPC");
    expect(() => sink.close()).not.toThrow();
  });

  it("disables itself once when the directory cannot be created", () => {
    const reports: string[] = [];
    const brokenFs: DebugLogFs = {
      ...realFs,
      mkdirSync: () => {
        throw new Error("EACCES: permission denied");
      },
    };
    const sink = createRotatingDebugLog({
      dir,
      maxBytes: 1000,
      fs: brokenFs,
      report: (m) => reports.push(m),
    });
    expect(sink).not.toBeNull();
    expect(() => sink!.write("x")).not.toThrow();
    expect(reports).toHaveLength(1);
    expect(existsSync(join(dir, "debug.log"))).toBe(false);
  });

  it("ignores writes after close", () => {
    const sink = createRotatingDebugLog({ dir, maxBytes: 1000 })!;
    sink.write("kept");
    sink.close();
    sink.write("dropped");
    expect(readFileSync(sink.files().current, "utf8")).toBe("kept\n");
  });
});
