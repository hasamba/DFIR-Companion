import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  installUncaughtExceptionNet,
  resetUncaughtExceptionNetForTests,
} from "../../src/logging/uncaughtExceptionNet.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import type { Logger } from "../../src/logging/logger.js";

// The net converts Node's fatal default for an uncaught exception into a loud log line before the
// process exits, so "the server crashed with no trace anywhere" stops being possible. Unlike
// unhandledRejectionNet, it does NOT keep the process alive afterward — Node's own guidance is to
// exit rather than resume after a synchronous exception — so every test injects a fake `exit` to
// observe the call without actually killing the test worker, and fake-advances the flush delay.
//
// These drive process.emit("uncaughtException", ...) rather than actually throwing synchronously:
// it invokes the very listener Node would, deterministically, without crashing the test worker.

function captureLogger(lines: { level: string; message: string }[]): Logger {
  const record = (level: string) => (message: string) => lines.push({ level, message });
  return {
    debug: record("debug"),
    info: record("info"),
    warn: record("warn"),
    error: record("error"),
    getLevel: () => "debug",
    setLevel: () => {},
    close: async () => {},
  };
}

let lines: { level: string; message: string }[];
let previousLogger: Logger;
let listenersBefore: number;

beforeEach(() => {
  lines = [];
  previousLogger = getServerLogger();
  setServerLogger(captureLogger(lines));
  listenersBefore = process.listenerCount("uncaughtException");
  resetUncaughtExceptionNetForTests();
  vi.useFakeTimers();
});

afterEach(() => {
  setServerLogger(previousLogger);
  // Drop only the listeners this test armed, so Vitest's own stays intact.
  const armed = process.listeners("uncaughtException").slice(listenersBefore);
  for (const listener of armed) process.off("uncaughtException", listener);
  resetUncaughtExceptionNetForTests();
  vi.useRealTimers();
});

describe("installUncaughtExceptionNet", () => {
  it("logs the exception at error level with its stack, then exits", () => {
    const exit = vi.fn();
    installUncaughtExceptionNet(exit);
    const err = new Error("heap allocation failed mid-import");
    err.name = "RangeError";

    expect(() => {
      process.emit("uncaughtException", err);
    }).not.toThrow();

    expect(lines).toHaveLength(1);
    expect(lines[0].level).toBe("error");
    expect(lines[0].message).toContain("RangeError: heap allocation failed mid-import");
    expect(lines[0].message).toContain("uncaughtExceptionNet.test.ts"); // the stack came through

    // The exit is delayed (to let the log write flush) — not called synchronously in the handler.
    expect(exit).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("reports a non-Error thrown value instead of dropping it", () => {
    const exit = vi.fn();
    installUncaughtExceptionNet(exit);

    process.emit("uncaughtException", "plain string thrown" as unknown as Error);

    expect(lines).toHaveLength(1);
    expect(lines[0].message).toContain("plain string thrown");
    vi.runAllTimers();
    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("is idempotent, so a second startServer in one process does not double-log or double-exit", () => {
    const exit = vi.fn();
    installUncaughtExceptionNet(exit);
    installUncaughtExceptionNet(exit);
    installUncaughtExceptionNet(exit);

    expect(process.listenerCount("uncaughtException")).toBe(listenersBefore + 1);

    process.emit("uncaughtException", new Error("once"));
    expect(lines).toHaveLength(1);
    vi.runAllTimers();
    expect(exit).toHaveBeenCalledTimes(1);
  });

  it("resolves the logger per event, so a post-boot logger swap is honoured", () => {
    const exit = vi.fn();
    installUncaughtExceptionNet(exit);
    const laterLines: { level: string; message: string }[] = [];
    setServerLogger(captureLogger(laterLines));

    process.emit("uncaughtException", new Error("after the swap"));

    expect(lines).toHaveLength(0);
    expect(laterLines).toHaveLength(1);
    expect(laterLines[0].message).toContain("after the swap");
  });

  it("still exits even if the logger itself throws", () => {
    const exit = vi.fn();
    setServerLogger({
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {
        throw new Error("disk full, log write failed");
      },
      getLevel: () => "debug",
      setLevel: () => {},
      close: async () => {},
    });
    installUncaughtExceptionNet(exit);

    expect(() => {
      process.emit("uncaughtException", new Error("original crash"));
    }).not.toThrow();

    vi.runAllTimers();
    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);
  });
});
