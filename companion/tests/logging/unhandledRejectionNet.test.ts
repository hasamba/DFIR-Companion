import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  installUnhandledRejectionNet,
  resetUnhandledRejectionNetForTests,
} from "../../src/logging/unhandledRejectionNet.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import type { Logger } from "../../src/logging/logger.js";

// The net converts Node's fatal default for an unhandled rejection into a loud log line, so one
// stray promise cannot end a live investigation. What matters is that it logs at ERROR, that
// it carries the stack (the only thing that identifies the culprit), and that it is not armed by
// merely importing the app — a rejection leaked inside the test suite must still fail loudly.
//
// These drive process.emit("unhandledRejection", ...) rather than orphaning a real promise: it
// invokes the very listener Node would, deterministically, without leaving an actual unhandled
// rejection loose in the worker for Vitest to trip over afterwards.

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
  listenersBefore = process.listenerCount("unhandledRejection");
  resetUnhandledRejectionNetForTests();
});

afterEach(() => {
  setServerLogger(previousLogger);
  // Drop only the listeners this test armed, so Vitest's own stays intact.
  const armed = process.listeners("unhandledRejection").slice(listenersBefore);
  for (const listener of armed) process.off("unhandledRejection", listener);
  resetUnhandledRejectionNetForTests();
});

describe("installUnhandledRejectionNet", () => {
  it("logs the rejection at error level with its stack, and does not rethrow", () => {
    installUnhandledRejectionNet();
    const reason = new Error("job cancelled before it started");
    reason.name = "AbortError";

    expect(() => {
      process.emit("unhandledRejection", reason, Promise.resolve());
    }).not.toThrow();

    expect(lines).toHaveLength(1);
    expect(lines[0].level).toBe("error");
    expect(lines[0].message).toContain("AbortError: job cancelled before it started");
    expect(lines[0].message).toContain("unhandledRejectionNet.test.ts"); // the stack came through
  });

  it("reports a non-Error rejection reason instead of dropping it", () => {
    installUnhandledRejectionNet();

    process.emit("unhandledRejection", "plain string reason", Promise.resolve());

    expect(lines).toHaveLength(1);
    expect(lines[0].message).toContain("plain string reason");
  });

  it("is idempotent, so a second startServer in one process does not double-log", () => {
    installUnhandledRejectionNet();
    installUnhandledRejectionNet();
    installUnhandledRejectionNet();

    expect(process.listenerCount("unhandledRejection")).toBe(listenersBefore + 1);

    process.emit("unhandledRejection", new Error("once"), Promise.resolve());
    expect(lines).toHaveLength(1);
  });

  it("resolves the logger per event, so a post-boot logger swap is honoured", () => {
    installUnhandledRejectionNet();
    const laterLines: { level: string; message: string }[] = [];
    setServerLogger(captureLogger(laterLines));

    process.emit("unhandledRejection", new Error("after the swap"), Promise.resolve());

    expect(lines).toHaveLength(0);
    expect(laterLines).toHaveLength(1);
    expect(laterLines[0].message).toContain("after the swap");
  });
});
