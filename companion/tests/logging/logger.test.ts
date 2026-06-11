import { describe, it, expect } from "vitest";
import {
  LoggerImpl,
  shouldLog,
  formatLogLine,
  normalizeLogLevel,
  isLogLevel,
  type LogWriter,
} from "../../src/logging/logger.js";

// A LogWriter that records every (path, line) pair instead of touching the filesystem.
function fakeWriter() {
  const lines: { path: string; line: string }[] = [];
  const writer: LogWriter = {
    write: (path, line) => lines.push({ path, line }),
    close: async () => {},
  };
  return { writer, lines };
}

function fakeConsole() {
  const log: string[] = [];
  const warn: string[] = [];
  const error: string[] = [];
  return { fns: { log: (s: string) => log.push(s), warn: (s: string) => warn.push(s), error: (s: string) => error.push(s) }, log, warn, error };
}

describe("log-level helpers", () => {
  it("ranks levels so a higher-or-equal message passes the threshold", () => {
    expect(shouldLog("debug", "debug")).toBe(true);
    expect(shouldLog("info", "debug")).toBe(false);
    expect(shouldLog("info", "info")).toBe(true);
    expect(shouldLog("info", "error")).toBe(true);
    expect(shouldLog("error", "warn")).toBe(false);
  });

  it("normalizes env values and falls back on garbage", () => {
    expect(normalizeLogLevel("debug")).toBe("debug");
    expect(normalizeLogLevel("  DEBUG ")).toBe("debug");
    expect(normalizeLogLevel("INFO")).toBe("info");
    expect(normalizeLogLevel(undefined)).toBe("info");
    expect(normalizeLogLevel("verbose")).toBe("info");
    expect(normalizeLogLevel("verbose", "warn")).toBe("warn");
  });

  it("validates log levels", () => {
    expect(isLogLevel("debug")).toBe(true);
    expect(isLogLevel("trace")).toBe(false);
    expect(isLogLevel(5)).toBe(false);
  });
});

describe("formatLogLine", () => {
  it("produces a stable, greppable line with a padded level", () => {
    expect(formatLogLine("info", "hello", { at: "2026-06-11T00:00:00.000Z" }))
      .toBe("2026-06-11T00:00:00.000Z INFO  hello");
  });
  it("includes the caseId scope when present", () => {
    expect(formatLogLine("debug", "x", { at: "T", caseId: "INC-1" }))
      .toBe("T DEBUG [INC-1] x");
  });
});

describe("LoggerImpl routing", () => {
  const at = () => "T";

  it("drops messages below the threshold from console AND files", () => {
    const { writer, lines } = fakeWriter();
    const c = fakeConsole();
    const log = new LoggerImpl({ level: "info", sessionLogPath: "/s.log", writer, consoleFns: c.fns, now: at });
    log.debug("quiet");
    expect(lines).toHaveLength(0);
    expect(c.log).toHaveLength(0);
    log.info("loud");
    expect(c.log).toEqual(["T INFO  loud"]);
    expect(lines).toEqual([{ path: "/s.log", line: "T INFO  loud" }]);
  });

  it("emits debug to console and files once the level is lowered", () => {
    const { writer, lines } = fakeWriter();
    const c = fakeConsole();
    const log = new LoggerImpl({ level: "info", sessionLogPath: "/s.log", writer, consoleFns: c.fns, now: at });
    log.debug("hidden");
    log.setLevel("debug");
    log.debug("shown");
    expect(c.log).toEqual(["T DEBUG shown"]);
    expect(lines).toEqual([{ path: "/s.log", line: "T DEBUG shown" }]);
  });

  it("tees a case-scoped line to BOTH the session log and the per-case log", () => {
    const { writer, lines } = fakeWriter();
    const log = new LoggerImpl({
      level: "debug",
      sessionLogPath: "/session.log",
      caseLogPath: (id) => `/cases/${id}/case.log`,
      console: false,
      writer,
      now: at,
    });
    log.info("touched", { caseId: "INC-7" });
    expect(lines).toEqual([
      { path: "/session.log", line: "T INFO  [INC-7] touched" },
      { path: "/cases/INC-7/case.log", line: "T INFO  [INC-7] touched" },
    ]);
  });

  it("does not write to a per-case file when no caseId is given", () => {
    const { writer, lines } = fakeWriter();
    const log = new LoggerImpl({
      level: "debug",
      sessionLogPath: "/session.log",
      caseLogPath: (id) => `/cases/${id}/case.log`,
      console: false,
      writer,
      now: at,
    });
    log.warn("global");
    expect(lines).toEqual([{ path: "/session.log", line: "T WARN  global" }]);
  });

  it("routes warn/error to the matching console channel", () => {
    const c = fakeConsole();
    const log = new LoggerImpl({ level: "debug", console: true, consoleFns: c.fns, now: at });
    log.warn("w");
    log.error("e");
    log.info("i");
    expect(c.warn).toEqual(["T WARN  w"]);
    expect(c.error).toEqual(["T ERROR e"]);
    expect(c.log).toEqual(["T INFO  i"]);
  });
});
