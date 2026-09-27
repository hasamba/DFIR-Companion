import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import { mkdtempSync, rmSync, readFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, isAbsolute } from "node:path";
import {
  createRotatingDebugLog,
  type DebugLogSink,
  type DebugLogFs,
} from "../../src/logging/debugLogSink.js";
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
  return {
    fns: {
      log: (s: string) => log.push(s),
      warn: (s: string) => warn.push(s),
      error: (s: string) => error.push(s),
    },
    log,
    warn,
    error,
  };
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
    expect(formatLogLine("info", "hello", { at: "2026-06-11T00:00:00.000Z" })).toBe(
      "2026-06-11T00:00:00.000Z INFO  hello",
    );
  });
  it("includes the caseId scope when present", () => {
    expect(formatLogLine("debug", "x", { at: "T", caseId: "INC-1" })).toBe("T DEBUG [INC-1] x");
  });
});

describe("LoggerImpl routing", () => {
  const at = () => "T";

  it("drops messages below the threshold from console AND files", () => {
    const { writer, lines } = fakeWriter();
    const c = fakeConsole();
    const log = new LoggerImpl({
      level: "info",
      sessionLogPath: "/s.log",
      writer,
      consoleFns: c.fns,
      now: at,
    });
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
    const log = new LoggerImpl({
      level: "info",
      sessionLogPath: "/s.log",
      writer,
      consoleFns: c.fns,
      now: at,
    });
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

// A DebugLogSink that records lines instead of touching the filesystem.
function fakeDebugSink() {
  const lines: string[] = [];
  let closed = false;
  const sink: DebugLogSink = {
    write: (line) => lines.push(line),
    files: () => ({ previous: "/logs/debug.1.log", current: "/logs/debug.log" }),
    close: () => {
      closed = true;
    },
  };
  return { sink, lines, isClosed: () => closed };
}

describe("LoggerImpl always-on debug log (#1735)", () => {
  const at = () => "T";

  it("writes every level to the debug sink even at level info", () => {
    const { writer, lines } = fakeWriter();
    const dbg = fakeDebugSink();
    const log = new LoggerImpl({
      level: "info",
      sessionLogPath: "/s.log",
      caseLogPath: (id) => `/cases/${id}/case.log`,
      console: false,
      writer,
      debugLog: dbg.sink,
      now: at,
    });
    log.debug("detail", { caseId: "INC-1" });
    log.info("i");
    log.warn("w");
    log.error("e");
    expect(dbg.lines).toEqual(["T DEBUG [INC-1] detail", "T INFO  i", "T WARN  w", "T ERROR e"]);
    // The live threshold still governs the session and case sinks.
    expect(lines.map((l) => l.line)).toEqual(["T INFO  i", "T WARN  w", "T ERROR e"]);
    expect(lines.some((l) => l.path.startsWith("/cases/"))).toBe(false);
  });

  it("keeps the console quiet below the threshold", () => {
    const c = fakeConsole();
    const dbg = fakeDebugSink();
    const log = new LoggerImpl({ level: "warn", consoleFns: c.fns, debugLog: dbg.sink, now: at });
    log.debug("d");
    log.info("i");
    expect(c.log).toEqual([]);
    expect(dbg.lines).toEqual(["T DEBUG d", "T INFO  i"]);
  });

  it("reports its log paths, and closes the debug sink", async () => {
    const dbg = fakeDebugSink();
    const log = new LoggerImpl({ sessionLogPath: "/s.log", console: false, debugLog: dbg.sink });
    expect(log.paths()).toEqual({
      sessionLogPath: "/s.log",
      debugLog: { previous: "/logs/debug.1.log", current: "/logs/debug.log" },
    });
    await log.close();
    expect(dbg.isClosed()).toBe(true);
  });

  it("reports a null debug log when none is configured", () => {
    const log = new LoggerImpl({ console: false });
    expect(log.paths()).toEqual({ sessionLogPath: null, debugLog: null });
  });

  it("never writes the debug log inside a case folder", async () => {
    const root = mkdtempSync(join(tmpdir(), "logger-dbg-"));
    try {
      const casesDir = join(root, "cases");
      const logsDir = join(root, "logs");
      const opened: string[] = [];
      const spyFs: DebugLogFs = {
        ...(fs as unknown as DebugLogFs),
        openSync: (path, flags, mode) => {
          opened.push(path);
          return fs.openSync(path, flags, mode);
        },
        mkdirSync: (path, opts) => {
          opened.push(path);
          return fs.mkdirSync(path, opts);
        },
      };
      const { writer } = fakeWriter();
      const log = new LoggerImpl({
        level: "info",
        sessionLogPath: join(logsDir, "session.log"),
        caseLogPath: (id) => join(casesDir, id, "logs", "session.log"),
        console: false,
        writer,
        debugLog: createRotatingDebugLog({ dir: logsDir, maxBytes: 10_000, fs: spyFs }),
      });
      log.debug("case detail", { caseId: "INC-9" });
      log.info("case info", { caseId: "INC-9" });
      await log.close();
      expect(opened.length).toBeGreaterThan(0);
      for (const p of opened) {
        const rel = relative(casesDir, p);
        expect(rel.startsWith("..") || isAbsolute(rel)).toBe(true);
      }
      expect(existsSync(casesDir)).toBe(false);
      expect(readdirSync(logsDir)).toEqual(["debug.log"]);
      expect(readFileSync(join(logsDir, "debug.log"), "utf8")).toContain("DEBUG [INC-9] case detail");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
