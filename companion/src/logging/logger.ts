import { mkdirSync, createWriteStream, type WriteStream } from "node:fs";
import { dirname } from "node:path";

// Leveled, greppable logging that tees to the console AND to log files. A single shared
// instance is created at server startup and threaded into the pipeline so the dashboard's
// Settings → Logging toggle can change the verbosity live (no restart — the #1 gotcha).
//
// File routing: every emitted line goes to a global SESSION log (one file per server run);
// lines carrying a caseId ALSO go to that case's own log (the per-investigation audit trail).
// The pure helpers (shouldLog/formatLogLine/normalizeLogLevel) are unit-tested independently
// of any I/O; the file sink is a thin, fail-safe wrapper that never throws into a caller.

export type LogLevel = "debug" | "info" | "warn" | "error";

const RANK: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const LEVELS: readonly LogLevel[] = ["debug", "info", "warn", "error"];

export function isLogLevel(value: unknown): value is LogLevel {
  return typeof value === "string" && (LEVELS as readonly string[]).includes(value);
}

// Parse an env / user-supplied value into a LogLevel, falling back when absent or invalid.
export function normalizeLogLevel(value: unknown, fallback: LogLevel = "info"): LogLevel {
  if (typeof value === "string") {
    const s = value.trim().toLowerCase();
    if (isLogLevel(s)) return s;
  }
  return fallback;
}

// Is a message at `msgLevel` emitted, given the current `threshold`?
export function shouldLog(threshold: LogLevel, msgLevel: LogLevel): boolean {
  return RANK[msgLevel] >= RANK[threshold];
}

// Format one log line. Stable + greppable: "<iso-ts> <LEVEL> [<caseId>] <message>".
export function formatLogLine(level: LogLevel, message: string, opts: { at: string; caseId?: string }): string {
  const lvl = level.toUpperCase().padEnd(5);
  const scope = opts.caseId ? ` [${opts.caseId}]` : "";
  return `${opts.at} ${lvl}${scope} ${message}`;
}

export interface LogContext {
  // When present, the line is also written to this case's per-case log file.
  caseId?: string;
}

export interface Logger {
  debug(message: string, ctx?: LogContext): void;
  info(message: string, ctx?: LogContext): void;
  warn(message: string, ctx?: LogContext): void;
  error(message: string, ctx?: LogContext): void;
  getLevel(): LogLevel;
  setLevel(level: LogLevel): void;
  close(): Promise<void>;
}

// A destination for formatted log lines, keyed by file path. Injectable so tests capture
// lines without touching the filesystem; the default appends to lazily-opened streams.
export interface LogWriter {
  write(path: string, line: string): void;
  close(): Promise<void>;
}

interface ConsoleFns {
  log(s: string): void;
  warn(s: string): void;
  error(s: string): void;
}

export interface LoggerOptions {
  level?: LogLevel;
  // Global session log file — every emitted line lands here. Absent/null → no global file sink.
  sessionLogPath?: string | null;
  // Resolve a per-case log file from a caseId. Absent → case-scoped lines go to console + session only.
  caseLogPath?: (caseId: string) => string;
  // Echo lines to the console too (the live "server log"). Default true.
  console?: boolean;
  // Injectable sink (tests) — defaults to the lazy append-stream file writer.
  writer?: LogWriter;
  // Injectable clock (tests) — defaults to wall-clock ISO-8601.
  now?: () => string;
  // Injectable console (tests) — defaults to the real console.
  consoleFns?: ConsoleFns;
}

// Lazy append-only file writer: one WriteStream per path, parent dirs created on first use.
// Logging must NEVER crash the server, so every fs failure is swallowed — a path that errors
// (e.g. a Dropbox/OneDrive lock on cases/) is disabled and reported once on the console.
class FileLogWriter implements LogWriter {
  private readonly streams = new Map<string, WriteStream | null>();

  write(path: string, line: string): void {
    let stream = this.streams.get(path);
    if (stream === undefined) {
      stream = this.open(path);
      this.streams.set(path, stream);
    }
    if (!stream) return;
    try {
      stream.write(line + "\n");
    } catch {
      // The stream's 'error' handler disables it; nothing actionable here.
    }
  }

  private open(path: string): WriteStream | null {
    try {
      mkdirSync(dirname(path), { recursive: true });
      const stream = createWriteStream(path, { flags: "a" });
      stream.on("error", (err) => {
        this.streams.set(path, null);
        console.error(`[log] file sink disabled for ${path}: ${(err as Error).message}`);
      });
      return stream;
    } catch (err) {
      console.error(`[log] could not open log file ${path}: ${(err as Error).message}`);
      return null;
    }
  }

  async close(): Promise<void> {
    const open = [...this.streams.values()].filter((s): s is WriteStream => s !== null);
    this.streams.clear();
    await Promise.all(open.map((s) => new Promise<void>((resolve) => s.end(resolve))));
  }
}

export class LoggerImpl implements Logger {
  private level: LogLevel;
  private readonly sessionLogPath: string | null;
  private readonly caseLogPath?: (caseId: string) => string;
  private readonly useConsole: boolean;
  private readonly writer: LogWriter;
  private readonly now: () => string;
  private readonly out: ConsoleFns;

  constructor(opts: LoggerOptions = {}) {
    this.level = opts.level ?? "info";
    this.sessionLogPath = opts.sessionLogPath ?? null;
    this.caseLogPath = opts.caseLogPath;
    this.useConsole = opts.console ?? true;
    this.writer = opts.writer ?? new FileLogWriter();
    this.now = opts.now ?? (() => new Date().toISOString());
    this.out = opts.consoleFns ?? {
      log: (s) => console.log(s),
      warn: (s) => console.warn(s),
      error: (s) => console.error(s),
    };
  }

  getLevel(): LogLevel {
    return this.level;
  }
  setLevel(level: LogLevel): void {
    this.level = level;
  }

  private emit(level: LogLevel, message: string, ctx?: LogContext): void {
    if (!shouldLog(this.level, level)) return;
    const line = formatLogLine(level, message, { at: this.now(), caseId: ctx?.caseId });
    if (this.useConsole) {
      if (level === "error") this.out.error(line);
      else if (level === "warn") this.out.warn(line);
      else this.out.log(line);
    }
    if (this.sessionLogPath) this.writer.write(this.sessionLogPath, line);
    if (ctx?.caseId && this.caseLogPath) this.writer.write(this.caseLogPath(ctx.caseId), line);
  }

  debug(message: string, ctx?: LogContext): void {
    this.emit("debug", message, ctx);
  }
  info(message: string, ctx?: LogContext): void {
    this.emit("info", message, ctx);
  }
  warn(message: string, ctx?: LogContext): void {
    this.emit("warn", message, ctx);
  }
  error(message: string, ctx?: LogContext): void {
    this.emit("error", message, ctx);
  }

  async close(): Promise<void> {
    await this.writer.close();
  }
}

// A console-only logger (no file sinks) — the safe default for tests and CLI scripts.
export function createConsoleLogger(level: LogLevel = "info"): Logger {
  return new LoggerImpl({ level, sessionLogPath: null });
}
