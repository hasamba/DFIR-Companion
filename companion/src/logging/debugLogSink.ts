import * as nodeFs from "node:fs";
import { join } from "node:path";

// The always-on debug log (#1735). Every line the logger emits — at EVERY level, before the live
// level threshold — is appended here, so a support bundle has debug detail even when the analyst
// never switched the level to `debug` before the problem happened.
//
// Two files in the GLOBAL log directory, never inside a case folder: `debug.log` (current) and
// `debug.1.log` (previous). When a write would take the current file past half the cap, the
// current file is renamed over the previous one and a new current file starts. Each file therefore
// stays at or below maxBytes / 2, and total disk use never passes maxBytes.
//
// Writes are SYNCHRONOUS (open fd + writeSync) with byte-accurate accounting: there is no buffer,
// so there is nothing to flush before a bundle reads the file, and the cap is exact. Like the
// logger's FileLogWriter, the sink must never crash the server: an fs error disables it and is
// reported once on the console.

export const DEFAULT_DEBUG_LOG_MAX_MB = 50;
const MAX_DEBUG_LOG_MB = 1024;
const CURRENT_NAME = "debug.log";
const PREVIOUS_NAME = "debug.1.log";
const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

export interface DebugLogSink {
  write(line: string): void;
  files(): { previous: string; current: string };
  close(): void;
}

/** The node:fs subset the sink uses — injectable so tests can simulate failures. */
export interface DebugLogFs {
  mkdirSync(path: string, opts: { recursive: true; mode?: number }): unknown;
  openSync(path: string, flags: string, mode?: number): number;
  writeSync(fd: number, data: string): number;
  closeSync(fd: number): void;
  renameSync(from: string, to: string): void;
  statSync(path: string): { size: number };
  unlinkSync(path: string): void;
}

export interface DebugLogOptions {
  dir: string;
  maxBytes: number;
  fs?: DebugLogFs;
  /** Where the one "sink disabled" message goes. Defaults to console.error. */
  report?: (message: string) => void;
}

/**
 * Parse `DFIR_DEBUG_LOG_MAX_MB` into megabytes. Absent or invalid → the default (50). `0` turns
 * the debug log off. Anything else is clamped to 1..1024.
 */
export function parseDebugLogMaxMb(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_DEBUG_LOG_MAX_MB;
  const n = Number(raw.trim());
  if (!Number.isFinite(n) || n < 0) return DEFAULT_DEBUG_LOG_MAX_MB;
  if (n === 0) return 0;
  return Math.min(MAX_DEBUG_LOG_MB, Math.max(1, Math.floor(n)));
}

/** Null when maxBytes <= 0 (the debug log is off). */
export function createRotatingDebugLog(opts: DebugLogOptions): DebugLogSink | null {
  if (!(opts.maxBytes > 0)) return null;
  return new RotatingDebugLog(opts);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function fileSize(fs: DebugLogFs, path: string): number {
  try {
    return fs.statSync(path).size;
  } catch {
    return 0; // absent — a fresh start
  }
}

/**
 * Cut a line that is longer than `maxLineBytes` (newline included) and append a marker. The cut
 * backs off to a UTF-8 character boundary, so the file never holds half a character.
 */
export function truncateLine(line: string, maxLineBytes: number): string {
  const total = Buffer.byteLength(line, "utf8");
  if (total + 1 <= maxLineBytes) return line;
  const buf = Buffer.from(line, "utf8");
  // The marker length depends on N; size it from the whole-line count, which is an upper bound.
  const markerBudget = Buffer.byteLength(` …[truncated ${total} bytes]`, "utf8");
  let keep = Math.max(0, maxLineBytes - 1 - markerBudget);
  while (keep > 0 && (buf[keep] & 0xc0) === 0x80) keep--;
  return `${buf.subarray(0, keep).toString("utf8")} …[truncated ${total - keep} bytes]`;
}

class RotatingDebugLog implements DebugLogSink {
  private readonly fs: DebugLogFs;
  private readonly report: (message: string) => void;
  private readonly current: string;
  private readonly previous: string;
  private readonly halfCap: number;
  private readonly maxLineBytes: number;
  private fd: number | null = null;
  private size = 0;
  private disabled = false;

  constructor(opts: DebugLogOptions) {
    this.fs = opts.fs ?? nodeFs;
    this.report = opts.report ?? ((m) => console.error(m));
    this.current = join(opts.dir, CURRENT_NAME);
    this.previous = join(opts.dir, PREVIOUS_NAME);
    this.halfCap = Math.floor(opts.maxBytes / 2);
    this.maxLineBytes = Math.floor(opts.maxBytes / 4);
    try {
      this.fs.mkdirSync(opts.dir, { recursive: true, mode: DIR_MODE });
      this.reconcile();
    } catch (err) {
      this.disable(err);
    }
  }

  files(): { previous: string; current: string } {
    return { previous: this.previous, current: this.current };
  }

  write(line: string): void {
    if (this.disabled || this.fd === null) return;
    try {
      const text = truncateLine(line, this.maxLineBytes) + "\n";
      const bytes = Buffer.byteLength(text, "utf8");
      if (this.size > 0 && this.size + bytes > this.halfCap) this.rotate();
      this.fs.writeSync(this.fd, text);
      this.size += bytes;
    } catch (err) {
      this.disable(err);
    }
  }

  close(): void {
    this.closeFd();
    this.disabled = true;
  }

  // Startup: the files survive restarts, and the cap may have been LOWERED since they were
  // written. An over-cap previous file is deleted. An over-cap current file is emptied, not
  // rotated: renaming it would only move the excess into the previous file.
  private reconcile(): void {
    if (fileSize(this.fs, this.previous) > this.halfCap) this.fs.unlinkSync(this.previous);
    this.openCurrent();
    this.size = fileSize(this.fs, this.current);
    if (this.size > this.halfCap) this.emptyCurrent();
  }

  // Empty the current file by reopening it with "w". Not ftruncate on the append handle: on
  // Windows an "a" handle carries append rights only, the truncate fails, and the sink would
  // disable itself with the file still over the cap (CI, Windows shard, #1735).
  private emptyCurrent(): void {
    this.closeFd();
    this.fd = this.fs.openSync(this.current, "w", FILE_MODE);
    this.size = 0;
  }

  private openCurrent(): void {
    this.fd = this.fs.openSync(this.current, "a", FILE_MODE);
  }

  private rotate(): void {
    this.closeFd();
    try {
      this.fs.renameSync(this.current, this.previous);
      this.openCurrent();
    } catch {
      // A rename can fail on Windows while another process holds the file. Emptying the current
      // file instead still honours the cap; only the older half of the history is lost.
      this.emptyCurrent();
    }
    this.size = 0;
  }

  private closeFd(): void {
    if (this.fd === null) return;
    const fd = this.fd;
    this.fd = null;
    try {
      this.fs.closeSync(fd);
    } catch {
      /* already unusable — nothing to release */
    }
  }

  private disable(err: unknown): void {
    this.closeFd();
    if (this.disabled) return;
    this.disabled = true;
    this.report(`[log] debug log disabled for ${this.current}: ${errorMessage(err)}`);
  }
}
