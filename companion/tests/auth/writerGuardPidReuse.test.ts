import { mkdtempSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { acquireWriterGuard, WRITER_GUARD_HEARTBEAT_MS } from "../../src/auth/writerGuard.js";

// #2278 — in a container the server is always PID 1. A guard left by an unclean exit (SIGKILL,
// OOM, power loss) names PID 1, and the NEW container is PID 1 too, so a bare liveness probe sees
// itself and refuses forever. A record that names our own PID but is not one we hold must be
// judged by who wrote it (host) and whether its owner still refreshes it (lease), not by the probe.

function guardPath(): string {
  return join(mkdtempSync(join(tmpdir(), "dfir-writer-pid-")), "writer.lock");
}

function writeRecord(path: string, record: Record<string, unknown>, ageMs = 0): string {
  const text = JSON.stringify({ token: "dead-owner", startedAt: "2026-01-01T00:00:00.000Z", ...record });
  writeFileSync(path, text, "utf8");
  if (ageMs > 0) {
    const past = new Date(Date.now() - ageMs);
    utimesSync(path, past, past);
  }
  return text;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("writer guard — a stale record that names our own PID (#2278)", () => {
  it("recovers a same-host record with our PID at once, then refuses a second acquire", () => {
    const path = guardPath();
    writeRecord(path, { pid: process.pid, host: hostname() });

    const guard = acquireWriterGuard(path);
    const record = JSON.parse(readFileSync(path, "utf8"));
    expect(record).toMatchObject({ pid: process.pid, host: hostname() });
    expect(record.token).not.toBe("dead-owner");
    // The replacement is a held guard now, so the same PID no longer reads as stale.
    expect(() => acquireWriterGuard(path)).toThrow(/one DFIR Companion writer/i);
    guard.release();
  });

  it("refuses a record with our PID from another host while its owner keeps it fresh", () => {
    const path = guardPath();
    const text = writeRecord(path, { pid: process.pid, host: "other-container" });

    expect(() => acquireWriterGuard(path)).toThrow(/one DFIR Companion writer/i);
    expect(readFileSync(path, "utf8")).toBe(text); // a refusal never touches the owner's record
  });

  it("recovers a record with our PID from another host once its lease has expired", () => {
    const path = guardPath();
    writeRecord(path, { pid: process.pid, host: "crashed-container" }, 5 * 60_000);

    const guard = acquireWriterGuard(path);
    expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ pid: process.pid, host: hostname() });
    guard.release();
  });

  it("judges a legacy record without a host by its lease", () => {
    const fresh = guardPath();
    writeRecord(fresh, { pid: process.pid });
    expect(() => acquireWriterGuard(fresh)).toThrow(/one DFIR Companion writer/i);

    const old = guardPath();
    writeRecord(old, { pid: process.pid }, 5 * 60_000);
    const guard = acquireWriterGuard(old);
    expect(JSON.parse(readFileSync(old, "utf8"))).toMatchObject({ pid: process.pid });
    guard.release();
  });

  it("still refuses a different live PID and leaves its record alone", () => {
    const path = guardPath();
    const text = writeRecord(path, { pid: process.ppid, host: hostname() }, 5 * 60_000);

    expect(() => acquireWriterGuard(path)).toThrow(new RegExp(`process ${process.ppid} already owns it`));
    expect(readFileSync(path, "utf8")).toBe(text);
  });
});

describe("writer guard heartbeat", () => {
  it("refreshes the guard while held and stops after release", () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const path = guardPath();
    const guard = acquireWriterGuard(path);
    const past = new Date(Date.now() - 5 * 60_000);

    utimesSync(path, past, past);
    vi.advanceTimersByTime(WRITER_GUARD_HEARTBEAT_MS);
    expect(Date.now() - statSync(path).mtimeMs).toBeLessThan(WRITER_GUARD_HEARTBEAT_MS);

    guard.release();
    expect(() => statSync(path)).toThrow(/ENOENT/);
  });

  it("does not refresh a guard another writer has replaced", () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const path = guardPath();
    const guard = acquireWriterGuard(path);
    const replacement = writeRecord(
      path,
      { pid: process.pid, host: "other", token: "other-writer" },
      5 * 60_000,
    );
    const before = statSync(path).mtimeMs;

    vi.advanceTimersByTime(WRITER_GUARD_HEARTBEAT_MS);
    expect(statSync(path).mtimeMs).toBe(before);
    guard.release();
    expect(readFileSync(path, "utf8")).toBe(replacement);
  });
});
