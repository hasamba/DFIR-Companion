import { mkdtempSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { acquireWriterGuard } from "../../src/auth/writerGuard.js";

// #2287 — a record from another host names a PID in THAT host's process table. Probing it here
// asks the wrong machine: a dead local PID would steal a live owner's guard, and a live local PID
// would block startup forever. Only the lease (the owner's heartbeat keeps the file fresh) can tell.

const DEAD_PID = 2147483647;
const EXPIRED_MS = 5 * 60_000;

function guardPath(): string {
  return join(mkdtempSync(join(tmpdir(), "dfir-writer-host-")), "writer.lock");
}

function writeRecord(path: string, record: Record<string, unknown>, ageMs = 0): string {
  const text = JSON.stringify({ token: "foreign-owner", startedAt: "2026-01-01T00:00:00.000Z", ...record });
  writeFileSync(path, text, "utf8");
  if (ageMs > 0) {
    const past = new Date(Date.now() - ageMs);
    utimesSync(path, past, past);
  }
  return text;
}

function expectTakenOver(path: string): void {
  const guard = acquireWriterGuard(path);
  expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ pid: process.pid, host: hostname() });
  guard.release();
}

describe("writer guard — a record from another host is judged by its lease (#2287)", () => {
  it("refuses a fresh foreign record whose PID is dead here, and leaves it alone", () => {
    const path = guardPath();
    const text = writeRecord(path, { pid: DEAD_PID, host: "other-container" });

    expect(() => acquireWriterGuard(path)).toThrow(/server on host other-container holds it/);
    expect(readFileSync(path, "utf8")).toBe(text);
  });

  it("refuses a fresh foreign record whose PID is alive here, with the lease message", () => {
    const path = guardPath();
    const text = writeRecord(path, { pid: process.ppid, host: "other-container" });

    expect(() => acquireWriterGuard(path)).toThrow(
      /server on host other-container holds it.*retry in \d+ seconds/,
    );
    expect(readFileSync(path, "utf8")).toBe(text);
  });

  it("takes over an expired foreign record whose PID is alive here", () => {
    const path = guardPath();
    writeRecord(path, { pid: process.ppid, host: "crashed-container" }, EXPIRED_MS);

    expectTakenOver(path);
  });

  it("takes over an expired foreign record whose PID is dead here", () => {
    const path = guardPath();
    writeRecord(path, { pid: DEAD_PID, host: "crashed-container" }, EXPIRED_MS);

    expectTakenOver(path);
  });

  it("still takes over a host-less record with a dead PID at once", () => {
    const path = guardPath();
    writeRecord(path, { pid: DEAD_PID });

    expectTakenOver(path);
  });

  it("still refuses an own-host record with a different live PID", () => {
    const path = guardPath();
    const text = writeRecord(path, { pid: process.ppid, host: hostname() });

    expect(() => acquireWriterGuard(path)).toThrow(new RegExp(`process ${process.ppid} already owns it`));
    expect(readFileSync(path, "utf8")).toBe(text);
  });
});
