import { randomBytes } from "node:crypto";
import { closeSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

interface GuardRecord {
  pid: number;
  token: string;
  startedAt: string;
}

export interface WriterGuard {
  path: string;
  release(): void;
}

function guardRecord(value: string): GuardRecord | null {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const source = parsed as Record<string, unknown>;
    if (typeof source.pid !== "number" || !Number.isInteger(source.pid) || source.pid <= 0) return null;
    if (typeof source.token !== "string" || !source.token) return null;
    if (typeof source.startedAt !== "string") return null;
    return { pid: source.pid, token: source.token, startedAt: source.startedAt };
  } catch {
    return null;
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function removeIfUnchanged(path: string, expected: string): void {
  let current: string;
  try {
    current = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (current !== expected) return;
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

export function acquireWriterGuard(path: string): WriterGuard {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const token = randomBytes(24).toString("base64url");
  const contents = JSON.stringify({
    pid: process.pid,
    token,
    startedAt: new Date().toISOString(),
  } satisfies GuardRecord);

  for (;;) {
    try {
      const descriptor = openSync(path, "wx", 0o600);
      try {
        writeFileSync(descriptor, contents, { encoding: "utf8" });
      } finally {
        closeSync(descriptor);
      }
      let released = false;
      return {
        path,
        release(): void {
          if (released) return;
          released = true;
          removeIfUnchanged(path, contents);
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const existingText = readFileSync(path, "utf8");
      const existing = guardRecord(existingText);
      if (existing && processIsAlive(existing.pid)) {
        throw new Error(
          `team mode requires one DFIR Companion writer per cases root; process ${existing.pid} already owns it`,
        );
      }
      if (!existing && Date.now() - statSync(path).mtimeMs < 30_000) {
        throw new Error("the team-mode writer guard is incomplete; retry startup in a few seconds");
      }
      removeIfUnchanged(path, existingText);
    }
  }
}
