import { createHash, randomBytes } from "node:crypto";
import { closeSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// How long a guard — or a recovery claim — may sit in an inconsistent state before the process that
// left it there is presumed dead. Long enough to cover a two-step write that got descheduled, short
// enough that an operator restarting after a crash is not locked out for a shift.
const ABANDONED_AFTER_MS = 30_000;

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

// ENOENT is never a fault on the paths below: we are inspecting a file that belongs to ANOTHER
// starter, and that starter may remove it at any moment. Returning null lets the acquire loop go
// back to the top and re-derive the state of the world, instead of aborting startup on a race it
// was written to handle.
function readIfPresent(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

function mtimeMsIfPresent(path: string): number | null {
  try {
    return statSync(path).mtimeMs;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

function removeIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

function removeIfUnchanged(path: string, expected: string): void {
  const current = readIfPresent(path);
  if (current === null || current !== expected) return;
  removeIfPresent(path);
}

// Serialises stale-guard recovery, which is the one place a starter deletes a file it does not own.
// Two starters that both read the same DEAD owner must not both remove it: the first unlinks and
// creates its own guard, and the second — whose content check ran against the dead record it read
// moments earlier — deletes that FRESH guard and acquires on top of it, leaving two writers on one
// cases root. The re-read inside removeIfUnchanged cannot close that window on its own, because the
// read and the unlink are separate syscalls.
//
// An exclusive create of a claim file is the mutex over the removal, so only one starter may remove
// a given record; every other starter is held off until the winner's new guard is in place, and
// then sees a LIVE owner and refuses. The claim is named FROM the record it recovers, so a claim
// abandoned by a starter that died mid-recovery can only ever hold up that one record, and the same
// abandonment window that applies to a half-written guard applies to the claim.
function claimPathFor(path: string, record: string): string {
  return `${path}.recover-${createHash("sha256").update(record).digest("hex").slice(0, 16)}`;
}

function recoverStaleGuard(path: string, existingText: string): void {
  const claimPath = claimPathFor(path, existingText);
  let claim: number;
  try {
    claim = openSync(claimPath, "wx", 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    const claimedAt = mtimeMsIfPresent(claimPath);
    if (claimedAt !== null && Date.now() - claimedAt < ABANDONED_AFTER_MS) {
      throw new Error(
        "another DFIR Companion is recovering the team-mode writer guard; retry startup in a few seconds",
      );
    }
    removeIfPresent(claimPath); // its owner died mid-recovery; the acquire loop retries from the top
    return;
  }
  try {
    removeIfUnchanged(path, existingText);
  } finally {
    closeSync(claim);
    removeIfPresent(claimPath);
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
      const existingText = readIfPresent(path);
      if (existingText === null) continue; // the owner released it — compete for it again
      const existing = guardRecord(existingText);
      if (existing && processIsAlive(existing.pid)) {
        throw new Error(
          `team mode requires one DFIR Companion writer per cases root; process ${existing.pid} already owns it`,
        );
      }
      if (!existing) {
        const writtenAt = mtimeMsIfPresent(path);
        if (writtenAt === null) continue; // gone between the read and the stat
        if (Date.now() - writtenAt < ABANDONED_AFTER_MS) {
          throw new Error("the team-mode writer guard is incomplete; retry startup in a few seconds");
        }
      }
      recoverStaleGuard(path, existingText);
    }
  }
}
