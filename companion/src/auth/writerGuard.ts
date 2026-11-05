import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { hostname } from "node:os";
import { dirname } from "node:path";

// How long a guard — or a recovery claim — may sit in an inconsistent state before the process that
// left it there is presumed dead. Long enough to cover a two-step write that got descheduled, short
// enough that an operator restarting after a crash is not locked out for a shift.
const ABANDONED_AFTER_MS = 30_000;

// A live owner touches its guard this often, so a record whose liveness cannot be probed (#2278)
// can still be judged by whether anyone keeps it fresh. The lease is several missed beats long, so a
// busy event loop does not hand the guard to a second writer.
export const WRITER_GUARD_HEARTBEAT_MS = 10_000;
const LEASE_MS = 60_000;

interface GuardRecord {
  pid: number;
  token: string;
  startedAt: string;
  /** Absent on records written before #2278. Docker sets the hostname to the container id. */
  host?: string;
}

// The exact contents of every guard this process holds. Ownership is tracked per module instance:
// the guard is acquired once, on the main thread, at startup — no worker acquires it.
const heldGuards = new Set<string>();

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
    if (source.host !== undefined && typeof source.host !== "string") return null;
    return { pid: source.pid, token: source.token, startedAt: source.startedAt, host: source.host };
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

// A record from another host — a recreated container, or a second container or machine on a shared
// volume — names a PID in THAT host's process table, so a local liveness probe asks the wrong
// machine (#2287). Only the lease can tell: a live owner keeps the file fresh. In a container the
// server is always PID 1, so a guard left by an unclean exit names PID 1 and the probe in the NEXT
// container answers for itself (#2278). A record from our own host that names our own PID but is
// not one we hold is stale: no other live process can have our PID. A record older than the host
// field was never refreshed, so its age proves nothing; a live older-version server would look
// expired. If it names our PID, refuse it and name the file.
type Liveness = { live: false } | { live: true; reason: string };

function judgeRecord(path: string, text: string, record: GuardRecord): Liveness {
  const owned = `process ${record.pid} already owns it`;
  if (heldGuards.has(text)) return { live: true, reason: owned };
  if (record.host !== undefined && record.host !== hostname()) return judgeLease(path, record.host);
  if (record.pid !== process.pid)
    return processIsAlive(record.pid) ? { live: true, reason: owned } : { live: false };
  if (record.host === hostname()) return { live: false };
  return {
    live: true,
    reason: `an older DFIR Companion recorded process ${record.pid}; if no other server uses this cases folder, delete ${path} and restart`,
  };
}

function judgeLease(path: string, host: string): Liveness {
  const touchedAt = mtimeMsIfPresent(path);
  if (touchedAt === null) return { live: false };
  const remainingMs = LEASE_MS - (Date.now() - touchedAt);
  if (remainingMs <= 0) return { live: false };
  return {
    live: true,
    reason: `a server on host ${host} holds it; if that server has stopped, retry in ${Math.ceil(remainingMs / 1000)} seconds`,
  };
}

function startHeartbeat(path: string, contents: string): NodeJS.Timeout {
  const timer = setInterval(() => {
    try {
      if (readIfPresent(path) !== contents) return;
      const now = new Date();
      utimesSync(path, now, now);
    } catch {
      // A missed beat only shortens the lease another host sees; the next beat retries.
    }
  }, WRITER_GUARD_HEARTBEAT_MS);
  timer.unref();
  return timer;
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
    host: hostname(),
  } satisfies GuardRecord);

  for (;;) {
    try {
      const descriptor = openSync(path, "wx", 0o600);
      try {
        writeFileSync(descriptor, contents, { encoding: "utf8" });
      } finally {
        closeSync(descriptor);
      }
      heldGuards.add(contents);
      const heartbeat = startHeartbeat(path, contents);
      let released = false;
      return {
        path,
        release(): void {
          if (released) return;
          released = true;
          clearInterval(heartbeat);
          heldGuards.delete(contents);
          removeIfUnchanged(path, contents);
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const existingText = readIfPresent(path);
      if (existingText === null) continue; // the owner released it — compete for it again
      const existing = guardRecord(existingText);
      const liveness = existing ? judgeRecord(path, existingText, existing) : { live: false as const };
      if (liveness.live) {
        throw new Error(`team mode requires one DFIR Companion writer per cases root; ${liveness.reason}`);
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
