import { mkdtempSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Concurrent startup against ONE cases root. Every scenario here needs two starters interleaved at
// a specific syscall, so node:fs is wrapped to run the second starter — the real acquire, not a
// stand-in — at the exact moment the first is mid-recovery. The assertions are on the filesystem
// and on who ended up owning the guard, never on the wrapper.

type Hook = ((path: string) => void) | null;
let onUnlink: Hook = null;
let onOpenFailed: Hook = null;
let onRead: Hook = null;

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    unlinkSync: (path: Parameters<typeof actual.unlinkSync>[0]) => {
      onUnlink?.(String(path));
      return actual.unlinkSync(path);
    },
    openSync: (...args: Parameters<typeof actual.openSync>) => {
      try {
        return actual.openSync(...args);
      } catch (err) {
        onOpenFailed?.(String(args[0]));
        throw err;
      }
    },
    readFileSync: (...args: Parameters<typeof actual.readFileSync>) => {
      const out = actual.readFileSync(...args);
      onRead?.(String(args[0]));
      return out;
    },
  };
});

import { acquireWriterGuard } from "../../src/auth/writerGuard.js";

const STALE = JSON.stringify({
  pid: 2_147_483_647, // never a live pid on any supported platform
  token: "stale-token",
  startedAt: "2020-01-01T00:00:00.000Z",
});

function guardDir(): string {
  return mkdtempSync(join(tmpdir(), "dfir-writer-race-"));
}

afterEach(() => {
  onUnlink = null;
  onOpenFailed = null;
  onRead = null;
});

describe("acquireWriterGuard under concurrent startup", () => {
  it("lets only one of two starters recover the same stale guard", () => {
    // The window: a starter reads a DEAD owner, and between that read and its unlink another
    // starter recovers the guard and creates its own. An unconditional unlink then deletes the new
    // owner's guard and the first starter acquires on top of it — two writers on one cases root,
    // which is the single thing this guard exists to prevent.
    const path = join(guardDir(), "writer.lock");
    writeFileSync(path, STALE, "utf8");

    const acquired: string[] = [];
    let interleaved = false;
    onUnlink = (unlinked) => {
      if (interleaved || unlinked !== path) return;
      interleaved = true;
      try {
        acquireWriterGuard(path);
        acquired.push("second");
      } catch {
        /* refused — the correct outcome for the starter that loses the race */
      }
    };

    try {
      acquireWriterGuard(path);
      acquired.push("first");
    } catch {
      /* refused */
    }

    expect(interleaved).toBe(true); // the race was actually exercised
    expect(acquired).toHaveLength(1);
    // The guard on disk belongs to the starter that won, and to nobody else.
    expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ pid: process.pid });
  });

  it("retries when the guard disappears before it can be read", () => {
    // Between our failed exclusive create and our read of the existing guard, the owner released
    // it. That is an ordinary race, not a fault: the loop must go back and compete for the now-free
    // guard rather than let ENOENT escape into startup.
    const path = join(guardDir(), "writer.lock");
    writeFileSync(path, STALE, "utf8");
    let removed = false;
    onOpenFailed = (failed) => {
      if (removed || failed !== path) return;
      removed = true;
      unlinkSync(path); // the other starter released it a moment after our create failed
    };

    const guard = acquireWriterGuard(path);

    expect(removed).toBe(true);
    expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ pid: process.pid });
    guard.release();
  });

  it("retries when an unparseable guard disappears before it can be aged", () => {
    // Same race one step later: the guard did not parse, so its age decides whether it is a
    // half-written guard or an abandoned one — and the owner removed it before we could stat it.
    const path = join(guardDir(), "writer.lock");
    writeFileSync(path, "not-json", "utf8");
    let removed = false;
    onRead = (read) => {
      if (removed || read !== path) return;
      removed = true;
      unlinkSync(path);
    };

    const guard = acquireWriterGuard(path);

    expect(removed).toBe(true);
    expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ pid: process.pid });
    guard.release();
  });
});
