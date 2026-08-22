import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, symlink, link, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  openNoFollow,
  readFileNoFollow,
  readHeadNoFollow,
  LinkGuardError,
} from "../../src/storage/noFollowRead.js";

// The guarantee these tests exist for: a link check and the read it authorizes are ONE operation on
// ONE descriptor. Every path-based guard in this codebase used to lstat a path and then read that
// path again, and the gap between the two belonged to whoever controlled the directory.

let dir: string;
let secretPath: string;
const SECRET = "host-only-secret\n";
const CONTENT = "legitimate evidence\n";

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-nofollow-"));
  secretPath = join(dir, "secret.txt");
  await writeFile(secretPath, SECRET, "utf8");
});

describe("readFileNoFollow", () => {
  it("reads an ordinary file unchanged", async () => {
    const path = join(dir, "evidence.json");
    await writeFile(path, CONTENT, "utf8");
    expect((await readFileNoFollow(path)).toString("utf8")).toBe(CONTENT);
  });

  it("refuses a symlink instead of following it to the host file", async () => {
    const path = join(dir, "planted");
    await symlink(secretPath, path);

    const err = await readFileNoFollow(path).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LinkGuardError);
    expect((err as LinkGuardError).kind).toBe("symlink");
  });

  it("refuses a hardlink, which no symlink check and no readdir can see", async () => {
    const path = join(dir, "aliased");
    await link(secretPath, path);

    const err = await readFileNoFollow(path).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LinkGuardError);
    expect((err as LinkGuardError).kind).toBe("hardlink");
  });

  it("refuses a symlink pointing at a directory or a dangling target too", async () => {
    await mkdir(join(dir, "elsewhere"));
    await symlink(join(dir, "elsewhere"), join(dir, "to-dir"));
    await symlink(join(dir, "does-not-exist"), join(dir, "dangling"));

    await expect(readFileNoFollow(join(dir, "to-dir"))).rejects.toBeInstanceOf(LinkGuardError);
    await expect(readFileNoFollow(join(dir, "dangling"))).rejects.toBeInstanceOf(LinkGuardError);
  });

  // THE RACE ITSELF. The path is swapped between a plain file and a symlink to the secret while
  // reads run against it. A check-then-read implementation loses this: it lstats the plain file,
  // the swap lands, and the read follows the link. Reading through the checked descriptor cannot —
  // there is no interval in which the two disagree. Every read must either return the legitimate
  // content or refuse; the secret must never come back.
  it("never returns the swap target's content, however the swap is timed", async () => {
    const path = join(dir, "raced");
    let leaked = false;
    let reads = 0;

    for (let i = 0; i < 200; i++) {
      await rm(path, { force: true });
      if (i % 2 === 0) await writeFile(path, CONTENT, "utf8");
      else await symlink(secretPath, path);

      // Started before the swap below, resolved after it — the window a path-based guard exposes.
      const reading = readFileNoFollow(path).then(
        (buf) => buf.toString("utf8"),
        (err: unknown) => {
          if (!(err instanceof LinkGuardError) && (err as NodeJS.ErrnoException).code !== "ENOENT") {
            throw err;
          }
          return null;
        },
      );
      await rm(path, { force: true }).catch(() => {});
      await symlink(secretPath, path).catch(() => {});

      const got = await reading;
      if (got !== null) {
        reads++;
        if (got.includes("host-only-secret")) leaked = true;
      }
    }

    expect(leaked).toBe(false);
    // Guard against a vacuous pass: some reads must actually have succeeded.
    expect(reads).toBeGreaterThan(0);
  });
});

describe("readHeadNoFollow", () => {
  it("reads only the requested prefix", async () => {
    const path = join(dir, "big.bin");
    await writeFile(path, "0123456789", "utf8");
    expect((await readHeadNoFollow(path, 4)).toString("utf8")).toBe("0123");
  });

  it("returns what exists when the file is shorter than the request", async () => {
    const path = join(dir, "short.bin");
    await writeFile(path, "ab", "utf8");
    expect((await readHeadNoFollow(path, 8)).toString("utf8")).toBe("ab");
  });

  it("returns an empty buffer for a zero-length request without opening a hole", async () => {
    const path = join(dir, "empty-req");
    await writeFile(path, "abc", "utf8");
    expect((await readHeadNoFollow(path, 0)).length).toBe(0);
  });

  it("applies the same link guard as a whole-file read", async () => {
    const path = join(dir, "planted-head");
    await symlink(secretPath, path);
    await expect(readHeadNoFollow(path, 8)).rejects.toBeInstanceOf(LinkGuardError);
  });
});

describe("openNoFollow", () => {
  it("hands back a descriptor the caller closes", async () => {
    const path = join(dir, "handle.txt");
    await writeFile(path, CONTENT, "utf8");

    const handle = await openNoFollow(path);
    try {
      expect((await handle.readFile()).toString("utf8")).toBe(CONTENT);
    } finally {
      await handle.close();
    }
  });

  // A rejected open must not leak the descriptor it had already obtained.
  it("closes the descriptor when the fstat check rejects it", async () => {
    const path = join(dir, "aliased-2");
    await link(secretPath, path);
    await expect(openNoFollow(path)).rejects.toBeInstanceOf(LinkGuardError);
  });
});

// The branch below is unreachable on this platform in normal operation: Linux HAS O_NOFOLLOW, so
// `before` is null and the identity comparison never runs. It runs on Windows, where it turned
// every concurrent atomic write into "symlink detected … refusing to include in export (security)"
// — an analyst exporting a case while any sidecar saved. Forcing the fallback is the only way to
// cover it anywhere but Windows, and it went unnoticed precisely because nothing did.
describe("openNoFollow — the Windows fallback, forced (no O_NOFOLLOW)", () => {
  const loadWithFallback = async (lstatImpl?: (p: string) => Promise<unknown>) => {
    vi.resetModules();
    vi.doMock("node:fs", async () => {
      const real = await vi.importActual<typeof import("node:fs")>("node:fs");
      const constants = { ...real.constants } as Record<string, unknown>;
      delete constants.O_NOFOLLOW;
      return { ...real, constants, default: { ...real, constants } };
    });
    if (lstatImpl) {
      vi.doMock("node:fs/promises", async () => {
        const real = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
        return { ...real, default: real, lstat: lstatImpl };
      });
    }
    return import("../../src/storage/noFollowRead.js");
  };

  afterEach(() => {
    vi.doUnmock("node:fs");
    vi.doUnmock("node:fs/promises");
    vi.resetModules();
  });

  it("takes the fallback path at all once O_NOFOLLOW is gone", async () => {
    const mod = await loadWithFallback();
    expect(mod.NOFOLLOW_SUPPORTED).toBe(false);
  });

  // A rename by our own atomicWrite lands here: the file the descriptor opened is not the file the
  // check saw, because a legitimate write replaced it in between.
  it("retries a file replaced between the check and the open, and returns the real content", async () => {
    const path = join(dir, "swapped-once.txt");
    await writeFile(path, CONTENT, "utf8");

    const realFs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    let calls = 0;
    const mod = await loadWithFallback(async (p: string) => {
      const st = await realFs.lstat(p);
      // First look only: report an identity that cannot match the opened descriptor, exactly as a
      // rename between the two syscalls would.
      if (calls++ === 0) return { ...st, ino: Number(st.ino) + 1, isSymbolicLink: () => false };
      return st;
    });

    const buf = await mod.readFileNoFollow(path);
    expect(buf.toString("utf8")).toBe(CONTENT);
    expect(calls).toBeGreaterThan(1); // it actually retried rather than passing first time
  });

  // The bound is what keeps the retry from becoming a spin against a hostile writer.
  it("still refuses when the file is replaced on every single attempt", async () => {
    const path = join(dir, "swapped-always.txt");
    await writeFile(path, CONTENT, "utf8");

    const realFs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    let calls = 0;
    const mod = await loadWithFallback(async (p: string) => {
      calls++;
      const st = await realFs.lstat(p);
      return { ...st, ino: Number(st.ino) + 1, isSymbolicLink: () => false };
    });

    await expect(mod.readFileNoFollow(path)).rejects.toBeInstanceOf(mod.LinkGuardError);
    expect(calls).toBeGreaterThan(1); // bounded, not one-shot
    expect(calls).toBeLessThan(20); // bounded, not a spin
  });

  // The pre-check still rejects a link that is already in place, fallback or not.
  it("still refuses a symlink that was there before the open", async () => {
    const path = join(dir, "fallback-link");
    await symlink(secretPath, path);
    const mod = await loadWithFallback();
    await expect(mod.readFileNoFollow(path)).rejects.toBeInstanceOf(mod.LinkGuardError);
  });
});
