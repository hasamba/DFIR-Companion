import { describe, it, expect, beforeEach } from "vitest";
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
