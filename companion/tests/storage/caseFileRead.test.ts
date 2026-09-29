import { describe, it, expect, beforeEach } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { link, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CaseFileRefusedError,
  openCaseFile,
  readCaseFile,
  readCaseFileTail,
  snapshotCaseFile,
  withPinnedCaseFile,
  type CaseScope,
} from "../../src/storage/caseFileRead.js";

// #1846 / #1847: a case file that ships (archive, export, download, AI, SCP) is read from ONE judged
// handle whose real path is exactly <case>/<rel>. Every test plants the swap BEFORE the read.
const POSIX = process.platform !== "win32";
const SECRET = "other-case-secret-token\n";

let root: string;
let scope: CaseScope;
let c1: string;
let c2: string;

async function tryMkfifo(path: string): Promise<boolean> {
  try {
    execFileSync("mkfifo", [path], { stdio: ["ignore", "pipe", "pipe"] });
    return true;
  } catch {
    return false;
  }
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-casefile-"));
  c1 = join(root, "c1");
  c2 = join(root, "c2");
  await mkdir(join(c1, "screenshots"), { recursive: true });
  await mkdir(join(c2, "screenshots"), { recursive: true });
  await writeFile(join(c1, "screenshots", "a.png"), "benign-bytes");
  await writeFile(join(c2, "screenshots", "a.png"), SECRET);
  await writeFile(join(c2, "case.json"), SECRET);
  scope = { casesRoot: root, caseDir: c1 };
});

async function refusal(p: Promise<unknown>): Promise<CaseFileRefusedError> {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(CaseFileRefusedError);
  return err as CaseFileRefusedError;
}

describe("openCaseFile / readCaseFile", () => {
  it("reads a plain case file", async () => {
    expect((await readCaseFile(scope, join(c1, "screenshots", "a.png"))).toString()).toBe("benign-bytes");
  });

  it("throws ENOENT for a missing file", async () => {
    await expect(readCaseFile(scope, join(c1, "screenshots", "nope.png"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it.skipIf(!POSIX)("refuses a final-component symlink to another case", async () => {
    await symlink(join(c2, "case.json"), join(c1, "screenshots", "b.png"));
    const err = await refusal(readCaseFile(scope, join(c1, "screenshots", "b.png")));
    expect(err.kind).toBe("symlink");
  });

  it.skipIf(!POSIX)("refuses a symlink to a file inside the same case (no links at all)", async () => {
    await symlink(join(c1, "screenshots", "a.png"), join(c1, "screenshots", "b.png"));
    expect((await refusal(readCaseFile(scope, join(c1, "screenshots", "b.png")))).kind).toBe("symlink");
  });

  it.skipIf(!POSIX)("refuses a folder above the file swapped for a link into another case", async () => {
    await rm(join(c1, "screenshots"), { recursive: true });
    await symlink(join(c2, "screenshots"), join(c1, "screenshots"));
    const err = await refusal(readCaseFile(scope, join(c1, "screenshots", "a.png")));
    expect(err.message).not.toContain(SECRET.trim());
  });

  it.skipIf(!POSIX)("refuses a case folder that is itself a link out of the cases root", async () => {
    const elsewhere = await mkdtemp(join(tmpdir(), "dfir-casefile-away-"));
    await mkdir(join(elsewhere, "screenshots"));
    await writeFile(join(elsewhere, "screenshots", "a.png"), SECRET);
    await rm(c1, { recursive: true });
    await symlink(elsewhere, c1);
    await refusal(readCaseFile(scope, join(c1, "screenshots", "a.png")));
  });

  it("refuses a hardlink", async () => {
    await link(join(c2, "case.json"), join(c1, "screenshots", "h.png"));
    expect((await refusal(readCaseFile(scope, join(c1, "screenshots", "h.png")))).kind).toBe("hardlink");
  });

  it.skipIf(!POSIX)(
    "refuses a FIFO without hanging",
    async () => {
      const fifo = join(c1, "screenshots", "f.png");
      if (!(await tryMkfifo(fifo))) return;
      expect((await refusal(readCaseFile(scope, fifo))).kind).toBe("special file");
    },
    5_000,
  );

  it("refuses a path outside the case folder", async () => {
    await refusal(readCaseFile(scope, join(c2, "case.json")));
  });

  it("reads a tail from the judged handle", async () => {
    await writeFile(join(c1, "log.txt"), "0123456789");
    expect(await readCaseFileTail(scope, join(c1, "log.txt"), 4)).toEqual({
      bytes: Buffer.from("6789"),
      size: 10,
    });
  });

  it("a caller owns a handle that keeps reading the judged inode after a swap", async () => {
    const p = join(c1, "screenshots", "a.png");
    const file = await openCaseFile(scope, p);
    try {
      await rename(p, join(c1, "moved.png"));
      if (POSIX) await symlink(join(c2, "case.json"), p);
      expect((await file.handle.readFile()).toString()).toBe("benign-bytes");
    } finally {
      await file.handle.close();
    }
  });
});

describe("snapshotCaseFile", () => {
  it("copies the judged bytes, hashes them, and dispose removes the copy", async () => {
    const staging = join(root, ".export-staging");
    const snap = await snapshotCaseFile(scope, join(c1, "screenshots", "a.png"), staging, { name: "a.png" });
    expect(await readFile(snap.path, "utf8")).toBe("benign-bytes");
    expect(snap.bytes).toBe(12);
    expect(snap.sha256).toBe(createHash("sha256").update("benign-bytes").digest("hex"));
    await snap.dispose();
    expect(existsSync(snap.path)).toBe(false);
    expect(await readdir(staging)).toEqual([]);
  });

  it("an empty file snapshots as empty", async () => {
    await writeFile(join(c1, "empty.bin"), "");
    const snap = await snapshotCaseFile(scope, join(c1, "empty.bin"), join(root, ".export-staging"));
    expect(snap.bytes).toBe(0);
    await snap.dispose();
  });

  it.skipIf(!POSIX)("a refused source leaves nothing in staging", async () => {
    await symlink(join(c2, "case.json"), join(c1, "screenshots", "b.png"));
    const staging = join(root, ".export-staging");
    await refusal(snapshotCaseFile(scope, join(c1, "screenshots", "b.png"), staging));
    expect(existsSync(staging) ? await readdir(staging) : []).toEqual([]);
  });

  it("a cancelled copy leaves nothing in staging", async () => {
    const staging = join(root, ".export-staging");
    await writeFile(join(c1, "big.bin"), Buffer.alloc(4 << 20, 1));
    const ac = new AbortController();
    ac.abort();
    await expect(
      snapshotCaseFile(scope, join(c1, "big.bin"), staging, { signal: ac.signal }),
    ).rejects.toThrow();
    expect(await readdir(staging)).toEqual([]);
  });
});

describe("withPinnedCaseFile", () => {
  it("passes when the name still holds the same inode", async () => {
    await expect(withPinnedCaseFile(scope, join(c1, "screenshots", "a.png"), async () => 7)).resolves.toBe(7);
  });

  it("fails when the name is replaced during the work", async () => {
    const p = join(c1, "screenshots", "a.png");
    const err = await refusal(
      withPinnedCaseFile(scope, p, async () => {
        await rm(p);
        await writeFile(p, "other");
      }),
    );
    expect(err.kind).toBe("changed file");
  });

  it.skipIf(!POSIX)("fails when the name becomes a link during the work", async () => {
    const p = join(c1, "screenshots", "a.png");
    await refusal(
      withPinnedCaseFile(scope, p, async () => {
        await rm(p);
        await symlink(join(c2, "case.json"), p);
      }),
    );
  });

  it("a missing file stays allowed when it stays missing", async () => {
    await expect(withPinnedCaseFile(scope, join(c1, "none.db"), async () => "ok")).resolves.toBe("ok");
  });
});
