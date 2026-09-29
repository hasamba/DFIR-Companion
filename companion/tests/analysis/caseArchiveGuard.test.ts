import { describe, it, expect, beforeEach } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { archiveCase } from "../../src/analysis/caseArchive.js";
import { INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";

// #1846: "Archive to ZIP" read every case file by name with readFile, which follows a link and opens
// a FIFO. A name swapped for a link to another case's file put that file in this case's archive.
// Now each file is read through storage/caseFileRead.ts and any refusal fails the whole archive.
const POSIX = process.platform !== "win32";
const SECRET = "other-case-secret-token";

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-archguard-"));
  await mkdir(join(root, "c1", "screenshots"), { recursive: true });
  await mkdir(join(root, "c2", "screenshots"), { recursive: true });
  await writeFile(join(root, "c1", "case.json"), "{}");
  await writeFile(join(root, "c1", "screenshots", "a.png"), "benign");
  await writeFile(join(root, "c2", "case.json"), SECRET);
  await writeFile(join(root, "c2", "screenshots", "a.png"), SECRET);
});

async function zipsInRoot(): Promise<string[]> {
  return (await readdir(root)).filter((n) => n.endsWith(".zip"));
}

describe("archiveCase — reads through the case-file guard (#1846)", () => {
  it("archives a plain case", async () => {
    const r = await archiveCase(root, "c1");
    expect(r.manifest.files.map((f) => f.path).sort()).toEqual(["case.json", "screenshots/a.png"]);
  });

  it.skipIf(!POSIX)(
    "fails on a file swapped for a symlink into another case, and writes no archive",
    async () => {
      await symlink(join(root, "c2", "case.json"), join(root, "c1", "screenshots", "b.png"));
      await expect(archiveCase(root, "c1")).rejects.toThrow(
        /screenshots\/b\.png.*symlink.*refusing to include/,
      );
      expect(await zipsInRoot()).toEqual([]);
    },
  );

  it.skipIf(!POSIX)("fails on a folder swapped for a link after the walk", async () => {
    // The walk sees a real folder; the swap lands before the read.
    const scanFiles = async (): Promise<string[]> => {
      await rm(join(root, "c1", "screenshots"), { recursive: true });
      await symlink(join(root, "c2", "screenshots"), join(root, "c1", "screenshots"));
      return ["case.json", "screenshots/a.png"];
    };
    await expect(archiveCase(root, "c1", { scanFiles })).rejects.toThrow(/refusing to include/);
    expect(await zipsInRoot()).toEqual([]);
  });

  it.skipIf(!POSIX)(
    "fails on a FIFO instead of hanging",
    async () => {
      try {
        execFileSync("mkfifo", [join(root, "c1", "screenshots", "f.png")], {
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch {
        return;
      }
      await expect(archiveCase(root, "c1")).rejects.toThrow(/special file/);
    },
    5_000,
  );

  it.skipIf(!POSIX)("fails when the case database is a link to another case's database", async () => {
    await mkdir(join(root, "c1", "state"), { recursive: true });
    await mkdir(join(root, "c2", "state"), { recursive: true });
    await writeFile(join(root, "c2", "state", INVESTIGATION_DB_FILENAME), SECRET);
    await symlink(
      join(root, "c2", "state", INVESTIGATION_DB_FILENAME),
      join(root, "c1", "state", INVESTIGATION_DB_FILENAME),
    );
    await expect(archiveCase(root, "c1")).rejects.toThrow(/symlink/);
    expect(await zipsInRoot()).toEqual([]);
  });
});
