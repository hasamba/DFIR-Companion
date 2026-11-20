import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, symlink, utimes, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sweepStaleAtomicTemps } from "../../src/storage/staleTempSweep.js";

// #2770: an archive killed mid-write leaves `<casesRoot>/<name>.zip.<uuid>.tmp`. A startup sweep
// removes only that exact shape, at the top level of the cases root, once it is a day old.
const UUID = "0123abcd-4567-89ab-cdef-0123456789ab";
const DAY_MS = 24 * 60 * 60 * 1000;

let root: string;
const exists = (p: string): Promise<boolean> =>
  access(p).then(
    () => true,
    () => false,
  );

async function makeFile(path: string, ageMs: number): Promise<void> {
  await writeFile(path, "x");
  const when = new Date(Date.now() - ageMs);
  await utimes(path, when, when);
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-stale-temp-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("sweepStaleAtomicTemps", () => {
  it("removes only old top-level atomic-write temps and keeps everything else", async () => {
    const staleTemp = join(root, `Case-1.zip.${UUID}.tmp`);
    const freshTemp = join(root, `Case-2.zip.${UUID.replace("0123abcd", "9999ffff")}.tmp`);
    const bareTmp = join(root, "payload.tmp");
    const realZip = join(root, "Case-3.zip");
    const caseDir = join(root, "case-4");
    const nestedTemp = join(caseDir, `evidence.bin.${UUID}.tmp`);
    await makeFile(staleTemp, 2 * DAY_MS);
    await makeFile(freshTemp, 60 * 1000);
    await makeFile(bareTmp, 2 * DAY_MS);
    await makeFile(realZip, 2 * DAY_MS);
    await mkdir(caseDir);
    await makeFile(nestedTemp, 2 * DAY_MS);

    const removed = await sweepStaleAtomicTemps(root);

    expect(removed).toBe(1);
    expect(await exists(staleTemp)).toBe(false);
    expect(await exists(freshTemp)).toBe(true);
    expect(await exists(bareTmp)).toBe(true);
    expect(await exists(realZip)).toBe(true);
    expect(await exists(nestedTemp)).toBe(true);
  });

  it("never removes a directory, even one named like a temp", async () => {
    const dirLikeTemp = join(root, `folder.${UUID}.tmp`);
    await mkdir(dirLikeTemp);
    await makeFile(join(dirLikeTemp, "inner.txt"), 2 * DAY_MS);
    const old = new Date(Date.now() - 2 * DAY_MS);
    await utimes(dirLikeTemp, old, old);

    expect(await sweepStaleAtomicTemps(root)).toBe(0);
    expect(await exists(join(dirLikeTemp, "inner.txt"))).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "never follows or removes a symlink named like a temp",
    async () => {
      const outside = await mkdtemp(join(tmpdir(), "dfir-stale-target-"));
      try {
        const target = join(outside, "evidence.bin");
        await makeFile(target, 2 * DAY_MS);
        const link = join(root, `link.${UUID}.tmp`);
        await symlink(target, link);

        expect(await sweepStaleAtomicTemps(root, Date.now() + 10 * DAY_MS)).toBe(0);
        expect(await exists(target)).toBe(true);
        expect(await exists(link)).toBe(true);
      } finally {
        await rm(outside, { recursive: true, force: true });
      }
    },
  );

  it("honours the injected clock", async () => {
    const temp = join(root, `Case-5.zip.${UUID}.tmp`);
    await makeFile(temp, 60 * 1000);
    expect(await sweepStaleAtomicTemps(root, Date.now() + 2 * DAY_MS)).toBe(1);
    expect(await exists(temp)).toBe(false);
  });

  it("returns 0 for a missing root", async () => {
    expect(await sweepStaleAtomicTemps(join(root, "does-not-exist"))).toBe(0);
  });
});
