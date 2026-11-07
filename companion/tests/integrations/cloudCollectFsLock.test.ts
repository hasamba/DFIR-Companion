import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// #2370: on Windows a rename over a file that another handle holds (Defender, the indexer, a sync
// client, a reader) fails with EPERM/EBUSY/EACCES for a moment. The collect fs must ride that out
// like every other atomic write in the app, or one locked checkpoint write fails the collection.

const renameFaults: Array<{ code: string; times: number }> = [];

vi.mock("node:fs/promises", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...real,
    rename: async (from: string, to: string) => {
      const fault = renameFaults[0];
      if (fault && fault.times > 0) {
        fault.times--;
        throw Object.assign(new Error(`${fault.code}: operation not permitted, rename`), {
          code: fault.code,
        });
      }
      return real.rename(from, to);
    },
  };
});

const { nodeCollectFs } = await import("../../src/integrations/cloudCollect/collectFs.js");
const { writeCheckpoint, readCheckpoint } =
  await import("../../src/integrations/cloudCollect/collectCheckpoint.js");
const { collectionPaths } = await import("../../src/integrations/cloudCollect/collectManifest.js");

let dir = "";
afterEach(() => {
  renameFaults.length = 0;
  delete process.env.DFIR_ATOMIC_WRITE_RETRIES;
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = "";
});

function checkpoint(collectionId: string) {
  return {
    version: 1 as const,
    collectionId,
    caseId: "c1",
    status: "running" as const,
    subWindows: [],
    imported: [],
    missing: [],
    quarantined: [],
    updatedAt: "2026-10-01T00:00:00Z",
  } as unknown as Parameters<typeof writeCheckpoint>[2];
}

describe("collect fs rename under a transient Windows lock (#2370)", () => {
  it("a checkpoint write rides out a brief EPERM and lands", async () => {
    dir = mkdtempSync(join(tmpdir(), "collect-fs-lock-"));
    const paths = collectionPaths(dir);
    renameFaults.push({ code: "EPERM", times: 2 });
    await writeCheckpoint(nodeCollectFs, paths, checkpoint("cc-a"));
    expect((await readCheckpoint(nodeCollectFs, paths))?.collectionId).toBe("cc-a");
    expect(renameFaults[0].times).toBe(0);
  });

  it.each(["EBUSY", "EACCES"])("retries %s too", async (code) => {
    dir = mkdtempSync(join(tmpdir(), "collect-fs-lock-"));
    renameFaults.push({ code, times: 1 });
    await nodeCollectFs.writeFileSync(join(dir, "a.tmp"), "x");
    await nodeCollectFs.rename(join(dir, "a.tmp"), join(dir, "a.json"));
    expect(readFileSync(join(dir, "a.json"), "utf8")).toBe("x");
  });

  it("a non-transient error throws at once, without retrying", async () => {
    dir = mkdtempSync(join(tmpdir(), "collect-fs-lock-"));
    renameFaults.push({ code: "ENOSPC", times: 2 });
    await expect(nodeCollectFs.rename(join(dir, "a"), join(dir, "b"))).rejects.toMatchObject({
      code: "ENOSPC",
    });
    expect(renameFaults[0].times).toBe(1);
  });

  it("a lock that never clears gives up within the budget and rethrows the original error", async () => {
    dir = mkdtempSync(join(tmpdir(), "collect-fs-lock-"));
    process.env.DFIR_ATOMIC_WRITE_RETRIES = "2";
    renameFaults.push({ code: "EPERM", times: 100 });
    await expect(nodeCollectFs.rename(join(dir, "a"), join(dir, "b"))).rejects.toMatchObject({
      code: "EPERM",
    });
    expect(renameFaults[0].times).toBe(97); // one try plus two retries
  });
});
