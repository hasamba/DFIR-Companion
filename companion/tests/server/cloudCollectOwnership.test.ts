import { describe, it, expect } from "vitest";
import { claimResume, workerStarted, workerLive } from "../../src/routes/cloudCollectOwnership.js";
import { writeCheckpoint } from "../../src/integrations/cloudCollect/collectCheckpoint.js";
import { isAtomicWriteTempPath } from "../../src/storage/atomicWrite.js";
import type { CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type { CollectionPaths } from "../../src/integrations/cloudCollect/collectManifest.js";
import type { CollectionCheckpoint } from "../../src/integrations/cloudCollect/collectTypes.js";

// #2402: one writer per cloud collection folder.
describe("cloud collection ownership", () => {
  it("a Resume claim is exclusive until released", () => {
    const release = claimResume("/c/a");
    expect(release).not.toBeNull();
    expect(claimResume("/c/a")).toBeNull();
    expect(claimResume("/c/b")).not.toBeNull();
    release!();
    expect(claimResume("/c/a")).not.toBeNull();
  });

  it("a second worker on the same folder is refused while the first is live", () => {
    const release = workerStarted("/c/w");
    expect(workerLive("/c/w")).toBe(true);
    expect(workerStarted("/c/w")).toBeNull();
    release!();
    expect(workerLive("/c/w")).toBe(false);
  });
});

describe("writeCheckpoint temp file", () => {
  it("uses a unique atomicWrite-shaped temp per write, then renames and syncs", async () => {
    const calls: string[] = [];
    const fs = {
      writeFileSync: async (p: string) => void calls.push(`write ${p}`),
      rename: async (from: string, to: string) => void calls.push(`rename ${from} -> ${to}`),
      fsyncDir: async (d: string) => void calls.push(`sync ${d}`),
    } as unknown as CollectFs;
    const paths = { dir: "/c/x", checkpoint: "/c/x/checkpoint.json" } as CollectionPaths;
    const cp = { version: 1 } as unknown as CollectionCheckpoint;
    await writeCheckpoint(fs, paths, cp);
    await writeCheckpoint(fs, paths, cp);
    const temps = calls.filter((c) => c.startsWith("write ")).map((c) => c.slice(6));
    expect(temps).toHaveLength(2);
    expect(temps[0]).not.toBe(temps[1]);
    for (const t of temps) expect(isAtomicWriteTempPath(t)).toBe(true);
    expect(calls[1]).toBe(`rename ${temps[0]} -> /c/x/checkpoint.json`);
    expect(calls[2]).toBe("sync /c/x");
  });
});
