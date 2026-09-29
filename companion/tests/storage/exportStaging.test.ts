import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, readdir, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EXPORT_STAGING_DIRNAME,
  EXPORT_STAGING_MAX_AGE_MS,
  createStagingDir,
  sweepStaleStaging,
} from "../../src/storage/exportStaging.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { exportEncryptedCase } from "../../src/analysis/caseExportArchive.js";

// #1851: every export stages a private copy (a whole case database, or an evidence file) under
// <casesRoot>/.export-staging and removes it in a finally block. A process that dies mid-export never
// runs that finally, and nothing else ever looked in the folder, so the copy stayed for good.

let root: string;
let staging: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-export-staging-"));
  staging = join(root, EXPORT_STAGING_DIRNAME);
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function leftover(name: string, ageMs: number): Promise<string> {
  const dir = join(staging, name);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "investigation.db"), "a full copy of a case database");
  const when = new Date(Date.now() - ageMs);
  await utimes(dir, when, when);
  return dir;
}

describe("sweepStaleStaging", () => {
  it("removes a leftover older than the max age and keeps a fresh one", async () => {
    await leftover("c1-crashed", EXPORT_STAGING_MAX_AGE_MS + 60_000);
    await leftover("c2-running", 60_000);

    const removed = await sweepStaleStaging(staging);

    expect(removed).toBe(1);
    expect(await readdir(staging)).toEqual(["c2-running"]);
  });

  it("is a no-op when the staging folder does not exist yet", async () => {
    expect(await sweepStaleStaging(staging)).toBe(0);
  });
});

describe("createStagingDir", () => {
  it("creates a private folder under the staging root, sweeping stale leftovers first", async () => {
    await leftover("c1-crashed", EXPORT_STAGING_MAX_AGE_MS + 60_000);

    const dir = await createStagingDir(staging, "c3-");

    expect(dir.startsWith(join(staging, "c3-"))).toBe(true);
    expect((await stat(dir)).isDirectory()).toBe(true);
    expect(await readdir(staging)).toEqual([dir.slice(staging.length + 1)]);
  });
});

describe("an export sweeps what a crashed export left behind", () => {
  it("removes a stale leftover and its own staging when the encrypted export runs", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "Case", investigator: "i", aiProvider: null });
    await leftover("c1-crashed", EXPORT_STAGING_MAX_AGE_MS + 60_000);

    await exportEncryptedCase(store, "c1", "a-long-enough-password");

    expect(await readdir(staging)).toEqual([]);
  });
});
