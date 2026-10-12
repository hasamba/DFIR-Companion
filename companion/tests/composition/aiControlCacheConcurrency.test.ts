// #2153: setControl was an unserialized read-modify-write. Two concurrent patches both read the
// same base, so the second save overwrote the first — a capture flush writing lastAnalyzedSeq at
// the moment the analyst paused AI brought `enabled: true` back. setControl now runs under a
// per-case StateLock.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAiControlCache } from "../../src/composition/aiControlCache.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import type { CaseStore } from "../../src/storage/caseStore.js";

const CASE_ID = "case-2153";

let root: string;
let store: CaseStore;

function stateDir(id: string): string {
  return join(root, id, "state");
}

async function seed(control: object): Promise<void> {
  await mkdir(stateDir(CASE_ID), { recursive: true });
  await writeFile(join(stateDir(CASE_ID), "ai-control.json"), JSON.stringify(control));
}

async function onDisk(): Promise<unknown> {
  return JSON.parse(await readFile(join(stateDir(CASE_ID), "ai-control.json"), "utf8"));
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "ai-control-2153-"));
  store = { casesRoot: root, stateDir } as unknown as CaseStore;
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

describe("aiControlCache setControl serialization (#2153)", () => {
  it("keeps both disjoint patches when the cache is warm", async () => {
    await seed({ enabled: true, lastAnalyzedSeq: 0 });
    const cache = createAiControlCache(store);
    await cache.getControl(CASE_ID); // warm the cache

    await Promise.all([
      cache.setControl(CASE_ID, { enabled: false }),
      cache.setControl(CASE_ID, { lastAnalyzedSeq: 42 }),
    ]);

    const expected = { enabled: false, lastAnalyzedSeq: 42 };
    expect(await onDisk()).toEqual(expected);
    expect(await cache.getControl(CASE_ID)).toEqual(expected);
  });

  it("keeps both disjoint patches when the cache is cold", async () => {
    await seed({ enabled: true, lastAnalyzedSeq: 0 });
    const cache = createAiControlCache(store);

    await Promise.all([
      cache.setControl(CASE_ID, { enabled: false }),
      cache.setControl(CASE_ID, { lastAnalyzedSeq: 42 }),
    ]);

    const expected = { enabled: false, lastAnalyzedSeq: 42 };
    expect(await onDisk()).toEqual(expected);
    expect(await cache.getControl(CASE_ID)).toEqual(expected);
  });

  it("returns the merged, persisted state to the later caller", async () => {
    await seed({ enabled: true, lastAnalyzedSeq: 0 });
    const cache = createAiControlCache(store);

    const [first, second] = await Promise.all([
      cache.setControl(CASE_ID, { enabled: false }),
      cache.setControl(CASE_ID, { lastAnalyzedSeq: 42 }),
    ]);

    expect(first).toEqual({ enabled: false, lastAnalyzedSeq: 0 });
    expect(second).toEqual({ enabled: false, lastAnalyzedSeq: 42 });
    expect(second).toEqual(await onDisk());
  });

  it("does not wedge the lock when a save rejects", async () => {
    await seed({ enabled: true, lastAnalyzedSeq: 0 });
    const cache = createAiControlCache(store);
    vi.spyOn(AiControlStore.prototype, "save").mockRejectedValueOnce(new Error("disk full"));

    await expect(cache.setControl(CASE_ID, { enabled: false })).rejects.toThrow("disk full");
    const next = await cache.setControl(CASE_ID, { lastAnalyzedSeq: 7 });

    // The failed patch never reached the cache, so the next write does not persist it either.
    expect(next).toEqual({ enabled: true, lastAnalyzedSeq: 7 });
    expect(await onDisk()).toEqual(next);
  });
});
