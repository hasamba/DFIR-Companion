// #2760: a damaged ai-control.json must hold AI OFF (fail closed), say which file is damaged, and
// not stick in the cache — a file repaired outside the app is picked up on the next read.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAiControlCache } from "../../src/composition/aiControlCache.js";
import type { CaseStore } from "../../src/storage/caseStore.js";

const CASE_ID = "case-2760";

let root: string;
let store: CaseStore;

const stateDir = (id: string): string => join(root, id, "state");
const file = (): string => join(stateDir(CASE_ID), "ai-control.json");

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "ai-control-2760-"));
  store = { casesRoot: root, stateDir } as unknown as CaseStore;
  await mkdir(stateDir(CASE_ID), { recursive: true });
  await writeFile(file(), "{corrupt");
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("aiControlCache on a damaged ai-control.json (#2760)", () => {
  it("returns AI off with the damage detail instead of throwing", async () => {
    const c = await createAiControlCache(store).getControl(CASE_ID);
    expect(c.enabled).toBe(false);
    expect(c.corrupt?.file).toBe("ai-control.json");
    expect(c.corrupt?.message).toContain(CASE_ID);
  });

  it.each(['"false"', '"yes"', "1", "null"])(
    "holds AI off with the damage detail for enabled %s",
    async (v) => {
      await writeFile(file(), `{"enabled":${v},"lastAnalyzedSeq":0}`);
      const c = await createAiControlCache(store).getControl(CASE_ID);
      expect(c.enabled).toBe(false);
      expect(c.corrupt?.file).toBe("ai-control.json");
      expect(c.corrupt?.message).toContain("enabled");
    },
  );

  it("does not cache the fail-closed answer, so a repaired file is read next time", async () => {
    const cache = createAiControlCache(store);
    await cache.getControl(CASE_ID);
    await writeFile(file(), JSON.stringify({ enabled: true, lastAnalyzedSeq: 7 }));
    expect(await cache.getControl(CASE_ID)).toEqual({ enabled: true, lastAnalyzedSeq: 7 });
  });

  it("setControl writes a clean record without the damage marker", async () => {
    const cache = createAiControlCache(store);
    const next = await cache.setControl(CASE_ID, { enabled: false });
    expect(next.corrupt).toBeUndefined();
    expect(JSON.parse(await readFile(file(), "utf8"))).toEqual({ enabled: false, lastAnalyzedSeq: 0 });
  });
});
