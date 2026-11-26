import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FolderMoveCounter, heldStill } from "../../src/storage/caseFolderMoves.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2945: every case-folder move between the active root and _archived/ is counted, so a check that
// cannot hold the case store's per-case locks can still tell whether a folder moved while it looked.

const dirs: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0))
    await rm(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-2945-moves-"));
  dirs.push(root);
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { root, store };
}

describe("FolderMoveCounter (#2945)", () => {
  it("counts a move as started before it runs and in flight until it settles", async () => {
    const counter = new FolderMoveCounter();
    let release!: () => void;
    let seenInside: { started: number; inFlight: number } | null = null;
    const moving = counter.track(async () => {
      seenInside = counter.state();
      await new Promise<void>((r) => (release = r));
    });
    expect(seenInside).toEqual({ started: 1, inFlight: 1 });
    const during = counter.state();
    release();
    await moving;
    expect(counter.state()).toEqual({ started: 1, inFlight: 0 });
    expect(during).toEqual({ started: 1, inFlight: 1 }); // a fresh object, not a live view
  });

  it("settles a move that throws synchronously or rejects", async () => {
    const counter = new FolderMoveCounter();
    await expect(
      counter.track(() => {
        throw new Error("sync");
      }),
    ).rejects.toThrow("sync");
    await expect(counter.track(() => Promise.reject(new Error("async")))).rejects.toThrow("async");
    expect(counter.state()).toEqual({ started: 2, inFlight: 0 });
  });

  it("holds still only with no move started and none in flight at either end", () => {
    const s = (started: number, inFlight: number) => ({ started, inFlight });
    expect(heldStill(s(3, 0), s(3, 0))).toBe(true);
    expect(heldStill(s(3, 0), s(5, 0))).toBe(false); // moved twice and came back
    expect(heldStill(s(3, 1), s(3, 1))).toBe(false); // a move in flight at the start
    expect(heldStill(s(3, 0), s(4, 1))).toBe(false); // a move still in flight at the end
  });
});

describe("CaseStore counts every folder move (#2945)", () => {
  it("archive, restore and the archive-label repair move each count once", async () => {
    const { root, store } = await makeStore();
    await store.archiveCaseFolder("c1");
    expect(store.folderMoves.state()).toEqual({ started: 1, inFlight: 0 });
    await store.restoreCaseFolder("c1");
    expect(store.folderMoves.state()).toEqual({ started: 2, inFlight: 0 });
    // A case labelled archived but sitting in the active root: the repair moves it.
    const metaPath = join(root, "c1", "case.json");
    const meta = JSON.parse(await readFile(metaPath, "utf8")) as Record<string, unknown>;
    await writeFile(metaPath, JSON.stringify({ ...meta, status: "archived" }));
    expect(await store.reconcileArchiveLabel("c1")).toBe(true);
    expect(existsSync(join(root, "_archived", "c1"))).toBe(true);
    expect(store.folderMoves.state()).toEqual({ started: 3, inFlight: 0 });
  });

  it("counts the move back when the status write after a move fails", async () => {
    const { root, store } = await makeStore();
    vi.spyOn(
      store as unknown as { writeCaseMetaLocked: () => Promise<never> },
      "writeCaseMetaLocked",
    ).mockRejectedValueOnce(new Error("disk full"));
    await expect(store.archiveCaseFolder("c1", "archived")).rejects.toThrow("disk full");
    expect(existsSync(join(root, "c1"))).toBe(true); // moved back
    expect(store.folderMoves.state()).toEqual({ started: 2, inFlight: 0 });
  });

  it("counts a failed move back too, and leaves nothing in flight", async () => {
    const { root, store } = await makeStore();
    vi.spyOn(
      store as unknown as { writeCaseMetaLocked: () => Promise<never> },
      "writeCaseMetaLocked",
    ).mockImplementationOnce(async () => {
      // Something now occupies the old place, so the move back cannot land.
      await mkdir(join(root, "c1", "blocker"), { recursive: true });
      throw new Error("disk full");
    });
    await expect(store.archiveCaseFolder("c1", "archived")).rejects.toThrow("moving it back also failed");
    expect(store.folderMoves.state()).toEqual({ started: 2, inFlight: 0 });
  });

  it("a move the store did not make is not counted", async () => {
    const { root, store } = await makeStore();
    await mkdir(join(root, "_archived"), { recursive: true });
    await rename(join(root, "c1"), join(root, "_archived", "c1"));
    expect(store.folderMoves.state()).toEqual({ started: 0, inFlight: 0 });
  });
});
