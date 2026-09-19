import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, writeFile, appendFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";

// #1329. The text and image branches of the drop sweep gated on `isOversize(file.size)` taken from
// the directory LISTING stat, then read the path in full — the check-then-read shape #947 named.
// A file that grows (or is swapped for a larger one) between the sweep's listing and the read was
// read whole, and the cap bounded nothing. The BTM branch of the same function already reads
// through an fstat-bounded descriptor; this pins the two older branches to the same recipe.
//
// The growth is staged at the one hook between the listing stat and the whole-file read: the head
// sniff. Wrapping it appends bytes past the cap to the file it is about to sniff, so the listing
// saw a small file and the read sees a large one — exactly the window the issue describes.

const CAP_BYTES = 1024;

vi.mock("../../src/storage/noFollowRead.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/storage/noFollowRead.js")>();
  return {
    ...real,
    readHeadNoFollow: async (path: string, length: number) => {
      await appendFile(path, Buffer.alloc(CAP_BYTES * 4, 0x41));
      return real.readHeadNoFollow(path, length);
    },
  };
});

const savedCap = process.env.DFIR_DROP_MAX_BYTES;
beforeAll(() => {
  process.env.DFIR_DROP_MAX_BYTES = String(CAP_BYTES);
});
afterAll(() => {
  if (savedCap === undefined) delete process.env.DFIR_DROP_MAX_BYTES;
  else process.env.DFIR_DROP_MAX_BYTES = savedCap;
});

function harness(store: CaseStore, dropStatusStore: DropStatusStore) {
  const refuse = (): never => {
    throw new Error("not expected to be reached");
  };
  return createDropFolder({
    store,
    options: { dropStatusStore },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: () => {},
    dispatchNotify: () => {},
    // Reached only if the grown file was read in full — the exact outcome under test.
    resolveImportKind: () => {
      throw new Error("read in full past the cap");
    },
    ingestStreamed: refuse,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
}

async function seed(name: string, body: Buffer | string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-bounded-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  await writeFile(join(dropDir, name), body);
  return { store, dropDir, dropStatusStore: new DropStatusStore(store) };
}

async function sweepTwice(store: CaseStore, dropStatusStore: DropStatusStore) {
  const drops = harness(store, dropStatusStore);
  // A file is ready only once a second sweep sees it unchanged (one poll interval of stability).
  await drops.scanCaseDrops("c1");
  await drops.scanCaseDrops("c1");
  return dropStatusStore.load("c1");
}

describe("drop folder bounds the whole-file read by the descriptor, not the listing stat (#1329)", () => {
  it("refuses a text file that grew past the cap after the sweep listed it", async () => {
    const { store, dropDir, dropStatusStore } = await seed("notes.txt", "small,when,listed\n");
    const status = await sweepTwice(store, dropStatusStore);

    expect(status.imported).toEqual([]);
    expect(status.failed).toHaveLength(1);
    expect(status.failed[0]?.relpath).toBe("notes.txt");
    expect(status.failed[0]?.reason).toMatch(/too large/i);
    expect(status.failed[0]?.reason).toContain(`${CAP_BYTES}-byte cap`);
    expect((await stat(join(dropDir, "_failed", "notes.txt"))).isFile()).toBe(true);
  });

  it("refuses an image that grew past the cap after the sweep listed it, before decoding it", async () => {
    // A real PNG signature so nothing upstream mistakes the file for a raw binary; the bytes past
    // it never matter because the bounded read refuses before the decoder sees them.
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const { store, dropStatusStore } = await seed("shot.png", png);
    const status = await sweepTwice(store, dropStatusStore);

    expect(status.imported).toEqual([]);
    expect(status.failed).toHaveLength(1);
    expect(status.failed[0]?.relpath).toBe("shot.png");
    expect(status.failed[0]?.reason).toMatch(/too large/i);
    expect(status.failed[0]?.reason).not.toMatch(/not a readable image/);
  });
});
