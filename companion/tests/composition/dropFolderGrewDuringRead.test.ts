import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, writeFile, stat } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";

// #2834. The bounded read throws one error for "over the cap" and for "grew between fstat and the
// end of the read". The drop folder phrased both as a size refusal — "too large at read time (N
// bytes > cap…) — use Import-from-path" — with N under the cap for a file that only grew. Such a
// file is not too large; it was still being written, and the analyst only has to drop it again.
//
// The growth is staged inside the bounded read itself: the real read is handed a handle whose stat
// is one byte short of what its read yields. (The head-sniff hook dropFolderBoundedRead.test.ts
// uses appends BEFORE the fstat, so it can only stage a file that is really over the cap.)

vi.mock("../../src/storage/boundedRead.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/storage/boundedRead.js")>();
  return {
    ...real,
    readHandleBounded: (handle: FileHandle, maxBytes: number) =>
      real.readHandleBounded(statOneByteShort(handle), maxBytes),
  };
});

function statOneByteShort(handle: FileHandle): FileHandle {
  return {
    stat: async () => ({ size: (await handle.stat()).size - 1 }),
    read: (buf: Buffer, offset: number, length: number, position: number) =>
      handle.read(buf, offset, length, position),
  } as unknown as FileHandle;
}

const CAP_BYTES = 1024 * 1024;

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
    // Reached only if the partly-read file was handed on as if it were whole.
    resolveImportKind: () => {
      throw new Error("imported a file that changed during the read");
    },
    ingestStreamed: refuse,
    ingestMacLoginItemBinary: refuse,
    ingestDiskFile: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
}

async function sweepTwice(name: string, body: Buffer | string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-grew-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  await writeFile(join(dropDir, name), body);
  const dropStatusStore = new DropStatusStore(store);
  const drops = harness(store, dropStatusStore);
  // A file is ready only once a second sweep sees it unchanged (one poll interval of stability).
  await drops.scanCaseDrops("c1");
  await drops.scanCaseDrops("c1");
  return { status: await dropStatusStore.load("c1"), dropDir };
}

// A bplist00 header under a login-item file name: enough for the drop folder to take its
// byte-native macOS login item branch, whose whole read is the one under test.
const BTM_HEAD = Buffer.concat([Buffer.from("bplist00"), Buffer.alloc(64, 0x00)]);

describe("drop folder: a file that grows during the whole read is reported as changed (#2834)", () => {
  it.each([
    ["a text file", "notes.txt", "small,when,listed\n"],
    ["an image", "shot.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
    ["a macOS login item file", "backgrounditems.btm", BTM_HEAD],
  ])("%s goes to _failed/ with the changed-while-read reason", async (_what, name, body) => {
    const { status, dropDir } = await sweepTwice(name, body);

    expect(status.imported).toEqual([]);
    expect(status.failed).toHaveLength(1);
    expect(status.failed[0]?.relpath).toBe(name);
    const reason = status.failed[0]?.reason ?? "";
    expect(reason).toBe("the file changed while it was being read — drop it again when it is complete");
    // No size figures and no advice that fits only a file that is really over a limit.
    expect(reason).not.toMatch(/too large|byte cap|\d+ bytes|Import-from-path/);
    // Still a visible failure: the file is not left in drop/ to be retried on its own.
    expect((await stat(join(dropDir, "_failed", name))).isFile()).toBe(true);
  });
});
