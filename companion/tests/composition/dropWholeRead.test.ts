import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { runImportAttempt } from "../../src/analysis/importAttempt.js";
import { ImportMemoryRefusedError, type ImportAdmissionHint } from "../../src/analysis/importMemoryGuard.js";
import { createDropFolder, dropDirOf, type DropFolderDeps } from "../../src/composition/dropFolder.js";
import { DROP_INFLIGHT_MARKER, parseInFlight } from "../../src/composition/dropInFlight.js";
import { createDropWholeReader } from "../../src/composition/dropWholeRead.js";

// #2785 — a large file UNDER the drop cap is read whole into memory before its import takes the
// case's import section. A server that ran out of memory there left no crash-loop marker, so it
// died on the same file at every start. A large under-cap file now counts its start before the
// read, and the import memory guard is asked first. Small files and small limits only.

const CAP_BYTES = 4096;
const EARLY_MARK_BYTES = 256; // injected: files at or above this are "large" for the test
const savedCap = process.env.DFIR_DROP_MAX_BYTES;
beforeAll(() => {
  process.env.DFIR_DROP_MAX_BYTES = String(CAP_BYTES);
});
afterAll(() => {
  if (savedCap === undefined) delete process.env.DFIR_DROP_MAX_BYTES;
  else process.env.DFIR_DROP_MAX_BYTES = savedCap;
});

async function newCase() {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-wholeread-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return store;
}

const markerOf = (store: CaseStore) => join(store.stateDir("c1"), DROP_INFLIGHT_MARKER);
const plasoCsv = (bytes: number): string => {
  const head = "datetime,timestamp_desc,source,message\n";
  const row = "2026-10-01T10:00:00Z,Content Modification Time,FILE,C:/x.txt\n";
  return head + row.repeat(Math.ceil((bytes - head.length) / row.length));
};

async function dropFile(store: CaseStore, name: string, bytes: number) {
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  await writeFile(join(dropDir, name), plasoCsv(bytes));
  return dropDir;
}

/** A server incarnation over the same case store, as a restart builds one. */
function incarnation(
  store: CaseStore,
  over: Partial<Pick<DropFolderDeps, "resolveImportKind" | "ingestStreamed" | "admitImport">>,
) {
  const refuse = (): never => {
    throw new Error("not expected to be reached");
  };
  const dropStatusStore = new DropStatusStore(store);
  const drops = createDropFolder({
    store,
    options: { dropStatusStore },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: () => {},
    dispatchNotify: () => {},
    resolveImportKind: over.resolveImportKind ?? (() => "plaso"),
    ingestStreamed:
      over.ingestStreamed ??
      vi.fn(async () => ({ storedName: "x", addedEvents: 1, addedIocs: 0, analyzed: true })),
    ingestDiskFile: refuse,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
    admitImport: over.admitImport,
    dropEarlyMarkBytes: EARLY_MARK_BYTES,
  });
  return { drops, dropStatusStore };
}

/** Two sweeps settle the file; the second dies after the whole-file read, before any import section. */
async function crashAfterRead(store: CaseStore, reached: string[], expectReached: number) {
  // An import that never returns and never takes the section stands in for the process dying
  // while it holds the file's whole text, before any import section was granted.
  const dying = incarnation(store, {
    ingestStreamed: vi.fn((_c: string, _k: string, _t: string, name: string) => {
      reached.push(name);
      return new Promise<never>(() => {});
    }),
  });
  await dying.drops.scanCaseDrops("c1");
  void dying.drops.scanCaseDrops("c1");
  await vi.waitFor(() => expect(reached.length).toBe(expectReached));
}

describe("drop folder whole-file read is crash-loop guarded (#2785)", () => {
  it("counts the start of a large under-cap file before it is read, and fails it after two", async () => {
    const store = await newCase();
    const dropDir = await dropFile(store, "big.csv", 2000);
    const reached: string[] = [];
    await crashAfterRead(store, reached, 1);
    // The marker was written although no import section was ever granted.
    expect(parseInFlight(await readFile(markerOf(store), "utf8"))).toMatchObject([
      { relpath: "big.csv", starts: 1 },
    ]);
    await crashAfterRead(store, reached, 2);

    const ingestStreamed = vi.fn(async () => ({
      storedName: "x",
      addedEvents: 1,
      addedIocs: 0,
      analyzed: true,
    }));
    const third = incarnation(store, { ingestStreamed });
    await third.drops.scanCaseDrops("c1");
    await third.drops.scanCaseDrops("c1");
    expect(ingestStreamed).not.toHaveBeenCalled();
    expect(await readdir(join(dropDir, "_failed"))).toContain("big.csv");
    const status = await third.dropStatusStore.load("c1");
    expect(status?.failed[0]?.reason).toMatch(/server stopped 2 times while importing this file/);
  });

  it("does not count a small file before its import section (a queued file is never blamed)", async () => {
    const store = await newCase();
    await dropFile(store, "small.csv", 100);
    const reached: string[] = [];
    await crashAfterRead(store, reached, 1);
    await expect(readFile(markerOf(store), "utf8")).rejects.toThrow();
  });

  it("refuses a large file to _failed when the import memory guard refuses, without importing it", async () => {
    const store = await newCase();
    const dropDir = await dropFile(store, "big.csv", 2000);
    const resolveImportKind = vi.fn(() => "plaso");
    const admitImport = vi.fn(async () => {
      throw new ImportMemoryRefusedError("Import refused to protect the server: test refusal.");
    });
    const run = incarnation(store, { resolveImportKind, admitImport });
    await run.drops.scanCaseDrops("c1");
    await run.drops.scanCaseDrops("c1");
    expect(admitImport).toHaveBeenCalledWith(
      "c1",
      expect.objectContaining({ incomingBytes: expect.any(Number) }),
    );
    expect(resolveImportKind).not.toHaveBeenCalled();
    expect(await readdir(join(dropDir, "_failed"))).toContain("big.csv");
    const status = await run.dropStatusStore.load("c1");
    expect(status?.failed[0]?.reason).toMatch(/Import refused to protect the server/);
  });

  it("releases the guard's reservation before the import, so the import's own admission is not doubled", async () => {
    const store = await newCase();
    const dropDir = await dropFile(store, "big.csv", 2000);
    const release = vi.fn();
    const admitImport = vi.fn(async () => release);
    const ingestStreamed = vi.fn(async () => {
      expect(release).toHaveBeenCalledTimes(1);
      return { storedName: "x", addedEvents: 1, addedIocs: 0, analyzed: true };
    });
    const run = incarnation(store, { admitImport, ingestStreamed });
    await run.drops.scanCaseDrops("c1");
    await run.drops.scanCaseDrops("c1");
    expect(ingestStreamed).toHaveBeenCalledTimes(1);
    expect(await readdir(join(dropDir, "_processed"))).toContain("big.csv");
  });
});

describe("createDropWholeReader (#2785)", () => {
  it("counts the attempt's start before the read begins", async () => {
    const order: string[] = [];
    const reader = createDropWholeReader({
      maxBytes: 1000,
      earlyMarkBytes: 10,
      read: async () => {
        order.push("read");
        return Buffer.from("hello");
      },
    });
    const text = await runImportAttempt(
      async () => void order.push("start"),
      () => reader("c1", "/nowhere", 50),
    );
    expect(text).toBe("hello");
    expect(order).toEqual(["start", "read"]);
  });

  it("asks the guard with the file's size and a wording that does not claim the file is saved", async () => {
    const admit = vi.fn(async (_caseId: string, _hint: ImportAdmissionHint) => () => {});
    const reader = createDropWholeReader({
      maxBytes: 1000,
      earlyMarkBytes: 10,
      admit,
      read: async () => Buffer.from("x"),
    });
    await reader("c1", "/nowhere", 50);
    const hint = admit.mock.calls[0]?.[1];
    expect(hint?.incomingBytes).toBe(50);
    expect(hint?.wording?.saved).toMatch(/_failed/);
  });

  it("skips the guard and the early start for a file under the threshold", async () => {
    const admit = vi.fn(async () => () => {});
    const onStart = vi.fn(async () => {});
    const reader = createDropWholeReader({
      maxBytes: 1000,
      earlyMarkBytes: 100,
      admit,
      read: async () => Buffer.from("x"),
    });
    await runImportAttempt(onStart, () => reader("c1", "/nowhere", 50));
    expect(admit).not.toHaveBeenCalled();
    expect(onStart).not.toHaveBeenCalled();
  });
});
