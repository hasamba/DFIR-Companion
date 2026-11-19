import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { chmod, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { createDropFolder, dropDirOf, type DropFolderDeps } from "../../src/composition/dropFolder.js";
import {
  DROP_CRASH_LIMIT,
  DROP_INFLIGHT_MARKER,
  createDropInFlight,
  parseInFlight,
} from "../../src/composition/dropInFlight.js";

// #2713 — a drop file whose import kills the server is retried once on the next start, and refused
// into _failed/ with a reason the second time, instead of crashing the server on every restart.
// A start counts only once the file's import holds the case's import section.

const CAP_BYTES = 2048;
const savedCap = process.env.DFIR_DROP_MAX_BYTES;
beforeAll(() => {
  process.env.DFIR_DROP_MAX_BYTES = String(CAP_BYTES);
});
afterAll(() => {
  if (savedCap === undefined) delete process.env.DFIR_DROP_MAX_BYTES;
  else process.env.DFIR_DROP_MAX_BYTES = savedCap;
});

async function newCase() {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-inflight-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return store;
}

const v1 = { size: 100, mtimeMs: 1000 };
const markerOf = (store: CaseStore) => join(store.stateDir("c1"), DROP_INFLIGHT_MARKER);

describe("createDropInFlight (#2713)", () => {
  it("refuses a version that started DROP_CRASH_LIMIT times without returning, and keeps refusing", async () => {
    const guard = createDropInFlight(await newCase());
    for (let i = 0; i < DROP_CRASH_LIMIT; i++) {
      expect(await guard.refusal("c1", "big.json", v1)).toBeNull();
      await guard.begin("c1", "big.json", v1);
    }
    const refused = await guard.refusal("c1", "big.json", v1);
    expect(refused).toMatch(/stopped 2 times while importing this file/);
    expect(refused).toMatch(/_failed/);
    // Read only: until `end` (the file left drop/), the refusal stands.
    expect(await guard.refusal("c1", "big.json", v1)).toBe(refused);
    await guard.end("c1", "big.json");
    expect(await guard.refusal("c1", "big.json", v1)).toBeNull();
  });

  it("forgets a file whose import returned, so a later crash starts the count again", async () => {
    const guard = createDropInFlight(await newCase());
    await guard.begin("c1", "big.json", v1);
    await guard.end("c1", "big.json");
    await guard.begin("c1", "big.json", v1);
    expect(await guard.refusal("c1", "big.json", v1)).toBeNull();
  });

  it("counts a changed file (new size or mtime) as a new file", async () => {
    const guard = createDropInFlight(await newCase());
    await guard.begin("c1", "big.json", v1);
    await guard.begin("c1", "big.json", v1);
    const changed = { size: 101, mtimeMs: 1000 };
    expect(await guard.refusal("c1", "big.json", changed)).toBeNull();
    await guard.begin("c1", "big.json", changed);
    expect(await guard.refusal("c1", "big.json", changed)).toBeNull();
  });

  it("keeps each file's count when several begin and end at once", async () => {
    const store = await newCase();
    const guard = createDropInFlight(store);
    await Promise.all(["a", "b", "c", "d"].map((n) => guard.begin("c1", n, v1)));
    await Promise.all(["a", "b"].map((n) => guard.end("c1", n)));
    const names = parseInFlight(await readFile(markerOf(store), "utf8")).map((e) => e.relpath);
    expect(names.sort()).toEqual(["c", "d"]);
  });

  it("reads a torn or foreign marker as empty rather than refusing anything", async () => {
    expect(parseInFlight("{not json")).toEqual([]);
    expect(parseInFlight(JSON.stringify({ entries: [{ relpath: 1, starts: 9 }] }))).toEqual([]);
    const store = await newCase();
    await mkdir(store.stateDir("c1"), { recursive: true });
    await writeFile(markerOf(store), "{torn", "utf8");
    expect(await createDropInFlight(store).refusal("c1", "big.json", v1)).toBeNull();
  });
});

/** A server incarnation: its own drop folder over the same case store, as a restart builds one. */
function incarnation(store: CaseStore, ingestDiskFile: DropFolderDeps["ingestDiskFile"]) {
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
    resolveImportKind: (_n: string, text: string) => (text.startsWith('{"Records"') ? "aws" : "unknown"),
    ingestStreamed: vi.fn(async () => ({ storedName: "x", addedEvents: 0, addedIocs: 0, analyzed: true })),
    ingestDiskFile,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
  return { drops, dropStatusStore };
}

const records = (n: number): string =>
  JSON.stringify({
    Records: Array.from({ length: n }, (_, i) => ({
      eventTime: "2026-10-01T10:00:00Z",
      eventSource: "iam.amazonaws.com",
      eventName: "ListUsers",
      eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
    })),
  });

async function dropFiles(store: CaseStore, names: string[]) {
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  for (const n of names) await writeFile(join(dropDir, n), records(60));
  return dropDir;
}

/** An import that takes the case's import section, as the real ingest seams do, and never returns. */
function dyingImport(lock: ImportLock, started: string[]): DropFolderDeps["ingestDiskFile"] {
  return vi.fn((caseId: string, _kind: string, _h, name: string) =>
    lock.runSized(caseId, { incomingBytes: 1 }, () => {
      started.push(name);
      return new Promise<never>(() => {}); // the process died here
    }),
  );
}

/** Two sweeps settle the files; the second one's import never returns. */
async function crashOnce(store: CaseStore, started: string[], expectStarted: number) {
  const { drops } = incarnation(store, dyingImport(new ImportLock(), started));
  await drops.scanCaseDrops("c1");
  void drops.scanCaseDrops("c1");
  await vi.waitFor(() => expect(started.length).toBe(expectStarted));
}

describe("drop folder crash-loop guard (#2713)", () => {
  it("retries a file once after a crash, and moves it to _failed with a reason after the second", async () => {
    const store = await newCase();
    const dropDir = await dropFiles(store, ["big.json"]);
    const started: string[] = [];
    await crashOnce(store, started, 1);
    await crashOnce(store, started, 2);

    const third = incarnation(store, dyingImport(new ImportLock(), started));
    await third.drops.scanCaseDrops("c1");
    await third.drops.scanCaseDrops("c1");
    expect(started).toEqual(["big.json", "big.json"]); // never imported a third time
    expect(await readdir(join(dropDir, "_failed"))).toContain("big.json");
    expect(await readdir(dropDir)).not.toContain("big.json");
    const status = await third.dropStatusStore.load("c1");
    expect(status?.failed[0]?.reason).toMatch(/server stopped 2 times while importing this file/);
    expect(await readFile(join(dropDir, "drop-log.txt"), "utf8")).toMatch(
      /big\.json.*server stopped 2 times/,
    );
    await expect(readFile(markerOf(store), "utf8")).rejects.toThrow(); // forgotten once it moved
  });

  it("never blames a file that was still queued for the import section when the server died", async () => {
    const store = await newCase();
    const dropDir = await dropFiles(store, ["a.json", "b.json"]);
    const started: string[] = [];
    // a.json holds the section and dies in it; b.json waits behind it both times.
    await crashOnce(store, started, 1);
    await crashOnce(store, started, 2);
    expect(started).toEqual(["a.json", "a.json"]);
    const entries = parseInFlight(await readFile(markerOf(store), "utf8"));
    expect(entries.map((e) => e.relpath)).toEqual(["a.json"]);

    // Third start: a.json is refused, b.json finally imports.
    const imported: string[] = [];
    const ok: DropFolderDeps["ingestDiskFile"] = vi.fn(async (c: string, _k: string, _h, name: string) =>
      new ImportLock().runSized(c, { incomingBytes: 1 }, async () => {
        imported.push(name);
        return { storedName: `0001_${name}`, addedEvents: 1, addedIocs: 0, disclosure: [] };
      }),
    );
    const third = incarnation(store, ok);
    await third.drops.scanCaseDrops("c1");
    await third.drops.scanCaseDrops("c1");
    expect(imported).toEqual(["b.json"]);
    expect(await readdir(join(dropDir, "_failed"))).toEqual(["a.json"]);
    expect(await readdir(join(dropDir, "_processed"))).toContain("b.json");
  });

  it("keeps refusing a refused file whose move to _failed fails, instead of importing it again", async () => {
    const store = await newCase();
    const dropDir = await dropFiles(store, ["big.json"]);
    const started: string[] = [];
    await crashOnce(store, started, 1);
    await crashOnce(store, started, 2);
    await mkdir(join(dropDir, "_failed"), { recursive: true });
    await chmod(join(dropDir, "_failed"), 0o500); // the move cannot land
    try {
      const third = incarnation(store, dyingImport(new ImportLock(), started));
      await third.drops.scanCaseDrops("c1");
      await third.drops.scanCaseDrops("c1");
      expect(started).toHaveLength(2);
      expect(parseInFlight(await readFile(markerOf(store), "utf8"))[0]?.starts).toBe(2);
    } finally {
      await chmod(join(dropDir, "_failed"), 0o700);
    }
  });
});
