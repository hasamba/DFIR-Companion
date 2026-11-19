import { describe, it, expect, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";

// #2715: the drop log and status are written as each file finishes, so a server that stops
// mid-sweep still leaves a line and a status entry for every file already moved.

async function seed(ingest: (name: string) => Promise<unknown>) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-incremental-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  const dropStatusStore = new DropStatusStore(store);
  const refuse = (): never => {
    throw new Error("not expected to be called");
  };
  const drops = createDropFolder({
    store,
    options: { dropStatusStore },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: () => {},
    dispatchNotify: vi.fn(),
    resolveImportKind: () => "csv",
    ingestStreamed: (async (_c: string, _k: string, _t: string, name: string) => ingest(name)) as never,
    ingestMacLoginItemBinary: refuse,
    ingestDiskFile: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: vi.fn(async () => false),
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
  return { dropDir, dropStatusStore, drops };
}

const ok = { storedName: "s", addedEvents: 1, addedIocs: 0, analyzed: true };
const readLog = (dir: string) => readFile(join(dir, "drop-log.txt"), "utf8").catch(() => "");

describe("drop log and status are written per file (#2715)", () => {
  it("leaves lines and status for files 1 and 2 when the sweep never finishes file 3", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const { dropDir, dropStatusStore, drops } = await seed(async (name) => {
      if (name === "c.csv") await gate; // the "crash": file 3 never completes
      return ok;
    });
    for (const n of ["a.csv", "b.csv", "c.csv"]) await writeFile(join(dropDir, n), "h\n1\n", "utf8");
    await drops.scanCaseDrops("c1"); // settle pass
    const sweepDone = drops.scanCaseDrops("c1");

    await vi.waitFor(async () => {
      const log = await readLog(dropDir);
      expect(log).toMatch(/IMPORTED\s+a\.csv/);
      expect(log).toMatch(/IMPORTED\s+b\.csv/);
    });
    const mid = await dropStatusStore.load("c1");
    expect(mid.imported).toEqual(expect.arrayContaining(["a.csv", "b.csv"]));
    expect(mid.imported).not.toContain("c.csv");
    expect(await readLog(dropDir)).not.toMatch(/c\.csv/);

    release();
    await sweepDone;
    const end = await dropStatusStore.load("c1");
    expect(end.importedCount).toBe(3);
    const lines = (await readLog(dropDir)).trim().split("\n");
    expect(lines.filter((l) => /IMPORTED/.test(l))).toHaveLength(3); // no duplicates at the end
  });

  it("records a failure the moment it happens, with its reason", async () => {
    const { dropDir, dropStatusStore, drops } = await seed(async () => {
      throw new Error("boom");
    });
    await writeFile(join(dropDir, "a.csv"), "h\n1\n", "utf8");
    await drops.scanCaseDrops("c1");
    await drops.scanCaseDrops("c1");
    expect(await readLog(dropDir)).toMatch(/FAILED\s+a\.csv\s+— boom/);
    expect((await dropStatusStore.load("c1")).failed).toEqual([
      expect.objectContaining({ relpath: "a.csv", reason: "boom" }),
    ]);
  });
});
