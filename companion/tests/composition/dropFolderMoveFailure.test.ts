import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, access, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import type { ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import { createDropFolder, dropDirOf, type DropFolderDeps } from "../../src/composition/dropFolder.js";

// #2281. THE MOVE IS THE DEDUP: once a dropped file is imported it is moved to _processed/ (or
// _failed/), and the scanner never sees it again. When that move failed — a locked file on Windows,
// a read-only _processed/, the #2270 "changed size while being moved" refusal — the error was only
// logged and the sweep forgot the file, so the next stable poll imported it AGAIN, and every two
// polls after that: duplicate forensic-timeline events for per-import-id importers, duplicate
// evidence copies, duplicate AI runs, all without a word to the analyst.

const hooks = vi.hoisted(() => ({ failRename: false }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    rename: (async (...args: Parameters<typeof actual.rename>) => {
      // Only the drop folder's own move fails; atomicWrite (drop-status.json) renames too.
      if (hooks.failRename && /[\\/]_(processed|failed)[\\/]/.test(String(args[1]))) {
        throw Object.assign(new Error("EPERM: operation not permitted, rename"), { code: "EPERM" });
      }
      return actual.rename(...args);
    }) as typeof actual.rename,
  };
});

afterEach(() => {
  hooks.failRename = false;
});

async function seed(kind = "csv", overrides: Partial<DropFolderDeps> = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-move-failure-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  const dropStatusStore = new DropStatusStore(store);
  const ingestStreamed = vi.fn(async () => ({
    storedName: "s",
    addedEvents: 1,
    addedIocs: 0,
    analyzed: true,
  }));
  const dispatchNotify = vi.fn();
  const runDropToolAndIngest = vi.fn(async () => false);
  const refuse = (): never => {
    throw new Error("not expected to be called");
  };
  const drops = createDropFolder({
    store,
    options: { dropStatusStore },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: () => {},
    dispatchNotify,
    resolveImportKind: () => kind,
    ingestStreamed,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
    ...overrides,
  });
  return { store, dropDir, dropStatusStore, drops, ingestStreamed, dispatchNotify, runDropToolAndIngest };
}

async function sweep(drops: { scanCaseDrops(id: string): Promise<void> }, times: number) {
  for (let i = 0; i < times; i++) await drops.scanCaseDrops("c1");
}

const readLog = (dropDir: string) => readFile(join(dropDir, "drop-log.txt"), "utf8").catch(() => "");

describe("a dropped file whose move failed is not imported again (#2281)", () => {
  it("imports an unmovable file once, however many sweeps follow", async () => {
    const { dropDir, drops, ingestStreamed } = await seed();
    await writeFile(join(dropDir, "a.csv"), "h\n1\n", "utf8");
    hooks.failRename = true;

    await sweep(drops, 6);

    expect(ingestStreamed).toHaveBeenCalledTimes(1);
    expect((await readFile(join(dropDir, "a.csv"), "utf8")).length).toBeGreaterThan(0);
  });

  it("names the move failure in drop-log.txt and the drop-status warnings", async () => {
    const { dropDir, drops, dropStatusStore } = await seed();
    await writeFile(join(dropDir, "a.csv"), "h\n1\n", "utf8");
    hooks.failRename = true;

    await sweep(drops, 2);

    const log = await readLog(dropDir);
    expect(log).toMatch(/IMPORTED.*a\.csv.*could not be moved to _processed\/.*EPERM/);
    const status = await dropStatusStore.load("c1");
    expect(status.warnings).toEqual([
      expect.objectContaining({ relpath: "a.csv", reason: expect.stringMatching(/EPERM.*left in drop\//) }),
    ]);
  });

  it("finishes the move on a later sweep once the lock is gone, without importing again", async () => {
    const { dropDir, drops, ingestStreamed } = await seed();
    await writeFile(join(dropDir, "a.csv"), "h\n1\n", "utf8");
    hooks.failRename = true;
    await sweep(drops, 3);

    hooks.failRename = false;
    await sweep(drops, 2);

    expect(ingestStreamed).toHaveBeenCalledTimes(1);
    await expect(access(join(dropDir, "a.csv"))).rejects.toThrow();
    await access(join(dropDir, "_processed", "a.csv"));
  });

  it("treats changed content as new evidence and imports it again", async () => {
    const { dropDir, drops, ingestStreamed } = await seed();
    await writeFile(join(dropDir, "a.csv"), "h\n1\n", "utf8");
    hooks.failRename = true;
    await sweep(drops, 3);
    expect(ingestStreamed).toHaveBeenCalledTimes(1);

    await appendFile(join(dropDir, "a.csv"), "2\n", "utf8");
    await sweep(drops, 3);

    expect(ingestStreamed).toHaveBeenCalledTimes(2);
  });

  it("fails an unrecognised, unmovable file once: one FAILED line, one notification", async () => {
    const { dropDir, drops, ingestStreamed, dispatchNotify, dropStatusStore } = await seed("unknown");
    await writeFile(join(dropDir, "junk.txt"), "not an artifact", "utf8");
    hooks.failRename = true;

    await sweep(drops, 6);

    expect(ingestStreamed).not.toHaveBeenCalled();
    expect(dispatchNotify).toHaveBeenCalledTimes(1);
    const failedLines = (await readLog(dropDir)).split("\n").filter((l) => l.includes("FAILED"));
    expect(failedLines).toHaveLength(1);
    expect(failedLines[0]).toMatch(/could not be moved to _failed\/.*EPERM/);
    const status = await dropStatusStore.load("c1");
    expect(status.failed[0]?.reason).toMatch(/_failed\/.*EPERM/);
  });

  it("does not re-run an auto-run tool on a file whose run-pending move failed", async () => {
    const tool = { autoRun: true, transport: "http" } as unknown as ToolConfig;
    const { dropDir, drops, runDropToolAndIngest } = await seed("csv", {
      liveToolConfigs: () => new Map([["hayabusa", tool]]),
      resolveToolForExt: () => "hayabusa",
      rawExtClaimed: (ext) => ext === ".evtx",
    });
    await writeFile(join(dropDir, "Security.evtx"), Buffer.from([0, 1, 2, 3, 0, 0, 0xff]));
    // POST /drop/run-pending ran the tool, then its move failed — the route calls moveDropFile.
    hooks.failRename = true;
    await expect(drops.moveDropFile(dropDir, "Security.evtx", true)).rejects.toThrow(/EPERM/);

    await sweep(drops, 4);

    expect(runDropToolAndIngest).not.toHaveBeenCalled();
  });
});
