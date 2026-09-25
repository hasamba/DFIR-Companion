// #1629: a drop-folder CSV/log import names its model on the sweep's Background Jobs row, and its
// model calls carry the sweep's signal so the #1601 served-model stamp reaches the row. The model is
// named by ingestStreamed at the same point as its own AI-off gate — one gate, one decision — so a
// row never names a model that did not run, and a model that ran is never left unnamed.
import { describe, it, expect, vi } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { detectImportWithCustom } from "../../src/analysis/importDetect.js";
import { createDropFolder, dropDirOf, type DropFolderDeps } from "../../src/composition/dropFolder.js";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import type { ImportBase } from "../../src/routes/context.js";

const SONNET = { model: "sonnet", provider: "claude-code" };
const CSV = "user,action,host\nalice,login,ws01.example.com\nbob,logout,ws02.example.com\n";
const THOR = JSON.stringify({
  level: "Warning",
  module: "Filescan",
  message: "Suspicious file",
  time: "2026-05-02T10:00:00Z",
  file: "C:\\Temp\\a.exe",
});

async function caseStore(): Promise<CaseStore> {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-1629-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return store;
}

/** A real ingestStreamed over a pipeline stub that records the base each import got. */
function ingest(store: CaseStore, aiOn: () => boolean) {
  const bases: Array<{ kind: string; base: ImportBase }> = [];
  const record = (kind: string) => async (_c: string, _t: string, base: ImportBase) => {
    bases.push({ kind, base });
    return undefined;
  };
  const deps = {
    store,
    options: { pipeline: { analyzeCsv: record("csv"), importThor: record("thor") } },
    runStateExclusive: async (_c: string, fn: () => Promise<unknown>) => fn(),
    importLock: new ImportLock(),
    recordImporterRun: () => {},
    redactErr: (err: unknown) => String(err),
    autoTagImported: async () => {},
    getControl: async () => ({ enabled: aiOn() }),
    applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
    applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
    applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
    resynthesizeInBackground: () => {},
  } as unknown as ImportIngestDeps;
  return { ...createImportIngest(deps), bases };
}

describe("ingestStreamed modelCall (#1629)", () => {
  it("names the model and passes the signal for an AI kind, after the AI-off gate", async () => {
    const { ingestStreamed, bases } = ingest(await caseStore(), () => true);
    const signal = new AbortController().signal;
    const beforeModelRun = vi.fn();
    const r = await ingestStreamed("c1", "csv", CSV, "a.csv", undefined, undefined, undefined, {
      signal,
      beforeModelRun,
    });
    expect(r.analyzed).toBe(true);
    expect(beforeModelRun).toHaveBeenCalledOnce();
    expect(beforeModelRun).toHaveBeenCalledWith("csv");
    expect(bases[0].base.signal).toBe(signal);
  });

  it("names nothing and runs nothing when AI is off", async () => {
    const { ingestStreamed, bases } = ingest(await caseStore(), () => false);
    const beforeModelRun = vi.fn();
    const r = await ingestStreamed("c1", "csv", CSV, "a.csv", undefined, undefined, undefined, {
      signal: new AbortController().signal,
      beforeModelRun,
    });
    expect(r.analyzed).toBe(false);
    expect(beforeModelRun).not.toHaveBeenCalled();
    expect(bases).toHaveLength(0);
  });

  it("names nothing and passes no signal for a deterministic kind", async () => {
    const { ingestStreamed, bases } = ingest(await caseStore(), () => true);
    const beforeModelRun = vi.fn();
    await ingestStreamed("c1", "thor", THOR, "thor.json", undefined, undefined, undefined, {
      signal: new AbortController().signal,
      beforeModelRun,
    });
    expect(beforeModelRun).not.toHaveBeenCalled();
    expect(bases[0].base.signal).toBeUndefined();
  });
});

async function sweep(files: Record<string, string>, aiOn: boolean) {
  const store = await caseStore();
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  for (const [name, text] of Object.entries(files)) await writeFile(join(dropDir, name), text, "utf8");
  const jobManager = new JobManager();
  jobManager.useModelResolver((input) =>
    input.kind === "import" && input.parameters?.kind === "csv" ? SONNET : undefined,
  );
  const { ingestStreamed, bases } = ingest(store, () => aiOn);
  const refuse = (): never => {
    throw new Error("not expected");
  };
  const drops = createDropFolder({
    store,
    options: { jobManager },
    hasAiProvider: () => true,
    getControl: async () => ({ enabled: aiOn }),
    recordImportFailure: refuse,
    dispatchNotify: () => {},
    resolveImportKind: (filename: string, text: string) =>
      detectImportWithCustom(filename, text, new Map(), "builtin-first"),
    ingestStreamed,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  } as unknown as DropFolderDeps);
  // The first sweep only lists; a file is imported once its size is stable across two sweeps.
  await drops.scanCaseDrops("c1");
  await drops.scanCaseDrops("c1");
  return { job: jobManager.list("c1")[0], bases };
}

describe("drop-folder sweep job row (#1629)", () => {
  it("names the text model when the sweep ran a CSV, and the call carried the job's signal", async () => {
    const { job, bases } = await sweep({ "users.csv": CSV }, true);
    expect(job).toMatchObject({ kind: "import", model: "sonnet", modelProvider: "claude-code" });
    expect(job.cancellable).toBe(false);
    expect(bases[0].kind).toBe("csv");
    expect(bases[0].base.signal).toBeInstanceOf(AbortSignal);
  });

  it("names no model when AI is off", async () => {
    const { job, bases } = await sweep({ "users.csv": CSV }, false);
    expect(job.model).toBeUndefined();
    expect(bases).toHaveLength(0);
  });

  it("names no model for a sweep of deterministic files", async () => {
    const { job, bases } = await sweep({ "thor.json": THOR }, true);
    expect(job.model).toBeUndefined();
    expect(bases[0].base.signal).toBeUndefined();
  });
});
