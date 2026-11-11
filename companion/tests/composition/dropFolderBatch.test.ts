import { describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createDropFolder, dropDirOf, type DropFolderDeps } from "../../src/composition/dropFolder.js";
import type {
  DiskBatchIngest,
  DiskBatchResult,
  DropBatchRequest,
} from "../../src/composition/importIngestBatch.js";

// #2540 — the sweep side of a drop-folder batch: the ready files in relpath order, small gzip
// CloudTrail files handed to the batch, everything else on its own in place; and every file still
// gets its own move and its own drop-log line, and one Jobs-row tick.

const ct = (i: number): Buffer =>
  gzipSync(
    JSON.stringify({ Records: [{ eventVersion: "1.08", eventID: `id-${i}`, eventName: "ListUsers" }] }),
  );

function resolveImportKind(_name: string, text: string): string {
  if (text.startsWith('{"Records"')) return "aws";
  if (/sshd\[/.test(text)) return "syslog";
  return "unknown";
}

type BatchBehaviour = (req: DropBatchRequest) => DiskBatchResult;

async function seed(files: Record<string, Buffer | string>, behaviour: BatchBehaviour) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-batch-sweep-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  for (const [rel, body] of Object.entries(files)) {
    await mkdir(join(dropDir, rel, ".."), { recursive: true });
    await writeFile(join(dropDir, rel), body);
  }
  const order: string[] = [];
  const batches: DropBatchRequest[] = [];
  const dropBatch: DiskBatchIngest = {
    ingestDiskBatch: vi.fn(
      async (_caseId: string, req: DropBatchRequest, onFileDone: (r: string) => void) => {
        batches.push(req);
        const r = behaviour(req);
        for (const x of r.results) {
          order.push(`batch:${x.relpath}`);
          onFileDone(x.relpath);
        }
        return r;
      },
    ),
    recoverDropBatch: vi.fn(async () => {}),
  };
  const ingestDiskFile: DropFolderDeps["ingestDiskFile"] = vi.fn(
    async (_c: string, _k: string, _h: FileHandle, name: string) => {
      order.push(`solo:${name}`);
      return { storedName: `x_${name}`, addedEvents: 0, addedIocs: 0, disclosure: [] };
    },
  );
  const refuse = (): never => {
    throw new Error("not expected");
  };
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  const progress = vi.spyOn(jobManager, "progress");
  const dropStatusStore = new DropStatusStore(store);
  const drops = createDropFolder({
    store,
    options: { dropStatusStore, jobManager },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: () => {},
    dispatchNotify: () => {},
    resolveImportKind,
    ingestStreamed: vi.fn(async (_c: string, _k: string, _t: string, name: string) => {
      order.push(`solo:${name}`);
      return { storedName: name, addedEvents: 0, addedIocs: 0, analyzed: true };
    }),
    ingestDiskFile,
    dropBatch,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
  await drops.scanCaseDrops("c1");
  await drops.scanCaseDrops("c1");
  const log = await readFile(join(dropDir, "drop-log.txt"), "utf8").catch(() => "");
  const ls = (d: string) => readdir(join(dropDir, d)).catch(() => [] as string[]);
  return {
    order,
    batches,
    dropBatch,
    log,
    processed: await ls("_processed"),
    failed: await ls("_failed"),
    progress,
  };
}

const allOk: BatchBehaviour = (req) => ({
  results: req.files.map((f) => ({ relpath: f.relpath, ok: true })),
  rest: [],
});

describe("drop folder hands runs of small CloudTrail gzip files to a batch (#2540)", () => {
  it("imports in relpath order: a non-batchable file keeps its place between two batches", async () => {
    const s = await seed(
      {
        "a1.json.gz": ct(1),
        "a2.json.gz": ct(2),
        "b.log": "Oct 1 10:00:00 h sshd[1]: x\n",
        "c1.json.gz": ct(3),
        "c2.json.gz": ct(4),
      },
      allOk,
    );
    expect(s.order).toEqual([
      "batch:a1.json.gz",
      "batch:a2.json.gz",
      "solo:b.log",
      "batch:c1.json.gz",
      "batch:c2.json.gz",
    ]);
    expect(s.batches.map((b) => b.files.map((f) => f.relpath))).toEqual([
      ["a1.json.gz", "a2.json.gz"],
      ["c1.json.gz", "c2.json.gz"],
    ]);
    expect(s.processed.sort()).toEqual(["a1.json.gz", "a2.json.gz", "b.log", "c1.json.gz", "c2.json.gz"]);
    // One drop-log line per file, and one Jobs-row tick per file (files done / total).
    for (const f of ["a1.json.gz", "a2.json.gz", "b.log", "c1.json.gz", "c2.json.gz"])
      expect(s.log).toContain(f);
    expect(s.progress.mock.calls.map((c) => [c[1], c[2]])).toEqual([
      [1, 5],
      [2, 5],
      [3, 5],
      [4, 5],
      [5, 5],
    ]);
    expect(s.dropBatch.recoverDropBatch).toHaveBeenCalled();
  });

  it("a file the batch failed goes to _failed alone, with its own FAILED line", async () => {
    const s = await seed({ "a.json.gz": ct(1), "b.json.gz": ct(2), "c.json.gz": ct(3) }, (req) => ({
      results: req.files.map((f) =>
        f.relpath === "b.json.gz"
          ? { relpath: f.relpath, ok: false, reason: "unexpected end of file" }
          : { relpath: f.relpath, ok: true },
      ),
      rest: [],
    }));
    expect(s.processed.sort()).toEqual(["a.json.gz", "c.json.gz"]);
    expect(s.failed).toEqual(["b.json.gz"]);
    expect(s.log).toMatch(/FAILED.*b\.json\.gz.*unexpected end of file/);
  });

  it("a batch that could not start hands its files to today's one-by-one path", async () => {
    const s = await seed({ "a.json.gz": ct(1), "b.json.gz": ct(2) }, (req) => ({
      results: [],
      rest: req.files,
      stop: "fallback",
    }));
    expect(s.order).toEqual(["solo:a.json.gz", "solo:b.json.gz"]);
    expect(s.processed.sort()).toEqual(["a.json.gz", "b.json.gz"]);
  });

  it("a batch that throws mid-sweep leaves its files for the next sweep; earlier files keep their lines", async () => {
    let call = 0;
    const s = await seed(
      {
        "a1.json.gz": ct(1),
        "a2.json.gz": ct(2),
        "b.log": "Oct 1 10:00:00 h sshd[1]: x\n",
        "c1.json.gz": ct(3),
        "c2.json.gz": ct(4),
      },
      (req) => {
        if (++call === 2) throw new Error("case store unavailable");
        return allOk(req);
      },
    );
    expect(s.processed.sort()).toEqual(["a1.json.gz", "a2.json.gz", "b.log"]);
    for (const f of ["a1.json.gz", "a2.json.gz", "b.log"]) expect(s.log).toContain(f);
    expect(s.log).not.toContain("c1.json.gz");
    expect(s.failed).toEqual([]);
  });

  it("a file that no longer fits runs on its own in place, and the rest is batched again", async () => {
    let call = 0;
    const s = await seed(
      { "a.json.gz": ct(1), "b.json.gz": ct(2), "c.json.gz": ct(3), "d.json.gz": ct(4) },
      (req) => {
        call++;
        if (call > 1) return allOk(req);
        return { results: [{ relpath: "a.json.gz", ok: true }], rest: req.files.slice(1), stop: "mismatch" };
      },
    );
    expect(s.order).toEqual(["batch:a.json.gz", "solo:b.json.gz", "batch:c.json.gz", "batch:d.json.gz"]);
  });
});
