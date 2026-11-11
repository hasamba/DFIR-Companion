import { afterAll, describe, expect, it, vi } from "vitest";
import { mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import { CloudWeaknessStore } from "../../src/analysis/cloudWeaknessStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { ImportUndoStore, applyUndo, runUndoStep } from "../../src/analysis/importUndo.js";
import { buildRuntimePipeline } from "../../src/composition/aiProviders.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { createCaseAppliers } from "../../src/composition/caseAppliers.js";
import { importTagger } from "../../src/routes/routeSettleDeps.js";
import { createDiskIngest } from "../../src/composition/importIngestDisk.js";
import { createDiskBatchIngest, type BatchFile } from "../../src/composition/importIngestBatch.js";
import { DROP_BATCH_MARKER } from "../../src/composition/dropBatchMarker.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ImporterRegistry } from "../../src/analysis/importerStore.js";
import { sans504Records } from "../analysis/fixtures/sans504Lab.js";

// #2540 — a drop-folder batch of small CloudTrail files leaves the case as importing the same files
// one at a time does: forensic timeline, IOCs, super-timeline rows and tags, the dedup ledger,
// coverage and weaknesses. What it shares is the tail: one settle, one note for the files that added
// nothing, one import-meta record, one undo step naming the file count, one run record.

const RULES = `cloudtrail-iam-read:
  any:
    - { field: description, contains: ['ListUsers'] }
  tags: ['iam-recon']
`;

const roots: string[] = [];
afterAll(async () => {
  await Promise.all(roots.map((r) => rm(r, { recursive: true, force: true })));
});

/** The lab's records as small `.json.gz` files in time order, plus an empty one and a corrupt one. */
function labFiles(): { name: string; bytes: Buffer }[] {
  const recs = sans504Records();
  const files: { name: string; bytes: Buffer }[] = [];
  for (let i = 0; i < recs.length; i += 4) {
    const n = String(files.length).padStart(3, "0");
    files.push({
      name: `ct_${n}.json.gz`,
      bytes: gzipSync(JSON.stringify({ Records: recs.slice(i, i + 4) })),
    });
  }
  // A record a later file repeats (S3 delivers duplicates): the ledger must skip it the same way.
  files.push({ name: "ct_900_dup.json.gz", bytes: gzipSync(JSON.stringify({ Records: recs.slice(0, 2) })) });
  files.push({ name: "ct_901_empty.json.gz", bytes: gzipSync(JSON.stringify({ Records: [] })) });
  const corrupt = gzipSync(JSON.stringify({ Records: recs.slice(4, 8) }));
  files.splice(3, 0, { name: "ct_002b_corrupt.json.gz", bytes: corrupt.subarray(0, corrupt.length - 9) });
  return files;
}

function resolveImportKind(_name: string, text: string): string {
  return text.includes('"Records"') ? "aws" : "unknown";
}

async function harness(opts: { lock?: ImportLock } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-batch-"));
  roots.push(root);
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const lock = new StateLock();
  const runStateExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> =>
    lock.runExclusive(caseId, fn);
  await writeFile(join(root, "rules.yaml"), RULES);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    stateLock: lock,
    incrementalMerge: true,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const options = {
    pipeline,
    stateStore,
    superTimelineStore: new SuperTimelineStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
    tagsStore: new TagsStore(store),
    taggerStore: new TaggerStore(join(root, "user.yaml"), [join(root, "rules.yaml")]),
    cloudRecordStore: new CloudRecordStore(store),
    importMetaStore: new ImportMetaStore(store),
    analysisRunStore: new AnalysisRunStore(store, { appVersion: "test" }),
    importUndoStore: new ImportUndoStore(store),
  } as unknown as AppOptions;
  const demote = createImportDemote({ options, runStateExclusive });
  const autoTagImported = importTagger({ options, store, runStateExclusive, logLine: () => {} });
  const importLock = opts.lock ?? new ImportLock();
  const appliers = createCaseAppliers({ store, options, runStateExclusive, nsrlDb: () => undefined });
  const pushImportCheckpoint = vi.fn(appliers.pushImportCheckpoint);
  const disk = {
    store,
    options,
    importLock,
    runStateExclusive,
    demoteForensic: demote.demoteForensic,
    settleDeps: { options, runStateExclusive, autoTagImported, demote },
    afterImport: vi.fn(async () => {}),
  };
  const ingestDiskFile = createDiskIngest(disk);
  const batch = createDiskBatchIngest({
    ...disk,
    resolveImportKind,
    importerRegistry: () => ({ importers: new Map() }) as unknown as ImporterRegistry,
    pushImportCheckpoint,
  });
  const inbox = join(root, "inbox");
  await store.mkdirInCase(store.caseDir("c1"));
  await rm(inbox, { recursive: true, force: true });
  const { mkdir } = await import("node:fs/promises");
  await mkdir(inbox, { recursive: true });
  const files: BatchFile[] = [];
  for (const f of labFiles()) {
    await writeFile(join(inbox, f.name), f.bytes);
    files.push({ relpath: f.name, fullPath: join(inbox, f.name) });
  }
  return {
    root,
    store,
    stateStore,
    options,
    ingestDiskFile,
    batch,
    files,
    disk,
    pushImportCheckpoint,
    importLock,
    runStateExclusive,
  };
}

type Harness = Awaited<ReturnType<typeof harness>>;

async function oneAtATime(h: Harness): Promise<string[]> {
  const failed: string[] = [];
  for (const f of h.files) {
    const handle = await open(f.fullPath, "r");
    try {
      await h.ingestDiskFile("c1", "aws", handle, f.relpath);
    } catch {
      failed.push(f.relpath);
    } finally {
      await handle.close();
    }
  }
  return failed;
}

async function snapshot(h: Harness) {
  const state = await h.stateStore.load("c1");
  const opts = h.options as unknown as {
    superTimelineStore: SuperTimelineStore;
    tagsStore: TagsStore;
  };
  const supers: string[] = [];
  for await (const rows of opts.superTimelineStore.eventBatches("c1"))
    for (const e of rows) supers.push(JSON.stringify([e.id, e.severity, e.description]));
  const tags = (await opts.tagsStore.load("c1")).map((t) => `${t.targetId}:${t.label}`).sort();
  const coverage = (await new CloudCoverageStore(h.store).load("c1")).map((r) => {
    const { importedAt: _i, uploadFirstSeenAt: _u, ...rest } = r;
    return rest;
  });
  return {
    forensic: state.forensicTimeline.map((e) => [
      e.id,
      e.timestamp,
      e.severity,
      e.description,
      e.sources,
      e.mitreTechniques,
      e.asset,
      e.sourceScreenshots,
    ]),
    iocs: state.iocs.map((i) => [i.type, i.value, [...(i.extractedFrom ?? [])].sort()]).sort(),
    supers: supers.sort(),
    tags,
    coverage,
    weaknesses: await new CloudWeaknessStore(h.store).load("c1"),
    principalNames: state.principalNames ?? null,
    notes: state.timeline.map((n) => n.description),
  };
}

describe("drop-folder batch ≡ one at a time (#2540)", () => {
  it("leaves the same forensic timeline, IOCs, super rows, tags, coverage and weaknesses", async () => {
    const one = await harness();
    const failedOne = await oneAtATime(one);
    const batched = await harness();
    const done: string[] = [];
    const r = await batched.batch.ingestDiskBatch(
      "c1",
      { kind: "aws", assetHost: "", files: batched.files, bytes: 1 },
      (relpath) => done.push(relpath),
    );
    expect(r.rest).toEqual([]);
    expect(r.results.map((x) => x.relpath)).toEqual(batched.files.map((f) => f.relpath));
    expect(done).toEqual(batched.files.map((f) => f.relpath)); // progress: one tick per file
    // The corrupt file fails alone, as it does one at a time.
    expect(failedOne).toEqual(["ct_002b_corrupt.json.gz"]);
    expect(r.results.filter((x) => !x.ok).map((x) => x.relpath)).toEqual(failedOne);

    const a = await snapshot(one);
    const b = await snapshot(batched);
    expect(a.forensic.length).toBeGreaterThan(0);
    expect(b.forensic).toEqual(a.forensic);
    expect(b.iocs).toEqual(a.iocs);
    expect(b.supers).toEqual(a.supers);
    expect(a.tags.length).toBeGreaterThan(0); // the tag rule matched something
    expect(b.tags).toEqual(a.tags);
    expect(b.coverage).toEqual(a.coverage);
    expect(a.weaknesses?.accounts.length).toBeGreaterThan(0);
    expect(b.weaknesses).toEqual(a.weaknesses);
    expect(b.principalNames).toEqual(a.principalNames);

    // Notes: a file that added rows keeps its own; the files that added nothing share one.
    const emptyOne = a.notes.filter((n) => /no events from/.test(n));
    expect(emptyOne.length).toBeGreaterThan(1);
    const batchNotes = b.notes.filter((n) => /drop batch: \d+ file\(s\) added nothing/.test(n));
    expect(batchNotes).toHaveLength(1);
    expect(batchNotes[0]).toContain(`${emptyOne.length} file(s)`);
    expect(b.notes.filter((n) => /no events from/.test(n))).toEqual([]);
    expect(b.notes.filter((n) => !/drop batch/.test(n))).toEqual(
      a.notes.filter((n) => !/no events from/.test(n)),
    );

    // Evidence: one stored copy, custody record and imports.jsonl line per file, as one at a time.
    const lines = async (h: Harness, f: string) =>
      (await readFile(join(h.store.caseDir("c1"), "metadata", f), "utf8")).trim().split("\n").length;
    expect(await lines(batched, "imports.jsonl")).toBe(await lines(one, "imports.jsonl"));
    expect(batched.disk.afterImport).toHaveBeenCalledTimes(1);
  });

  it("records one undo step naming the count, and Undo takes the whole batch back", async () => {
    const h = await harness();
    await h.batch.ingestDiskBatch("c1", { kind: "aws", assetHost: "", files: h.files, bytes: 1 }, () => {});
    expect(h.pushImportCheckpoint).toHaveBeenCalledTimes(1);
    const [, , label, , , ledgerLabels] = h.pushImportCheckpoint.mock.calls[0];
    expect(label).toBe(`AWS CloudTrail drop batch (${h.files.length - 1} files)`); // the corrupt one failed
    expect(ledgerLabels).toHaveLength(h.files.length - 1); // every imported file, not the corrupt one
    const opts = h.options as unknown as {
      importUndoStore: ImportUndoStore;
      cloudRecordStore: CloudRecordStore;
    };
    await runUndoStep(
      {
        undoStore: opts.importUndoStore,
        stateStore: h.stateStore,
        importLock: h.importLock,
        runStateExclusive: h.runStateExclusive,
        cloudRecords: opts.cloudRecordStore,
      },
      "c1",
      applyUndo,
    );
    const after = await h.stateStore.load("c1");
    expect(after.forensicTimeline).toEqual([]);
    expect(after.iocs).toEqual([]);
    // The ledger forgot every file's records: importing the same files again adds them back.
    const again = h.files.filter((f) => !f.relpath.includes("corrupt"));
    await h.batch.ingestDiskBatch("c1", { kind: "aws", assetHost: "", files: again, bytes: 1 }, () => {});
    expect((await h.stateStore.load("c1")).forensicTimeline.length).toBeGreaterThan(0);
  });

  it("Undo of a batch on a non-empty case restores the rows and IOC links the batch changed", async () => {
    const h = await harness();
    const opts = h.options as unknown as {
      importUndoStore: ImportUndoStore;
      cloudRecordStore: CloudRecordStore;
    };
    const good = h.files.filter((f) => !f.relpath.includes("corrupt"));
    const third = Math.floor(good.length / 3);
    await h.batch.ingestDiskBatch(
      "c1",
      { kind: "aws", assetHost: "", files: good.slice(0, third), bytes: 1 },
      () => {},
    );
    const before = await snapshot(h);
    expect(before.forensic.length).toBeGreaterThan(0);
    await h.batch.ingestDiskBatch(
      "c1",
      { kind: "aws", assetHost: "", files: good.slice(third), bytes: 1 },
      () => {},
    );
    const during = await snapshot(h);
    // The second batch changed what the case already held (rows added, IOC links extended).
    expect(during.forensic.length).toBeGreaterThan(before.forensic.length);
    await runUndoStep(
      {
        undoStore: opts.importUndoStore,
        stateStore: h.stateStore,
        importLock: h.importLock,
        runStateExclusive: h.runStateExclusive,
        cloudRecords: opts.cloudRecordStore,
      },
      "c1",
      applyUndo,
    );
    const after = await snapshot(h);
    expect(after.forensic).toEqual(before.forensic);
    expect(after.iocs).toEqual(before.iocs);
    expect(after.notes).toEqual(before.notes);
    expect(after.principalNames).toEqual(before.principalNames);
  });

  it("records one analysis run listing every imported file with its hash", async () => {
    const h = await harness();
    await h.batch.ingestDiskBatch("c1", { kind: "aws", assetHost: "", files: h.files, bytes: 1 }, () => {});
    const runs = await (h.options as unknown as { analysisRunStore: AnalysisRunStore }).analysisRunStore.list(
      "c1",
    );
    const imports = runs.filter((r) => r.kind === "import");
    expect(imports).toHaveLength(1);
    const run = imports[0];
    expect(run.input.artifacts).toHaveLength(h.files.length - 1);
    expect(
      run.input.artifacts.every((x) => /^imports\/\d{4}_ct_/.test(x.path) && x.sha256.length === 64),
    ).toBe(true);
    expect(run.configuration?.parameters ?? {}).toMatchObject({ dropBatchFiles: h.files.length - 1 });
    // The tagger ran once for the batch, not once per file.
    expect(runs.filter((r) => r.kind === "deterministic")).toHaveLength(1);
    // The crash marker is gone once the tail finished.
    await expect(readFile(join(h.store.stateDir("c1"), DROP_BATCH_MARKER), "utf8")).rejects.toThrow();
  });

  it("hands every file back, untouched, when the batch cannot start", async () => {
    const lock = new ImportLock({
      admit: async () => {
        throw new Error("import memory guard: not enough memory");
      },
    });
    const h = await harness({ lock });
    const r = await h.batch.ingestDiskBatch(
      "c1",
      { kind: "aws", assetHost: "", files: h.files, bytes: 1 },
      () => {},
    );
    expect(r).toMatchObject({ results: [], stop: "fallback" });
    expect(r.rest).toEqual(h.files);
    await expect(
      readFile(join(h.store.caseDir("c1"), "metadata", "imports.jsonl"), "utf8"),
    ).rejects.toThrow();
  });

  it("stops batching when the super-timeline is within one import budget of its cap", async () => {
    const saved = process.env.DFIR_SUPERTIMELINE_MAX;
    process.env.DFIR_SUPERTIMELINE_MAX = "49999"; // under one per-import budget (50,000): no room at all
    try {
      const h = await harness();
      const r = await h.batch.ingestDiskBatch(
        "c1",
        { kind: "aws", assetHost: "", files: h.files, bytes: 1 },
        () => {},
      );
      expect(r.stop).toBe("capacity");
      expect(r.results).toEqual([]);
      expect(r.rest).toEqual(h.files);
    } finally {
      if (saved === undefined) delete process.env.DFIR_SUPERTIMELINE_MAX;
      else process.env.DFIR_SUPERTIMELINE_MAX = saved;
    }
  });

  it("ends the batch at a file that no longer fits, handing it and the rest back in order", async () => {
    const h = await harness();
    await writeFile(h.files[2].fullPath, "not gzip any more");
    const r = await h.batch.ingestDiskBatch(
      "c1",
      { kind: "aws", assetHost: "", files: h.files, bytes: 1 },
      () => {},
    );
    expect(r.stop).toBe("mismatch");
    expect(r.results.map((x) => x.relpath)).toEqual(h.files.slice(0, 2).map((f) => f.relpath));
    expect(r.rest).toEqual(h.files.slice(2));
  });

  it("settles the rows of a batch a crash interrupted", async () => {
    const h = await harness();
    // Simulate the crash: one file merged inside a section, the marker left behind, no settle.
    const { createDropBatchMarker } = await import("../../src/composition/dropBatchMarker.js");
    const marker = createDropBatchMarker(h.store);
    const handle = await open(h.files[1].fullPath, "r");
    const pipeline = (h.options as unknown as { pipeline: ReturnType<typeof buildRuntimePipeline> }).pipeline;
    const stored = "0001_ct_001.json.gz";
    await h.store.saveImportFromHandle("c1", stored, handle);
    await handle.close();
    await marker.add("c1", stored);
    await pipeline.importCloudFile("c1", "aws", join(h.store.importsDir("c1"), stored), {
      label: stored,
      idPrefix: "1",
      importedAt: new Date().toISOString(),
    });
    const superStore = (h.options as unknown as { superTimelineStore: SuperTimelineStore })
      .superTimelineStore;
    const superIds = async (): Promise<Set<string>> => {
      const ids = new Set<string>();
      for await (const rows of superStore.eventBatches("c1")) for (const e of rows) ids.add(e.id);
      return ids;
    };
    const forensic = (await h.stateStore.load("c1")).forensicTimeline.filter((e) =>
      e.sourceScreenshots.includes(stored),
    );
    expect(forensic.length).toBeGreaterThan(0);
    // Unsettled: the forensic rows were never dual-written into the super-timeline.
    const beforeIds = await superIds();
    expect(forensic.some((e) => !beforeIds.has(e.id))).toBe(true);
    await h.batch.recoverDropBatch("c1");
    const afterIds = await superIds();
    expect(forensic.every((e) => afterIds.has(e.id))).toBe(true);
    await expect(marker.read("c1")).resolves.toBeNull();
    await h.batch.recoverDropBatch("c1"); // nothing pending: a no-op
  });
});
