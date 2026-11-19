import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, open, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { BulkImportSink } from "../../src/analysis/ingest/velociraptorBulk.js";
import { importFileTooLarge, sniffImportFileHead } from "../../src/routes/importFileHead.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import {
  decideVeloDiskStream,
  veloDiskStreamThreshold,
  VELO_DISK_STREAM_BYTES,
} from "../../src/routes/importVeloStream.js";
import { registerImportResumeHandler } from "../../src/routes/importRecovery.js";
import type { RouteContext, ImportBase } from "../../src/routes/context.js";
import { createDropStreamer } from "../../src/composition/dropStreamed.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";

// #2705: a Velociraptor JSON Lines export over the in-memory threshold is accepted and streamed from
// the stored copy instead of refused; anything else over it keeps the honest 413. The threshold is
// min(DFIR_MAX_IMPORT_FILE_MB, 256 MB), so a 1 MB cap makes a 1.5 MB synthetic file "large".

const MB = 1024 * 1024;

function notebookRow(n: number): Record<string, unknown> {
  return {
    EventTime: new Date(Date.UTC(2026, 7, 13, 22, 0, n % 3600)).toISOString(),
    Computer: "HOSTNAME_1.lab.local",
    Detection: {
      Name: "T1567.002-Use of 32-bit LOLBINs",
      EventId: "^(4688)$",
      Regex: "syswow64",
      Ignore: "",
    },
    Channel: "Security",
    EventID: 4688,
    EventData: {
      SubjectUserName: "HOSTNAME_1$",
      NewProcessId: n,
      NewProcessName: "C:\\Windows\\SysWOW64\\wbem\\WmiPrvSE.exe",
      ParentProcessName: "C:\\Windows\\System32\\svchost.exe",
    },
    Message: "A new process has been created.",
    OSPath: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    FlowId: "F.EXAMPLEFLOW01.H",
    ClientId: "C.0123456789abcdef",
    Fqdn: "HOSTNAME_1.lab.local",
  };
}

function rowsOfAtLeast(bytes: number): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  for (let size = 0, i = 0; size < bytes; i++) {
    const r = notebookRow(i);
    rows.push(r);
    size += JSON.stringify(r).length + 1;
  }
  return rows;
}

const ndjson = (rows: object[]): string => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";

function memorySink(): BulkImportSink & { forensic: ForensicEvent[] } {
  const sink = {
    minBytes: 8 * MB,
    batchRows: 2000,
    forensic: [] as ForensicEvent[],
    beginRun: async () => 0,
    rollback: async () => ({ forensic: 0, super: 0, tags: 0 }),
    appendForensic: async (_c: string, events: ForensicEvent[]) => {
      sink.forensic.push(...events);
      return events.length;
    },
    appendSuper: async (_c: string, events: ForensicEvent[]) => ({
      retained: events.length,
      evicted: { count: 0, setAside: 0, from: "", to: "" },
    }),
    openTagger: async () => null,
    forensicMinSeverity: async () => "Low" as const,
    log: () => {},
  };
  return sink;
}

async function makeApp(withSink: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-stream-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const sink = memorySink();
  const bulk = withSink ? { bulkImportSink: sink } : {};
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    ...bulk,
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    ...bulk,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, root, sink, stateStore };
}

async function until(cond: () => boolean | Promise<boolean>, ms = 10_000): Promise<void> {
  const end = Date.now() + ms;
  while (!(await cond())) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}

const savedCap = process.env.DFIR_MAX_IMPORT_FILE_MB;
beforeEach(() => {
  process.env.DFIR_MAX_IMPORT_FILE_MB = "1";
});
afterEach(() => {
  if (savedCap === undefined) delete process.env.DFIR_MAX_IMPORT_FILE_MB;
  else process.env.DFIR_MAX_IMPORT_FILE_MB = savedCap;
});

describe("POST /cases/:id/import-file — a large Velociraptor JSON Lines file streams (#2705)", () => {
  it("accepts an over-cap notebook export and imports its detections from the stored copy", async () => {
    const { app, root, sink, stateStore } = await makeApp(true);
    const path = join(root, "sb_evtx.json");
    await writeFile(path, ndjson(rowsOfAtLeast(1.5 * MB)), "utf8");

    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("velociraptor");

    // The run's commit point is the final merge (#1480): wait for its timeline note, not the first batch.
    await until(async () => JSON.stringify(await stateStore.load("c1")).includes("bulk path"));
    const hit = sink.forensic.find((e) => /Velociraptor detection: T1567\.002/.test(e.description));
    expect(hit?.severity).toBe("Medium");
    expect(hit?.mitreTechniques).toContain("T1567.002");
  });

  it("keeps the 413 for an over-cap Velociraptor file that is not JSON Lines, naming JSON Lines", async () => {
    const { app, store, root } = await makeApp(true);
    const path = join(root, "sb_evtx.json");
    await writeFile(path, JSON.stringify(rowsOfAtLeast(1.5 * MB)), "utf8"); // one top-level array
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(413);
    expect(res.body.error).toMatch(/Velociraptor JSON Lines/);
    expect(await readdir(store.importsDir("c1")).catch(() => [])).toEqual([]);
  });

  it("refuses an over-threshold UTF-16 file before any evidence copy, saying to convert it to UTF-8", async () => {
    const { app, store, root } = await makeApp(true);
    const path = join(root, "sb_evtx.json");
    const body = Buffer.from(ndjson(rowsOfAtLeast(0.8 * MB)), "utf16le");
    await writeFile(path, Buffer.concat([Buffer.from([0xff, 0xfe]), body]));
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(413);
    expect(res.body.error).toMatch(/convert the file to UTF-8/);
    expect(await readdir(store.importsDir("c1")).catch(() => [])).toEqual([]);
  });

  it("keeps today's 413 on a server whose batched importer is not wired", async () => {
    const { app, root } = await makeApp(false);
    const path = join(root, "sb_evtx.json");
    await writeFile(path, ndjson(rowsOfAtLeast(1.5 * MB)), "utf8");
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(413);
  });
});

describe("veloDiskStreamThreshold (#2705)", () => {
  it("is the import cap when it is lower, and never above 256 MB however high the cap is raised", () => {
    expect(veloDiskStreamThreshold({ DFIR_MAX_IMPORT_FILE_MB: "1" })).toBe(MB);
    expect(veloDiskStreamThreshold({})).toBe(VELO_DISK_STREAM_BYTES);
    expect(veloDiskStreamThreshold({ DFIR_MAX_IMPORT_FILE_MB: "4096" })).toBe(256 * MB);
  });
});

describe("decideVeloDiskStream (#2705)", () => {
  async function decide(
    content: string | Buffer,
    over: Partial<{ kind: string; gzip: boolean; sinkWired: boolean }> = {},
  ) {
    const dir = await mkdtemp(join(tmpdir(), "dfir-velo-decide-"));
    const path = join(dir, "f.json");
    await writeFile(path, content);
    const handle = await open(path, "r");
    try {
      const size = (await handle.stat()).size;
      return await decideVeloDiskStream(
        { kind: "velociraptor", handle, size, gzip: false, sinkWired: true, ...over },
        16,
      );
    } finally {
      await handle.close();
    }
  }
  const lines = ndjson([notebookRow(1), notebookRow(2)]);

  it("streams JSON Lines over the threshold", async () => {
    expect(await decide(lines)).toEqual({ streams: true });
  });

  it("does not stream another kind, a gzip, a server with no batched importer, or a file under the threshold", async () => {
    expect(await decide(lines, { kind: "siem" })).toEqual({ streams: false });
    expect(await decide(lines, { gzip: true })).toEqual({ streams: false });
    expect(await decide(lines, { sinkWired: false })).toEqual({ streams: false });
    expect(await decide("{}\n")).toEqual({ streams: false });
  });

  it("does not stream an array, and refuses UTF-16 with a sentence", async () => {
    expect(await decide(JSON.stringify([notebookRow(1), notebookRow(2)]))).toEqual({ streams: false });
    const utf16 = await decide(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(lines, "utf16le")]));
    expect(utf16.streams).toBe(false);
    expect(utf16.refuse).toMatch(/UTF-8/);
  });
});

describe("importFileTooLarge — honest past the string ceiling (#2705)", () => {
  it("stops suggesting the cap once the file is past ~512 MB, and names JSON Lines for Velociraptor", () => {
    const msg = importFileTooLarge(748 * MB, "velociraptor", 256 * MB)!;
    expect(msg).not.toMatch(/DFIR_MAX_IMPORT_FILE_MB/);
    expect(msg).toMatch(/748 MB/);
    expect(msg).toMatch(/export it from Velociraptor as JSON Lines/);
    expect(importFileTooLarge(600 * MB, "siem", 256 * MB)).not.toMatch(/DFIR_MAX_IMPORT_FILE_MB/);
  });

  it("keeps the knob below the ceiling and lists Velociraptor JSON Lines among the streaming kinds", () => {
    const msg = importFileTooLarge(300 * MB, "thor", 256 * MB)!;
    expect(msg).toMatch(/DFIR_MAX_IMPORT_FILE_MB/);
    expect(msg).toMatch(/Velociraptor JSON Lines/);
  });
});

describe("import resume — a streamed Velociraptor job re-reads the stored file (#2705)", () => {
  async function harness() {
    const root = await mkdtemp(join(tmpdir(), "dfir-velo-resume-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(store);
    await mkdir(store.importsDir("c1"), { recursive: true });
    await writeFile(join(store.importsDir("c1"), "0007_sb_evtx.json"), ndjson([notebookRow(1)]), "utf8");
    let handler: ((job: unknown, signal: AbortSignal) => Promise<unknown>) | undefined;
    const importVelociraptorFile = vi.fn(async () => stateStore.load("c1"));
    const dispatchImport = vi.fn(async (_k: string, _c: string, _t: string, _b: ImportBase) => undefined);
    const ctx = {
      store,
      importLock: new ImportLock(),
      options: {
        pipeline: { importVelociraptorFile },
        stateStore,
        jobManager: {
          registerResumeHandler: (_k: string, h: typeof handler) => {
            handler = h;
          },
          checkpoint: async () => {},
          progress: () => {},
          warn: async () => {},
        },
      },
      dispatchImport,
      demoteForensicForCase: async (caseId: string) => stateStore.load(caseId),
      applyWhitelistToCase: async () => ({ added: 0 }),
      applyNsrlToCase: async () => ({ added: 0 }),
      applyDeobfuscationToCase: async () => ({ added: 0 }),
      recordImportFailure: () => {},
      resynthesizeInBackground: () => {},
      serverLogger: { info: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
    } as unknown as RouteContext;
    registerImportResumeHandler(ctx);
    const run = (streaming: boolean) =>
      handler!(
        {
          id: "j1",
          caseId: "c1",
          kind: "import",
          parameters: {
            kind: "velociraptor",
            storedName: "0007_sb_evtx.json",
            sequence: 7,
            importedAt: "2026-11-19T07:00:00.000Z",
            minSeverity: null,
            streaming,
          },
          lastCheckpoint: undefined,
        },
        new AbortController().signal,
      );
    return { run, importVelociraptorFile, dispatchImport, store };
  }

  it("streams from the stored file when the first run streamed", async () => {
    const h = await harness();
    await h.run(true);
    expect(h.importVelociraptorFile).toHaveBeenCalledTimes(1);
    expect(h.importVelociraptorFile.mock.calls[0]).toEqual(
      expect.arrayContaining(["c1", join(h.store.importsDir("c1"), "0007_sb_evtx.json")]),
    );
    expect(h.dispatchImport).not.toHaveBeenCalled();
  });

  it("reads the file whole when the first run did", async () => {
    const h = await harness();
    await h.run(false);
    expect(h.dispatchImport).toHaveBeenCalledTimes(1);
    expect(h.importVelociraptorFile).not.toHaveBeenCalled();
  });
});

describe("drop folder — a Velociraptor JSON Lines file over the drop cap streams (#2705)", () => {
  async function dropFile(content: string) {
    const dir = await mkdtemp(join(tmpdir(), "dfir-velo-drop-"));
    const full = join(dir, "sb_evtx.json");
    await writeFile(full, content, "utf8");
    return full;
  }
  const ingestDiskFile = vi.fn(async () => ({
    storedName: "0001_sb_evtx.json",
    addedEvents: 1,
    addedIocs: 0,
    disclosure: [],
  }));

  it("streams under a drop cap far below the import cap", async () => {
    process.env.DFIR_MAX_IMPORT_FILE_MB = "256";
    ingestDiskFile.mockClear();
    const stream = createDropStreamer({
      resolveImportKind: () => "velociraptor",
      ingestDiskFile,
      dropMaxBytes: 64,
      veloSinkWired: () => true,
    });
    const full = await dropFile(ndjson([notebookRow(1), notebookRow(2)]));
    const r = await stream("c1", full, "sb_evtx.json", createImportDebugRecorder());
    expect(r).toEqual({ ok: true });
    expect(ingestDiskFile).toHaveBeenCalledWith(
      "c1",
      "velociraptor",
      expect.anything(),
      "sb_evtx.json",
      undefined,
      expect.anything(),
    );
  });

  it("leaves a non-JSON-Lines file, or a server with no batched importer, to the usual oversize refusal", async () => {
    ingestDiskFile.mockClear();
    const mk = (wired: boolean) =>
      createDropStreamer({
        resolveImportKind: () => "velociraptor",
        ingestDiskFile,
        dropMaxBytes: 64,
        veloSinkWired: () => wired,
      });
    const arr = await dropFile(JSON.stringify([notebookRow(1), notebookRow(2)]));
    expect(await mk(true)("c1", arr, "sb_evtx.json", createImportDebugRecorder())).toBeNull();
    const lines = await dropFile(ndjson([notebookRow(1), notebookRow(2)]));
    expect(await mk(false)("c1", lines, "sb_evtx.json", createImportDebugRecorder())).toBeNull();
    expect(ingestDiskFile).not.toHaveBeenCalled();
  });
});

// Codex review of #2705: the kind is detected from a 256 KB head, so a notebook export whose FIRST
// record is longer than that (a long CommandLine, a big ScriptBlockText) was refused as unknown
// before the bounded first-record probe ever ran — with no Velociraptor filename to rescue it.
describe("a first record longer than the head sample still detects (#2705 review)", () => {
  const longFirst = (): string => {
    const first = { ...notebookRow(0), Message: `long ${"x".repeat(600_000)}` };
    return ndjson([first, ...rowsOfAtLeast(1.5 * MB)]);
  };

  it("sniffImportFileHead returns the whole first record, which detects as Velociraptor", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-velo-head-"));
    const path = join(dir, "export.json");
    await writeFile(path, longFirst(), "utf8");
    const fh = await open(path, "r");
    try {
      const sample = await sniffImportFileHead(fh);
      expect(detectImportKind("export.json", sample)).toBe("velociraptor");
    } finally {
      await fh.close();
    }
  });

  it("/import-file accepts it with no Velociraptor filename hint", async () => {
    const { app, root } = await makeApp(true);
    const path = join(root, "export.json");
    await writeFile(path, longFirst(), "utf8");
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("velociraptor");
  });

  it("the drop folder streams it with no Velociraptor filename hint", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-velo-drop-long-"));
    const full = join(dir, "export.json");
    await writeFile(full, longFirst(), "utf8");
    const ingestDiskFile = vi.fn(async () => ({
      storedName: "0001_export.json",
      addedEvents: 1,
      addedIocs: 0,
      disclosure: [],
    }));
    const stream = createDropStreamer({
      resolveImportKind: (name, text) => detectImportKind(name, text),
      ingestDiskFile,
      dropMaxBytes: 64,
      veloSinkWired: () => true,
    });
    expect(await stream("c1", full, "export.json", createImportDebugRecorder())).toEqual({ ok: true });
    expect(ingestDiskFile).toHaveBeenCalledWith(
      "c1",
      "velociraptor",
      expect.anything(),
      "export.json",
      undefined,
      expect.anything(),
    );
  });
});
