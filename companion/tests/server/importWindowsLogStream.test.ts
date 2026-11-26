import { describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, open, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { CLOUD_STREAM_MIN_BYTES } from "../../src/analysis/cloudStreamLimits.js";
import {
  decideWindowsLogDiskStream,
  windowsLogWholeReadHint,
} from "../../src/routes/importWindowsLogStream.js";
import { registerImportResumeHandler } from "../../src/routes/importRecovery.js";
import { cancellableByParse } from "../../src/routes/importKinds.js";
import type { RouteContext, ImportBase } from "../../src/routes/context.js";
import { createDropStreamer } from "../../src/composition/dropStreamed.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";

// #2823: a large SIEM JSON Lines export or Windows Event XML export is read from the stored copy in
// parts instead of as one string — on upload / import-from-path, from the drop folder and on resume.
// Synthetic data only.

const winlogbeat = (i: number) => ({
  "@timestamp": new Date(Date.UTC(2026, 2, 1, 10, 0, i % 60)).toISOString(),
  log_name: "Security",
  computer_name: "WS-01",
  event_id: 4624,
  event_data: {
    TargetUserName: `user${i % 5}`,
    TargetDomainName: "LAB",
    LogonType: "3",
    IpAddress: `192.0.2.${i % 9}`,
  },
});
const ndjson = (count: number, from = 0) =>
  Array.from({ length: count }, (_, i) => JSON.stringify(winlogbeat(from + i))).join("\n") + "\n";
const XML_EVENT =
  '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Security"/>' +
  '<EventID>4624</EventID><TimeCreated SystemTime="2026-03-01T10:00:00Z"/><Channel>Security</Channel>' +
  '<Computer>WS-01</Computer></System><EventData><Data Name="TargetUserName">u1</Data></EventData></Event>';

async function tmpFile(name: string, content: string | Buffer): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-winlog-"));
  const full = join(dir, name);
  await writeFile(full, content);
  return full;
}

async function decide(kind: string, content: string | Buffer, threshold: number, gzip = false) {
  const fh = await open(await tmpFile("f.log", content), "r");
  try {
    return await decideWindowsLogDiskStream(
      { kind, handle: fh, size: (await fh.stat()).size, gzip },
      threshold,
    );
  } finally {
    await fh.close();
  }
}

describe("decideWindowsLogDiskStream (#2823)", () => {
  it("streams SIEM JSON Lines and Windows Event XML at or over the threshold", async () => {
    expect(await decide("siem", ndjson(3), 10)).toBe(true);
    expect(await decide("evtxxml", `<Events>${XML_EVENT}</Events>`, 10)).toBe(true);
  });

  it("keeps the whole read under the threshold, for gzip, UTF-16, one JSON document and other kinds", async () => {
    expect(await decide("siem", ndjson(3), 10_000_000)).toBe(false);
    expect(await decide("siem", ndjson(3), 10, true)).toBe(false);
    expect(
      await decide("evtxxml", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("<\0E\0")]), 1),
    ).toBe(false);
    expect(await decide("siem", JSON.stringify([winlogbeat(1), winlogbeat(2)]), 10)).toBe(false);
    expect(await decide("hayabusa", ndjson(3), 10)).toBe(false);
  });

  it("defaults to the cloud exports' 32 MB threshold", async () => {
    expect(CLOUD_STREAM_MIN_BYTES).toBe(32 * 1024 * 1024);
  });
});

describe("windowsLogWholeReadHint (#2823)", () => {
  it("charges a whole SIEM / EVTX XML read by its size, and leaves every other kind as it was", () => {
    expect(windowsLogWholeReadHint("siem", 5)).toEqual({ incomingBytes: 5, wholeRead: true });
    expect(windowsLogWholeReadHint("evtxxml", 5)).toEqual({ incomingBytes: 5, wholeRead: true });
    expect(windowsLogWholeReadHint("hayabusa", 5)).toEqual({ incomingBytes: 5 });
  });

  it("makes a streamed SIEM job cancellable, as its file twin checks the signal", () => {
    expect(cancellableByParse("siem", true)).toBe(true);
    expect(cancellableByParse("siem", false)).toBe(false);
  });
});

describe("drop folder — an under-cap SIEM JSON Lines file is offered to the streamer (#2823)", () => {
  const ingestDiskFile = vi.fn(async () => ({
    storedName: "0001_x",
    addedEvents: 1,
    addedIocs: 0,
    disclosure: [],
  }));
  const streamer = (kind: string, dropMaxBytes = 64) =>
    createDropStreamer({ resolveImportKind: () => kind, ingestDiskFile, dropMaxBytes });

  it("streams a SIEM JSON Lines file at or over min(32 MB, the drop cap)", async () => {
    ingestDiskFile.mockClear();
    const full = await tmpFile("winlogbeat.json", ndjson(5));
    const r = await streamer("siem")("c1", full, "winlogbeat.json", createImportDebugRecorder(), true);
    expect(r).toEqual({ ok: true });
    expect(ingestDiskFile).toHaveBeenCalledWith(
      "c1",
      "siem",
      expect.anything(),
      "winlogbeat.json",
      undefined,
      expect.anything(),
    );
  });

  it("returns null for one JSON document, or any other kind — even one that streams over the cap", async () => {
    ingestDiskFile.mockClear();
    const doc = await tmpFile("export.json", JSON.stringify([winlogbeat(1), winlogbeat(2)]));
    expect(await streamer("siem")("c1", doc, "export.json", createImportDebugRecorder(), true)).toBeNull();
    const cloud = await tmpFile("ct.json", ndjson(5));
    expect(await streamer("aws", 1)("c1", cloud, "ct.json", createImportDebugRecorder(), true)).toBeNull();
    expect(await streamer("plaso")("c1", cloud, "ct.json", createImportDebugRecorder(), true)).toBeNull();
    expect(ingestDiskFile).not.toHaveBeenCalled();
  });
});

describe("import resume — a streamed SIEM job re-reads the stored file in parts (#2823)", () => {
  it("calls the file twin when the first run streamed, and the whole read when it did not", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-winlog-resume-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(store);
    await mkdir(store.importsDir("c1"), { recursive: true });
    await writeFile(join(store.importsDir("c1"), "0003_winlogbeat.json"), ndjson(3));
    let handler: ((job: unknown, signal: AbortSignal) => Promise<unknown>) | undefined;
    const importWindowsLogFile = vi.fn(async () => stateStore.load("c1"));
    const dispatchImport = vi.fn(async (_k: string, _c: string, _t: string, _b: ImportBase) => undefined);
    const ctx = {
      store,
      importLock: new ImportLock(),
      options: {
        pipeline: { importWindowsLogFile },
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
            kind: "siem",
            storedName: "0003_winlogbeat.json",
            sequence: 3,
            importedAt: "2026-11-19T07:00:00.000Z",
            minSeverity: null,
            streaming,
          },
          lastCheckpoint: undefined,
        },
        new AbortController().signal,
      );
    await run(true);
    expect(importWindowsLogFile).toHaveBeenCalledTimes(1);
    expect(importWindowsLogFile.mock.calls[0]).toEqual(
      expect.arrayContaining(["c1", "siem", join(store.importsDir("c1"), "0003_winlogbeat.json")]),
    );
    expect(dispatchImport).not.toHaveBeenCalled();
    await run(false);
    expect(dispatchImport).toHaveBeenCalledTimes(1);
  });
});

describe("POST /cases/:id/import-file — a 32 MB+ SIEM JSON Lines file reads in parts (#2823)", () => {
  it("imports from the stored copy with the whole-text importer's note and counts", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-winlog-e2e-"));
    const store = new CaseStore(join(root, "cases"));
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const fileTwin = vi.spyOn(pipeline, "importWindowsLogFile");
    const wholeText = vi.spyOn(pipeline, "importSiem");
    const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    // Wide rows (an unread padding field) keep the row count, and so the test's run time, small.
    const pad = "x".repeat(32 * 1024);
    const line = (i: number) => JSON.stringify({ ...winlogbeat(i), agent: { pad } });
    const rows = Math.ceil(CLOUD_STREAM_MIN_BYTES / (line(0).length + 1)) + 2;
    const path = join(root, "winlogbeat.json");
    await writeFile(path, Array.from({ length: rows }, (_, i) => line(i)).join("\n") + "\n");
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("siem");

    const end = Date.now() + 60_000;
    let note = "";
    while (!note) {
      if (Date.now() > end) throw new Error("timed out");
      await new Promise((r) => setTimeout(r, 100));
      note = JSON.stringify(await stateStore.load("c1")).match(/SIEM import \(ndjson\)[^"]*/)?.[0] ?? "";
    }
    expect(note).toContain(`from ${rows} record(s)`);
    expect(fileTwin).toHaveBeenCalledTimes(1);
    expect(wholeText).not.toHaveBeenCalled();
  }, 90_000);
});
