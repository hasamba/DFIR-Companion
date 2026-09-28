import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateBundleDir } from "../helpers/bundleDir.js";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import type { ImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";
import { importArtifactsUnderJob } from "../../src/routes/veloExternalImportJob.js";
import { createApp, setServerLogger, buildRuntimePipeline } from "../../src/server.js";
import { LoggerImpl, createConsoleLogger } from "../../src/logging/logger.js";
import type { DebugLogSink } from "../../src/logging/debugLogSink.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #1736: the import entry points that are not an HTTP import route — the drop folder, a Velociraptor
// hunt collect, the external-import loop, and /push — each carry one debug recorder per attempt,
// from detection to its terminal seam (the success line, or the diagnostics ring on failure).

// Unique markers in the rows. None may reach a debug line.
const MARK_HOST = "WKS-MARKER-4417.example.com";
const MARK_CMD = "rundll32.exe marker-cmd-9051.dll,Start";

let lines: string[];
let logger: LoggerImpl;
const sink = (): DebugLogSink => ({
  write: (line) => lines.push(line),
  files: () => ({ previous: "", current: "" }),
  close: () => undefined,
});
const importerLines = (kind: string): string[] =>
  lines.filter((l) => l.includes(`[import-debug] importer ${kind}:`));
const summaryOf = (line: string): Record<string, unknown> =>
  JSON.parse(line.slice(line.indexOf("{"))) as Record<string, unknown>;

beforeEach(() => {
  lines = [];
  logger = new LoggerImpl({ level: "error", console: false, debugLog: sink() });
  setServerLogger(logger);
});

afterEach(async () => {
  await logger.close();
  setServerLogger(createConsoleLogger("error"));
});

// ── Drop folder ─────────────────────────────────────────────────────────────────────────────────

type IngestArgs = [
  string,
  string,
  string,
  string,
  unknown?,
  unknown?,
  unknown?,
  unknown?,
  ImportDebugRecorder?,
];

async function sweepDrop(files: Record<string, string>, ingestFails = false) {
  const root = await mkdtemp(join(tmpdir(), "dfir-idbg-drop-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  for (const [name, text] of Object.entries(files)) await writeFile(join(dropDir, name), text, "utf8");

  const detectedWith: ImportDebugRecorder[] = [];
  const failedWith: Array<ImportDebugRecorder | undefined> = [];
  const ingestStreamed = vi.fn(async (...args: IngestArgs) => {
    void args;
    if (ingestFails) throw new Error("disk full");
    return { storedName: "s", addedEvents: 1, addedIocs: 0, analyzed: true };
  });
  const refuse = (): never => {
    throw new Error("not expected");
  };
  const drops = createDropFolder({
    store,
    options: { dropStatusStore: new DropStatusStore(store) },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: (_c, _k, _f, _e, debug) => failedWith.push(debug),
    dispatchNotify: () => {},
    // A stand-in for the real resolver: it records a decision on the recorder it is handed.
    resolveImportKind: (filename, _text, debug) => {
      if (debug) detectedWith.push(debug);
      const kind = filename.endsWith(".json") ? "thor" : "unknown";
      debug?.detected(kind, { confident: true, decision: "test_rule" });
      return kind;
    },
    ingestStreamed,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
  // A file is ready only once a second sweep sees it unchanged.
  await drops.scanCaseDrops("c1");
  await drops.scanCaseDrops("c1");
  return { detectedWith, failedWith, ingestStreamed };
}

describe("drop folder: one recorder per dropped file (#1736)", () => {
  it("hands the recorder that saw detection to the import", async () => {
    const { detectedWith, ingestStreamed } = await sweepDrop({ "a.json": '{"x":1}', "b.json": '{"y":2}' });
    expect(detectedWith).toHaveLength(2);
    expect(detectedWith[0]).not.toBe(detectedWith[1]); // per file, not per sweep
    const handed = ingestStreamed.mock.calls.map((c) => c[8]);
    expect(new Set(handed)).toEqual(new Set(detectedWith));
    expect(detectedWith[0].summary().detection).toEqual({ confident: true, decision: "test_rule" });
  });

  it("hands the same recorder to recordImportFailure when the import throws", async () => {
    const { detectedWith, failedWith } = await sweepDrop({ "a.json": '{"x":1}' }, true);
    expect(failedWith).toHaveLength(1);
    expect(failedWith[0]).toBe(detectedWith[0]);
    expect(failedWith[0]!.summary()).toMatchObject({
      kind: "thor",
      detection: { decision: "test_rule" },
    });
  });

  it("writes a failed line with the detection decision for an unrecognized file", async () => {
    const { detectedWith, ingestStreamed } = await sweepDrop({ "notes.txt": "hello" });
    expect(ingestStreamed).not.toHaveBeenCalled();
    expect(detectedWith[0].summary()).toMatchObject({ kind: "unknown", outcome: "failed" });
    expect(importerLines("unknown")).toHaveLength(1);
  });
});

// ── Velociraptor external-import loop ───────────────────────────────────────────────────────────

describe("velociraptor external import: one recorder per artifact (#1736)", () => {
  it("gives each artifact its own recorder, and a failing artifact's reaches the ring", async () => {
    const seen: ImportDebugRecorder[] = [];
    const failed: Array<ImportDebugRecorder | undefined> = [];
    await expect(
      importArtifactsUnderJob(
        {
          jobManager: new JobManager({ perCaseConcurrency: 1 }),
          logLine: () => {},
          recordImportFailure: (_c, _k, _f, _e, debug) => failed.push(debug),
        },
        "c1",
        "hunt H.1 (external import)",
        ["A.One", "B.Two"],
        async () => ({ rows: [{ x: 1 }] }),
        async (art, _rows, read) => {
          seen.push(read.debug);
          if (art === "B.Two") throw new Error("disk full");
          return { addedEvents: 1, addedIocs: 0 };
        },
      ),
    ).rejects.toThrow("disk full");
    expect(seen).toHaveLength(2);
    expect(seen[0]).not.toBe(seen[1]);
    expect(failed).toEqual([seen[1]]); // the artifact that failed, not the hunt's first
  });
});

// ── Velociraptor hunt collect ───────────────────────────────────────────────────────────────────

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

// Two artifacts return rows, so a correct collect writes two lines — one per artifact import.
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts="))
    return { rows: [{ Hunt: { HuntId: "H.IDBG1", state: "RUNNING" } }], raw: "" };
  if (p.includes("hunt_results(") && (p.includes("Pstree") || p.includes("Malfind")))
    return {
      rows: [
        {
          Fqdn: MARK_HOST,
          Name: "rundll32.exe",
          Pid: 4321,
          CommandLine: MARK_CMD,
          Timestamp: "2026-06-01T10:00:00Z",
        },
      ],
      raw: "",
    };
  return { rows: [], raw: "" };
};

async function makeVeloApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-idbg-velo-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    superTimelineStore: new SuperTimelineStore(store),
    jobManager: new JobManager({ perCaseConcurrency: 1 }),
    velociraptorClient: new VelociraptorClient(veloCfg, runner),
    artifactBundleStore: new ArtifactBundleStore(privateBundleDir(root)),
    veloHuntStore: new VeloHuntStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

async function collect(app: Awaited<ReturnType<typeof makeVeloApp>>["app"]): Promise<string> {
  await request(app)
    .post("/cases/c1/velociraptor/run-bundle")
    .send({ bundleId: "best-practice", waitMinutes: 30 });
  expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);
  return pollFor("the hunt job to reach a terminal status", async () => {
    const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
    const status = (jobs.body as Array<{ status?: string }>)[0]?.status;
    return status === "imported" || status === "error" ? status : undefined;
  });
}

describe("velociraptor hunt collect: one recorder per artifact (#1736)", () => {
  it(
    "writes one succeeded line per imported artifact, with no row content",
    async () => {
      const { app } = await makeVeloApp();
      expect(await collect(app)).toBe("imported");
      const velo = importerLines("velociraptor");
      expect(velo).toHaveLength(2);
      for (const line of velo) {
        expect(summaryOf(line)).toMatchObject({
          outcome: "succeeded",
          detection: { confident: true, decision: "explicit_route" },
        });
        for (const value of [MARK_HOST, MARK_CMD, "H.IDBG1"]) expect(line).not.toContain(value);
      }
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "hands the failing artifact's recorder to the diagnostics ring",
    async () => {
      const { app, store } = await makeVeloApp();
      // EEXIST on the first artifact's evidence copy: a real failure inside the artifact loop.
      const artifacts = ["Windows.Detection.Malfind", "Generic.System.Pstree"];
      for (const a of artifacts) await store.saveImport("c1", `0001_velo-hunt_H.IDBG1_${a}.json`, "x");
      expect(await collect(app)).toBe("error");
      const diag = await request(app).get("/diagnostics");
      const entry = diag.body.report.importers.recentFailures[0];
      expect(entry.kind).toBe("velociraptor-hunt");
      expect(entry.importer).toMatchObject({ kind: "velociraptor", outcome: "failed" });
    },
    POLL_TIMEOUT_MS * 2,
  );
});

// ── /push ───────────────────────────────────────────────────────────────────────────────────────

const THOR_EVENT = {
  time: "2026-06-13T21:18:18Z",
  hostname: MARK_HOST,
  level: "Alert",
  module: "Filescan",
  message: "Malware file found",
  file: "C:\\Tools\\marker-9051.exe",
};

async function makePushApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-idbg-push-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, pushToken: "secret" });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

const push = (app: Awaited<ReturnType<typeof makePushApp>>["app"]) =>
  request(app)
    .post("/cases/c1/push")
    .set("X-DFIR-Key", "secret")
    .send({ source: "siem-webhook", filename: "thor.json", events: [THOR_EVENT] });

describe("/push: one recorder from detection to the terminal seam (#1736)", () => {
  it("writes one parsed line that carries the push's own detection decision", async () => {
    const { app } = await makePushApp();
    expect((await push(app)).status).toBe(202);
    const line = await pollFor("a thor import-debug line", async () => importerLines("thor")[0]);
    const summary = summaryOf(line);
    expect(summary.outcome).toBe("parsed");
    // Only the resolver sets a decision: its presence proves the same recorder reached the import.
    expect(summary.detection).toMatchObject({ decision: expect.any(String) });
    expect(importerLines("thor")).toHaveLength(1);
    for (const value of [MARK_HOST, "marker-9051"]) expect(line).not.toContain(value);
  });

  it("hands the recorder to the diagnostics ring when the import fails after the 202", async () => {
    const { app, store } = await makePushApp();
    await store.saveImport("c1", "0001_thor.json", "x"); // EEXIST on the evidence copy
    expect((await push(app)).status).toBe(202);
    const entry = await pollFor("a push failure on the ring", async () => {
      const diag = await request(app).get("/diagnostics");
      return diag.body.report.importers.recentFailures[0] as Record<string, unknown> | undefined;
    });
    expect(entry.importer).toMatchObject({ kind: "thor", outcome: "failed" });
    expect((entry.importer as Record<string, unknown>).detection).toMatchObject({
      decision: expect.any(String),
    });
  });
});
