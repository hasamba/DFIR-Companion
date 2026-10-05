import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { privateBundleDir } from "../helpers/bundleDir.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { DROP_LOG_FILE } from "../../src/analysis/dropLog.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";
import { createApp, setServerLogger, buildRuntimePipeline } from "../../src/server.js";
import { LoggerImpl, createConsoleLogger } from "../../src/logging/logger.js";
import type { DebugLogSink } from "../../src/logging/debugLogSink.js";
import { SIEM_FALLBACK_WARNING } from "../../src/routes/importNotes.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";
import { McpServerStore } from "../../src/integrations/mcp/mcpServerStore.js";
import type { ClaudeRunner } from "../../src/providers/claudeRunner.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { approvalRecorder, stagedDetection } from "../../src/routes/mcpPreviewDetection.js";

// #1824: #1795's "unrecognised JSON — imported as generic SIEM" warning reached only /import and
// /import-file. The drop folder, /push and the Velociraptor collectors use the same detector; each now
// says so through its own channel, and every one writes a case-log WARN line that outlives the status.

// Event-shaped JSON no importer claims: detection falls to the SIEM catch-all, not confident.
const GUESSED = JSON.stringify({ name: "dfir-companion", version: "1.0.0", private: true });
// A THOR alert: a confident, deterministic detection.
const THOR_EVENT = {
  time: "2026-06-13T21:18:18Z",
  hostname: "WIN11",
  level: "Alert",
  module: "Filescan",
  message: "Malware file found",
  file: "C:\\Tools\\mimikatz.exe",
};

let lines: string[];
let logger: LoggerImpl;
const sink = (): DebugLogSink => ({
  write: (line) => lines.push(line),
  files: () => ({ previous: "", current: "" }),
  close: () => undefined,
});
const warnLines = (): string[] => lines.filter((l) => l.includes(SIEM_FALLBACK_WARNING));

beforeEach(() => {
  lines = [];
  logger = new LoggerImpl({ level: "error", console: false, debugLog: sink() });
  setServerLogger(logger);
});

afterEach(async () => {
  await logger.close();
  setServerLogger(createConsoleLogger("error"));
});

function runtimePipeline(store: CaseStore, stateStore: StateStore) {
  return buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

// ── /push ───────────────────────────────────────────────────────────────────────────────────────

describe("/push names a guessed JSON kind (#1824)", () => {
  async function pushApp() {
    const root = await mkdtemp(join(tmpdir(), "dfir-siemfb-push-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const statuses: Array<{ detail?: string }> = [];
    const app = createApp(store, {
      pipeline: runtimePipeline(store, stateStore),
      stateStore,
      pushToken: "secret",
      onAiStatus: (_c, e) => statuses.push(e),
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    return { app, statuses };
  }

  it("answers 202 with the warning, logs it, and puts it on the live import status", async () => {
    const { app, statuses } = await pushApp();
    const res = await request(app)
      .post("/cases/c1/push")
      .set("X-DFIR-Key", "secret")
      .send({ source: "webhook", filename: "package.json", text: GUESSED });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("siem");
    expect(res.body.warning).toBe(SIEM_FALLBACK_WARNING);
    expect(warnLines().some((l) => l.includes("package.json"))).toBe(true);
    const detail = await pollFor("the importing status", async () =>
      statuses.map((s) => s.detail ?? "").find((d) => d.startsWith("importing (siem)")),
    );
    expect(detail).toContain(SIEM_FALLBACK_WARNING);
  });

  it("a recognised payload carries no warning", async () => {
    const { app } = await pushApp();
    const res = await request(app)
      .post("/cases/c1/push")
      .set("X-DFIR-Key", "secret")
      .send({ source: "thor", filename: "thor.json", events: [THOR_EVENT] });
    expect(res.status).toBe(202);
    expect(res.body.warning).toBeUndefined();
    expect(warnLines()).toEqual([]);
  });
});

// ── Drop folder ─────────────────────────────────────────────────────────────────────────────────

describe("drop folder names a guessed JSON kind (#1824)", () => {
  it("writes the warning on the file's drop-log line and in drop-status, not on a confident file", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-siemfb-drop-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const dropDir = dropDirOf(store, "c1");
    await mkdir(dropDir, { recursive: true });
    await writeFile(join(dropDir, "guess.json"), GUESSED, "utf8");
    await writeFile(join(dropDir, "thor.json"), JSON.stringify(THOR_EVENT), "utf8");
    const dropStatusStore = new DropStatusStore(store);
    const refuse = (): never => {
      throw new Error("not expected");
    };
    const drops = createDropFolder({
      store,
      options: { dropStatusStore },
      hasAiProvider: () => false,
      getControl: refuse,
      recordImportFailure: refuse,
      dispatchNotify: () => {},
      // The real resolver's two outcomes: a guessed siem, and a confident thor.
      resolveImportKind: (filename, _text, debug) => {
        const kind = filename === "guess.json" ? "siem" : "thor";
        debug?.detected(kind, { confident: kind === "thor", decision: "test_rule" });
        return kind;
      },
      ingestStreamed: vi.fn(async () => ({ storedName: "s", addedEvents: 1, addedIocs: 0, analyzed: true })),
      ingestMacLoginItemBinary: refuse,
      liveToolConfigs: () => new Map(),
      resolveToolForExt: () => null,
      rawExtClaimed: () => false,
      runDropToolAndIngest: refuse,
      indexCaptureText: refuse,
      captureBuffers: new Map(),
      flush: refuse,
    });
    await drops.scanCaseDrops("c1"); // a file is ready once a second sweep sees it unchanged
    await drops.scanCaseDrops("c1");

    const log = (await readFile(join(dropDir, DROP_LOG_FILE), "utf8")).split("\n");
    const guessLine = log.find((l) => l.includes("guess.json")) ?? "";
    expect(guessLine).toMatch(/IMPORTED/);
    expect(guessLine).toContain(SIEM_FALLBACK_WARNING);
    expect(log.find((l) => l.includes("thor.json"))).not.toContain("unrecognised");

    const status = await dropStatusStore.load("c1");
    expect(status.importedCount).toBe(2);
    expect(status.failedCount).toBe(0); // a warning is not a failure, and a clean file is neither
    expect(status.failed).toEqual([]);
    expect(log.some((l) => l.includes("FAILED"))).toBe(false);
    expect(status.warnings).toEqual([{ relpath: "guess.json", reason: SIEM_FALLBACK_WARNING }]);
    expect(warnLines()).toHaveLength(1);
  });
});

// ── Velociraptor /import-external, uploads-only ────────────────────────────────────────────────

describe("Velociraptor uploads-only import names a guessed JSON kind (#1824)", () => {
  async function uploadsApp(uploads: Array<{ name: string; clientId: string; content: string }>) {
    const root = await mkdtemp(join(tmpdir(), "dfir-siemfb-ups-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const client = {
      huntUploads: async () => uploads,
      flowUploads: async () => uploads,
      huntGuiUrlFor: () => undefined,
      flowGuiUrlFor: () => undefined,
    };
    const app = createApp(store, {
      pipeline: runtimePipeline(store, stateStore),
      stateStore,
      superTimelineStore: new SuperTimelineStore(store),
      jobManager: new JobManager({ perCaseConcurrency: 1 }),
      velociraptorClient: client as unknown as NonNullable<
        Parameters<typeof createApp>[1]
      >["velociraptorClient"],
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    return app;
  }

  it("lists a warning for each guessed file that imported, and none for skipped or confident ones", async () => {
    const app = await uploadsApp([
      { name: "guess.json", clientId: "C.1", content: GUESSED },
      { name: "thor.json", clientId: "C.1", content: JSON.stringify(THOR_EVENT) },
      { name: "mystery.bin", clientId: "C.1", content: "\x00\x01\x02 not a report" },
    ]);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads" });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.imported).toEqual(["guess.json", "thor.json"]);
    expect(res.body.skipped).toEqual(["mystery.bin"]);
    expect(res.body.warnings).toEqual([{ file: "guess.json", warning: SIEM_FALLBACK_WARNING }]);
    expect(warnLines()).toHaveLength(1);
  });

  it("omits warnings when nothing was a guess", async () => {
    const app = await uploadsApp([
      { name: "thor.json", clientId: "C.1", content: JSON.stringify(THOR_EVENT) },
    ]);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/collected/C.dead/F.001/uploads" });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.imported).toEqual(["thor.json"]);
    expect(res.body.warnings).toBeUndefined();
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

// The hunt returns one row per artifact plus one uploaded report whose JSON no importer claims.
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts="))
    return { rows: [{ Hunt: { HuntId: "H.SIEMFB1", state: "RUNNING" } }], raw: "" };
  if (p.includes("uploads("))
    return {
      rows: [{ ClientId: "C.1", Path: "/r/guess.json", Name: "guess.json", Content: GUESSED }],
      raw: "",
    };
  if (p.includes("hunt_results(") && p.includes("Pstree"))
    return {
      rows: [
        { Fqdn: "WKS1", Name: "cmd.exe", Pid: 1, CommandLine: "cmd", Timestamp: "2026-06-01T10:00:00Z" },
      ],
      raw: "",
    };
  return { rows: [], raw: "" };
};

describe("Velociraptor hunt collect names a guessed uploaded JSON kind (#1824)", () => {
  it(
    "writes the case-log warning for the guessed upload",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "dfir-siemfb-hunt-"));
      const store = new CaseStore(root);
      const stateStore = new StateStore(store);
      const app = createApp(store, {
        pipeline: runtimePipeline(store, stateStore),
        stateStore,
        importMetaStore: new ImportMetaStore(store),
        superTimelineStore: new SuperTimelineStore(store),
        jobManager: new JobManager({ perCaseConcurrency: 1 }),
        velociraptorClient: new VelociraptorClient(veloCfg, runner),
        artifactBundleStore: new ArtifactBundleStore(privateBundleDir(root)),
        veloHuntStore: new VeloHuntStore(store),
      });
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);
      const status = await pollFor("the hunt job to reach a terminal status", async () => {
        const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
        const s = (jobs.body as Array<{ status?: string }>)[0]?.status;
        return s === "imported" || s === "error" ? s : undefined;
      });
      expect(status).toBe("imported");
      expect(warnLines().filter((l) => l.includes("guess.json"))).toHaveLength(1);
    },
    POLL_TIMEOUT_MS * 2,
  );
});

// ── MCP preview approval ────────────────────────────────────────────────────────────────────────

// The approval runs in a later request with a fresh recorder; the staged preview keeps the detection
// decision so the approval can still tell a guessed kind from a confident one.
describe("MCP preview approval names a guessed JSON kind (#1824)", () => {
  async function mcpApp(output: string) {
    const root = await mkdtemp(join(tmpdir(), "dfir-siemfb-mcp-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const jobManager = new JobManager();
    const mcpServerStore = new McpServerStore(join(root, "mcp-servers.json"));
    const claude: ClaudeRunner = async () => ({
      code: 0,
      stderr: "",
      stdout: JSON.stringify({ type: "result", subtype: "success", result: output }) + "\n",
    });
    const app = createApp(store, {
      pipeline: runtimePipeline(store, stateStore),
      stateStore,
      mcpServerStore,
      jobManager,
      mcpClaudeRunner: claude,
      mcpTransferRunner: async () => ({ stdout: "", stderr: "", code: 0 }),
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await writeFile(join(store.caseDir("c1"), "imports", "mem.raw"), "MZ evidence bytes\n", "utf8");
    await mcpServerStore.add({
      id: "sift-mcp",
      allowedTools: ["run_command"],
      allowedCommands: ["vol.py"],
      delivery: { mode: "scp", host: "sift.example.com", user: "analyst", remoteDir: "/cases/incoming" },
    });
    return { app, jobManager };
  }

  async function previewThenApprove(output: string) {
    const { app, jobManager } = await mcpApp(output);
    const run = await request(app)
      .post("/cases/c1/mcp/sift-mcp/run")
      .send({
        tool: "run_command",
        args: { command: ["vol.py", "-f", "<target>", "pslist"] },
        targetPath: "imports/mem.raw",
        preview: true,
        ackUnmasked: true, // a default case has anonymisation on (#1952)
      });
    await pollFor("the preview job to finish", async () => {
      const st = jobManager.get(run.body.jobId)?.status;
      return st === "succeeded" || st === "failed" ? st : undefined;
    });
    return request(app).post(`/cases/c1/mcp/preview/${run.body.jobId}/import`);
  }

  it(
    "an approved guessed-SIEM preview answers with the warning and logs it",
    async () => {
      const imp = await previewThenApprove(GUESSED);
      expect(imp.status, JSON.stringify(imp.body)).toBe(200);
      expect(imp.body.warning).toBe(SIEM_FALLBACK_WARNING);
      expect(warnLines()).toHaveLength(1);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "an approved recognised preview carries no warning",
    async () => {
      const imp = await previewThenApprove("EvilRule /x/a.bin\n0x10:$s: 4d 5a");
      expect(imp.status, JSON.stringify(imp.body)).toBe(200);
      expect(imp.body.warning).toBeUndefined();
      expect(warnLines()).toEqual([]);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it("stages the decision and ignores a malformed one read back from disk", () => {
    const debug = createImportDebugRecorder();
    debug.detected("siem", { confident: false, decision: "siem_fallback" });
    const staged = stagedDetection(debug);
    expect(staged).toEqual({ detection: { confident: false, decision: "siem_fallback" } });
    expect(approvalRecorder({ kind: "siem", ...staged }).summary().detection?.confident).toBe(false);
    expect(stagedDetection(createImportDebugRecorder())).toEqual({});
    const bad = { kind: "siem", detection: { confident: "no", decision: 1 } } as unknown as Parameters<
      typeof approvalRecorder
    >[0];
    expect(approvalRecorder(bad).summary().detection).toBeUndefined();
  });
});
