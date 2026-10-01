import { describe, it, expect, vi } from "vitest";
import { mkdtemp, mkdir, readdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { VeloMonitorStore } from "../../src/analysis/veloMonitorStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import {
  admitIngest,
  admitOrDefer,
  beginArchive,
  CaseArchivedError,
  CaseArchivingError,
  hasIngestReservation,
  withIngestAdmission,
} from "../../src/analysis/caseIngestAdmission.js";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import { createDropFolder, dropDirOf, type DropFolderDeps } from "../../src/composition/dropFolder.js";
import {
  createVeloExternalIngest,
  type VeloExternalIngestDeps,
} from "../../src/composition/veloExternalIngest.js";
import { createHuntCollectAdmission } from "../../src/composition/veloHuntAdmission.js";
import { detectImportWithCustom } from "../../src/analysis/importDecision.js";
import { VelociraptorClient, type VqlRunner } from "../../src/integrations/velociraptor/velociraptorApi.js";

// #1920: ONE admission point between evidence ingest and a whole-case archive. Every ingest path
// writes its raw evidence before it queues for the import section, so the import lock cannot tell an
// archive that an ingest is in flight. Each path now reserves the case before its first evidence write
// and releases once settled; an archive refuses while a reservation is open; and while an archive
// holds the case each path refuses (or, for background work, skips this pass and tries again).

const THOR = JSON.stringify({
  level: "Warning",
  module: "Filescan",
  message: "Suspicious file",
  time: "2026-05-02T10:00:00Z",
  file: "C:\\Temp\\a.exe",
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

async function caseStore(): Promise<CaseStore> {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-1920-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return store;
}

const storedImports = async (store: CaseStore) =>
  existsSync(store.importsLogPath("c1")) ? (await readdir(join(store.caseDir("c1"), "imports"))).length : 0;

/** A real ingestStreamed over a pipeline stub whose THOR import waits on `gate`. */
function streamed(store: CaseStore, gate?: Promise<void>) {
  const deps = {
    store,
    options: {
      pipeline: {
        importThor: async () => {
          await gate;
          return undefined;
        },
      },
    },
    runStateExclusive: async (_c: string, fn: () => Promise<unknown>) => fn(),
    importLock: new ImportLock(),
    recordImporterRun: () => {},
    redactErr: (err: unknown) => String(err),
    autoTagImported: async () => {},
    getControl: async () => ({ enabled: true }),
    applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
    applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
    applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
    resynthesizeInBackground: () => {},
  } as unknown as ImportIngestDeps;
  return createImportIngest(deps);
}

describe("the admission point itself", () => {
  it("an archive cannot start while an ingest holds a reservation, and an ingest cannot start during an archive", () => {
    const root = "/cases-a";
    const release = admitIngest(root, "c1");
    expect(beginArchive(root, "c1")).toBeNull();
    release();
    release(); // idempotent: a second release does not free another ingest's reservation
    const end = beginArchive(root, "c1");
    expect(end).not.toBeNull();
    expect(() => admitIngest(root, "c1")).toThrow(CaseArchivingError);
    expect(beginArchive(root, "c1")).toBeNull(); // one archive at a time
    end!();
    expect(() => admitIngest(root, "c1")()).not.toThrow();
  });

  it("keeps cases and cases roots apart", () => {
    const end = beginArchive("/cases-b", "c1")!;
    expect(() => admitIngest("/cases-b", "c2")()).not.toThrow();
    expect(() => admitIngest("/other-root", "c1")()).not.toThrow();
    end();
  });

  it("withIngestAdmission releases after a failure too", async () => {
    await expect(
      withIngestAdmission("/cases-c", "c1", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(hasIngestReservation("/cases-c", "c1")).toBe(false);
  });

  it("admitOrDefer skips the pass and says why while an archive holds the case", async () => {
    const end = beginArchive("/cases-d", "c1")!;
    const fn = vi.fn(async () => 1);
    const onDeferred = vi.fn();
    expect(await admitOrDefer("/cases-d", "c1", fn, onDeferred)).toBeUndefined();
    expect(fn).not.toHaveBeenCalled();
    expect(onDeferred).toHaveBeenCalledWith(expect.stringMatching(/being archived/));
    end();
    expect(await admitOrDefer("/cases-d", "c1", fn, onDeferred)).toBe(1);
  });
});

describe("streamed ingest — /push, MCP, Velociraptor monitors, external tools, drop files", () => {
  it("holds a reservation from before the evidence write until the import settles", async () => {
    const store = await caseStore();
    const gate = deferred();
    const { ingestStreamed } = streamed(store, gate.promise);
    const run = ingestStreamed("c1", "thor", THOR, "thor.json");
    expect(hasIngestReservation(store.casesRoot, "c1")).toBe(true); // taken at the call, before any write
    expect(beginArchive(store.casesRoot, "c1")).toBeNull();
    gate.resolve();
    await run;
    expect(hasIngestReservation(store.casesRoot, "c1")).toBe(false);
  });

  it("is refused before anything is written while an archive holds the case", async () => {
    const store = await caseStore();
    const { ingestStreamed, ingestMacLoginItemStreamed } = streamed(store);
    const end = beginArchive(store.casesRoot, "c1")!;
    await expect(ingestStreamed("c1", "thor", THOR, "thor.json")).rejects.toBeInstanceOf(CaseArchivingError);
    await expect(
      ingestMacLoginItemStreamed("c1", Buffer.from("x"), "BackgroundItems-v4.btm"),
    ).rejects.toBeInstanceOf(CaseArchivingError);
    expect(await storedImports(store)).toBe(0);
    end();
  });
});

describe("an archived case takes no new evidence from a deferred background ingest", () => {
  it("refuses streamed ingest into an archived case before anything is written", async () => {
    const store = await caseStore();
    await store.archiveCaseFolder("c1", "archived");
    const { ingestStreamed } = streamed(store);
    await expect(ingestStreamed("c1", "thor", THOR, "thor.json")).rejects.toBeInstanceOf(CaseArchivedError);
    expect(hasIngestReservation(store.casesRoot, "c1")).toBe(false);
  });
});

describe("/push", () => {
  it("answers 409 before the 202 while an archive holds the case, and stores nothing", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-1920-push-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore, pushToken: "test-push-token" });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i" });
    const end = beginArchive(store.casesRoot, "c1")!;
    const res = await request(app)
      .post("/cases/c1/push")
      .set("X-DFIR-Key", "test-push-token")
      .send({ text: THOR, filename: "thor.json", source: "test" });
    end();
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/being archived/);
    expect(await storedImports(store)).toBe(0);
  });
});

describe("Velociraptor monitor", () => {
  it("keeps its cursor while an archive holds the case, so the next poll retries the same window", async () => {
    const row = {
      System: {
        EventID: { Value: 1 },
        Channel: "Microsoft-Windows-Sysmon/Operational",
        Computer: "WS01",
        TimeCreated: "2026-06-13T10:00:00Z",
      },
      EventData: { Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd /c whoami" },
      _ts: 1_780_000_100,
    };
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("get_client_monitoring()"))
        return {
          rows: [{ State: { artifacts: { artifacts: ["Windows.Events.ProcessCreation"] } } }],
          raw: "",
        };
      if (p.includes("source(")) return { rows: [row], raw: "" };
      return { rows: [], raw: "" };
    };
    const root = await mkdtemp(join(tmpdir(), "dfir-1920-mon-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, {
      pipeline,
      stateStore,
      importMetaStore: new ImportMetaStore(store),
      velociraptorClient: new VelociraptorClient(
        {
          apiConfigPath: "/x/api.yaml",
          binary: "velociraptor",
          timeoutMs: 5000,
          maxRows: 1000,
          maxOutputBytes: 1 << 20,
        },
        runner,
      ),
      veloMonitorStore: new VeloMonitorStore(store),
      veloMonitorPollSeconds: 30,
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i" });
    const start = await request(app)
      .post("/cases/c1/velociraptor/monitors")
      .send({ clientId: "C.abc123", artifact: "Windows.Events.ProcessCreation" });
    const mid = encodeURIComponent(start.body.monitor.id);

    const end = beginArchive(store.casesRoot, "c1")!;
    const deferredPoll = await request(app).post(`/cases/c1/velociraptor/monitors/${mid}/poll`);
    end();
    expect(deferredPoll.body.monitor.lastError).toMatch(/being archived/);
    expect(deferredPoll.body.monitor.cursor).toBe(start.body.monitor.cursor);
    expect(await storedImports(store)).toBe(0);

    const poll = await request(app).post(`/cases/c1/velociraptor/monitors/${mid}/poll`);
    expect(poll.body.monitor.status).toBe("active");
    expect(poll.body.monitor.addedEvents).toBeGreaterThan(0);
  });
});

describe("drop-folder sweep", () => {
  it("leaves the files in drop/ while an archive holds the case, and imports them on a later sweep", async () => {
    const store = await caseStore();
    const dropDir = dropDirOf(store, "c1");
    await mkdir(dropDir, { recursive: true });
    await writeFile(join(dropDir, "thor.json"), THOR, "utf8");
    const { ingestStreamed } = streamed(store);
    const ingest = vi.fn(ingestStreamed);
    const refuse = (): never => {
      throw new Error("not expected");
    };
    const drops = createDropFolder({
      store,
      options: {},
      hasAiProvider: () => true,
      getControl: async () => ({ enabled: true }),
      recordImportFailure: refuse,
      dispatchNotify: () => {},
      resolveImportKind: (filename: string, text: string) =>
        detectImportWithCustom(filename, text, new Map(), "builtin-first"),
      ingestStreamed: ingest,
      ingestMacLoginItemBinary: refuse,
      liveToolConfigs: () => new Map(),
      resolveToolForExt: () => null,
      rawExtClaimed: () => false,
      runDropToolAndIngest: refuse,
      indexCaptureText: refuse,
      captureBuffers: new Map(),
      flush: refuse,
    } as unknown as DropFolderDeps);

    await drops.scanCaseDrops("c1"); // the first sweep only lists; a stable file imports on the next
    const end = beginArchive(store.casesRoot, "c1")!;
    await drops.scanCaseDrops("c1");
    end();
    expect(ingest).not.toHaveBeenCalled();
    expect(existsSync(join(dropDir, "thor.json"))).toBe(true);

    await drops.scanCaseDrops("c1");
    expect(ingest).toHaveBeenCalledOnce();
  });
});

describe("Velociraptor external hunt/flow ingest", () => {
  function external(store: CaseStore, persistEvidence: VeloExternalIngestDeps["persistEvidence"]) {
    return createVeloExternalIngest({
      options: { pipeline: {} },
      store,
      importLock: new ImportLock(),
      persistEvidence,
    } as unknown as VeloExternalIngestDeps);
  }

  it("holds a reservation while it stores evidence, and is refused before storing during an archive", async () => {
    const store = await caseStore();
    const seen: boolean[] = [];
    const persist = vi.fn(async () => {
      seen.push(hasIngestReservation(store.casesRoot, "c1"));
      throw new Error("stop after the evidence write");
    });
    const { ingestVeloArtifactMap, ingestVeloUploads } = external(store, persist);
    await expect(ingestVeloArtifactMap("c1", "{}", { label: "m.json", idBase: "m" })).rejects.toThrow(
      "stop after",
    );
    expect(seen).toEqual([true]);
    expect(hasIngestReservation(store.casesRoot, "c1")).toBe(false);

    const end = beginArchive(store.casesRoot, "c1")!;
    await expect(ingestVeloArtifactMap("c1", "{}", { label: "m.json", idBase: "m" })).rejects.toBeInstanceOf(
      CaseArchivingError,
    );
    await expect(ingestVeloUploads("c1", [], { label: "u" })).rejects.toBeInstanceOf(CaseArchivingError);
    end();
    expect(persist).toHaveBeenCalledOnce();
  });
});

describe("Velociraptor hunt collect", () => {
  it("holds a reservation for the whole pass, and while an archive holds the case skips it, logs why and re-arms the status poll", async () => {
    const root = "/cases-hunt";
    const log = vi.fn();
    const reschedule = vi.fn();
    const status = { value: "open" };
    const admitted = createHuntCollectAdmission(
      { casesRoot: root, getCaseMeta: async () => ({ status: status.value }) } as never,
      log,
      reschedule,
    );

    let reservedDuring = false;
    await admitted("c1", "H.1", async () => {
      reservedDuring = hasIngestReservation(root, "c1");
    });
    expect(reservedDuring).toBe(true);
    expect(hasIngestReservation(root, "c1")).toBe(false);

    const end = beginArchive(root, "c1")!;
    const collect = vi.fn(async () => {});
    await admitted("c1", "H.1", collect);
    end();
    expect(collect).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/hunt H\.1 deferred: .*being archived/));
    expect(reschedule).toHaveBeenCalledWith("c1", "H.1");

    // The archive moved the case (removeFromList): a later pass must not write into the archived
    // folder after its zip, and is not re-armed.
    status.value = "archived";
    reschedule.mockClear();
    await admitted("c1", "H.1", collect);
    expect(collect).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/hunt H\.1 skipped: .*archived/));
    expect(reschedule).not.toHaveBeenCalled();
  });
});

describe("MCP and external-tool routes", () => {
  async function app() {
    const root = await mkdtemp(join(tmpdir(), "dfir-1920-routes-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const a = createApp(store, { stateStore });
    await request(a).post("/cases").send({ caseId: "c1", name: "n", investigator: "i" });
    return { app: a, store };
  }

  it("refuse every MCP write and a tool run with 409 while an archive holds the case", async () => {
    const { app: a, store } = await app();
    const end = beginArchive(store.casesRoot, "c1")!;
    const writes = [
      request(a).post("/cases/c1/mcp/srv/run").send({ tool: "t", args: {} }),
      request(a).post("/cases/c1/mcp/srv/run-upload").send({}),
      request(a).post("/cases/c1/mcp/preview/j1/import").send({}),
      request(a).delete("/cases/c1/mcp/preview/j1"),
      request(a).post("/cases/c1/mcp/agent").send({}),
      request(a).post("/cases/c1/mcp/agent-upload").send({}),
      request(a).post("/cases/c1/tools/hayabusa/run").send({ path: "x" }),
      request(a).post("/cases/c1/tools/hayabusa/run-upload").send({}),
    ];
    const results = await Promise.all(writes);
    end();
    expect(results.map((r) => r.status)).toEqual(Array(writes.length).fill(409));
    // Reads, and a rule update that touches no case data, are not reserved.
    expect((await request(a).get("/cases/c1/mcp/reports")).status).not.toBe(409);
  });

  it("an MCP request holds the case against an archive until its response closes", async () => {
    const { app: a, store } = await app();
    const res = await request(a).post("/cases/c1/mcp/srv/run").send({ tool: "t", args: {} });
    expect(res.status).not.toBe(409);
    await new Promise((r) => setTimeout(r, 10));
    expect(hasIngestReservation(store.casesRoot, "c1")).toBe(false);
  });
});
