import { describe, it, expect } from "vitest";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { privateBundleDir } from "../helpers/bundleDir.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import {
  createImportMemoryGuard,
  type ImportAdmission,
  type ImportAdmissionHint,
} from "../../src/analysis/importMemoryGuard.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #1874 item 4. The Velociraptor hunt collect and the external hunt/flow ingest used to store their
// fetched rows INSIDE the import section, so they could pass the memory guard no size hint: a refusal
// there would have dropped rows fetched from the server. They now store every artifact and upload as
// case evidence first, then ask the guard with a size. This file pins both halves: a refusal keeps
// the evidence and tells the analyst, and the guard sees how big the import is.

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

const PSTREE_ROWS = [
  {
    Name: "rundll32.exe",
    Pid: 4321,
    CommandLine: "rundll32.exe C:\\Users\\Public\\payload.dll,Start",
    Timestamp: "2026-06-01T10:00:00Z",
  },
  {
    Name: "powershell.exe",
    Pid: 4400,
    CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
    Timestamp: "2026-06-01T10:01:00Z",
  },
];

function huntRunner(rows: unknown[]): VqlRunner {
  return async (statements) => {
    const p = statements[0];
    if (p.includes("artifact_definitions()"))
      return {
        rows: [{ name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" }],
        raw: "",
      };
    if (p.includes("hunt(") && p.includes("artifacts="))
      return { rows: [{ Hunt: { HuntId: "H.GUARD1", state: "RUNNING" } }], raw: "" };
    if (p.includes("hunt_results(") && p.includes("Pstree")) return { rows, raw: "" };
    return { rows: [], raw: "" };
  };
}

/**
 * The real guard, fed a machine with no memory to spare, so its refusal carries the real wording.
 * `refuse` flips it to admitting, the way an analyst freeing memory does. Every hint is recorded.
 */
function recordingAdmission(): ImportAdmission & { refuse: boolean; hints: ImportAdmissionHint[] } {
  const starved = createImportMemoryGuard({
    countEvents: async () => 50_000,
    probe: () => ({ availableBytes: 0, rssBytes: 0, heapLimitBytes: 1024 ** 4 }),
  });
  const self = {
    refuse: true,
    hints: [] as ImportAdmissionHint[],
    async admit(caseId: string, hint?: ImportAdmissionHint): Promise<() => void> {
      self.hints.push(hint ?? {});
      if (self.refuse) return starved.admit(caseId, hint);
      return () => {};
    },
  };
  return self;
}

async function makeCollectApp(rows: unknown[] = PSTREE_ROWS) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-guard-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const admission = recordingAdmission();
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
    importMetaStore,
    superTimelineStore: new SuperTimelineStore(store),
    jobManager: new JobManager({ perCaseConcurrency: 1 }),
    importLock: new ImportLock(admission),
    velociraptorClient: new VelociraptorClient(veloCfg, huntRunner(rows)),
    artifactBundleStore: new ArtifactBundleStore(privateBundleDir(root)),
    veloHuntStore: new VeloHuntStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await request(app)
    .post("/cases/c1/velociraptor/run-bundle")
    .send({ bundleId: "best-practice", waitMinutes: 30 });
  return { app, store, stateStore, importMetaStore, admission };
}

type HuntJobView = { status?: string; error?: string; collectActive?: boolean };

async function collectAndSettle(
  app: Awaited<ReturnType<typeof makeCollectApp>>["app"],
): Promise<HuntJobView> {
  expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);
  let last: HuntJobView = {};
  await pollFor(
    () => `the collect to finish, last saw ${JSON.stringify(last)}`,
    async () => {
      const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
      last = (jobs.body as HuntJobView[])[0] ?? {};
      return last.collectActive === false && (last.status === "imported" || last.status === "error")
        ? true
        : undefined;
    },
  );
  return last;
}

async function storedEvidence(store: CaseStore, prefix: RegExp): Promise<string[]> {
  return (await readdir(store.importsDir("c1")).catch(() => [] as string[])).filter((f) => prefix.test(f));
}

/** The case's evidence audit log (imports.jsonl): one line per stored file. */
async function auditLines(store: CaseStore): Promise<string[]> {
  const text = await readFile(store.importsLogPath("c1"), "utf8").catch(() => "");
  return text.split("\n").filter(Boolean);
}

describe("a hunt collect asks the import memory guard only after its rows are evidence (#1874)", () => {
  it(
    "keeps every fetched row as evidence when the guard refuses, and shows why on the hunt card",
    async () => {
      const { app, store, stateStore, importMetaStore, admission } = await makeCollectApp();
      const job = await collectAndSettle(app);

      expect(job.status).toBe("error");
      expect(job.error).toMatch(/Import refused to protect the server/);
      expect(job.error).toMatch(/saved in the case/);
      expect(job.error).toMatch(/Collect now/); // the retry path for a hunt, not "import the file again"
      // The rows fetched from Velociraptor are stored, with their audit line, before the refusal.
      expect(await storedEvidence(store, /velo-hunt_H\.GUARD1_Generic\.System\.Pstree\.json$/)).toHaveLength(
        1,
      );
      expect(await auditLines(store)).toEqual([expect.stringMatching(/velo-hunt_H\.GUARD1_Generic/)]);
      // Nothing else changed.
      expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
      expect((await importMetaStore.load("c1")).lastImportKind).toBeFalsy();
      // The guard was asked with the hunt's row count.
      expect(admission.hints).toEqual([expect.objectContaining({ incomingEvents: PSTREE_ROWS.length })]);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "imports on Collect now once the guard admits it",
    async () => {
      const { app, stateStore, importMetaStore, admission } = await makeCollectApp();
      expect((await collectAndSettle(app)).status).toBe("error");

      admission.refuse = false;
      const job = await collectAndSettle(app);
      expect(job.status).toBe("imported");
      expect((await stateStore.load("c1")).forensicTimeline.length).toBeGreaterThan(0);
      expect((await importMetaStore.load("c1")).lastImportKind).toBe("velociraptor");
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "imports exactly as before when admitted, with the hint sized by the rows",
    async () => {
      const { app, store, stateStore, importMetaStore, admission } = await makeCollectApp();
      admission.refuse = false;
      const job = await collectAndSettle(app);
      expect(job.status).toBe("imported");
      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.length).toBeGreaterThan(0);
      const meta = await importMetaStore.load("c1");
      expect(meta.addedCount).toBe(state.forensicTimeline.length);
      // One evidence file for the one artifact that returned rows, named after it, as before.
      const files = await storedEvidence(store, /velo-hunt_H\.GUARD1_/);
      expect(files).toHaveLength(1);
      expect(meta.lastImportFile).toBe(files[0]);
      expect(admission.hints).toEqual([expect.objectContaining({ incomingEvents: PSTREE_ROWS.length })]);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "never asks the guard when the hunt returned nothing to import",
    async () => {
      const { app, admission } = await makeCollectApp([]);
      const job = await collectAndSettle(app);
      expect(job.status).toBe("imported"); // a no-op collect is not refused
      expect(admission.hints).toEqual([]); // the section is still taken, unsized: no admission
    },
    POLL_TIMEOUT_MS * 2,
  );
});

// ── The external hunt/flow import ────────────────────────────────────────────────────────────────

const MFT_ROW = { OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "évil.exe" };
const THOR_LINE = JSON.stringify({
  time: "2025-03-14T21:18:18Z",
  hostname: "WIN11",
  level: "Alert",
  module: "Filescan",
  message: "Malware file found — ünïcode",
  file: "C:\\Tools\\mimikatz.exe",
  sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
});

async function makeExternalApp(uploads: { name: string; clientId: string; content: string }[] = []) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-guard-ext-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const admission = recordingAdmission();
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const rows = [MFT_ROW, { ...MFT_ROW, OSPath: "C:\\evil2.exe" }, { ...MFT_ROW, OSPath: "C:\\evil3.exe" }];
  const client = {
    async getHuntArtifacts() {
      return ["Windows.NTFS.MFT"];
    },
    async huntArtifactRows() {
      return { rows, total: rows.length, truncated: false };
    },
    huntGuiUrlFor: (h: string) => `https://velo.example/#/hunts/${h}`,
    flowGuiUrlFor: () => undefined,
    async huntUploads() {
      return uploads;
    },
    async flowUploads() {
      return uploads;
    },
  };
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore: new SuperTimelineStore(store),
    jobManager: new JobManager({ perCaseConcurrency: 1 }),
    importLock: new ImportLock(admission),
    velociraptorClient: client as unknown as NonNullable<
      Parameters<typeof createApp>[1]
    >["velociraptorClient"],
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, admission, rows };
}

const UPLOADS_URL = "https://velo.example/app/index.html?org_id=root#/hunts/H.EXT/uploads";

describe("the external Velociraptor import asks the guard only after its rows are evidence (#1874)", () => {
  it("keeps the artifact as evidence when refused, and says so with a 503", async () => {
    const { app, store, stateStore, admission, rows } = await makeExternalApp();
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.EXT" });
    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/Import refused to protect the server/);
    expect(res.body.error).toMatch(/link again/);
    expect(await storedEvidence(store, /velo-hunt_H\.EXT_Windows\.NTFS\.MFT\.json$/)).toHaveLength(1);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
    expect(admission.hints).toEqual([expect.objectContaining({ incomingEvents: rows.length })]);
  });

  it("imports as before when admitted", async () => {
    const { app, store, stateStore, admission } = await makeExternalApp();
    admission.refuse = false;
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.EXT" });
    expect(res.status).toBe(200);
    expect(res.body.addedEvents).toBeGreaterThan(0);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBeGreaterThan(0);
    expect(await storedEvidence(store, /velo-hunt_H\.EXT_/)).toHaveLength(1);
  });

  it("keeps uploaded reports as evidence when refused, sized in UTF-8 bytes", async () => {
    const { app, store, stateStore, admission } = await makeExternalApp([
      { name: "thor.json", clientId: "C.1", content: THOR_LINE },
    ]);
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: UPLOADS_URL });
    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/Import refused to protect the server/);
    expect(await storedEvidence(store, /_thor\.json$/)).toHaveLength(1);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
    expect(admission.hints).toEqual([
      expect.objectContaining({ incomingBytes: Buffer.byteLength(THOR_LINE, "utf8") }),
    ]);
  });

  it("imports uploaded reports as before when admitted", async () => {
    const { app, stateStore, admission } = await makeExternalApp([
      { name: "thor.json", clientId: "C.1", content: THOR_LINE },
    ]);
    admission.refuse = false;
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: UPLOADS_URL });
    expect(res.status).toBe(200);
    expect(res.body.imported).toEqual(["thor.json"]);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBeGreaterThan(0);
  });

  it("does not refuse uploads it would not import anyway", async () => {
    const { app, admission } = await makeExternalApp([
      { name: "notes.bin", clientId: "C.1", content: "\u0000\u0001 not a report" },
    ]);
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: UPLOADS_URL });
    expect(res.status).toBe(200);
    expect(res.body.skipped).toEqual(["notes.bin"]);
    expect(admission.hints).toEqual([]); // taken unsized — nothing to size, nothing to refuse
  });
});
