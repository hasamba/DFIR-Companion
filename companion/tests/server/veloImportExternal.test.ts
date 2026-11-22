import { describe, it, expect } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { ImportUndoStore, emptyUndoStack, pushCheckpoint } from "../../src/analysis/importUndo.js";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VelociraptorRunResult,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { veloServerClients, stubServerClients } from "../helpers/serverClientsStub.js";

// The import-external route only calls four VelociraptorClient methods: getHuntArtifacts +
// huntResultsByArtifact for a hunt ref, getFlowInfo + collectionResults for a flow ref. A hand-rolled
// mock (cast to the client type, like superTimeline.test.ts's CapturingVeloClient) exercises the route
// without spawning the real binary. One MFT-like row maps to ≥1 forensic event through the velociraptor
// importer — the same shape the super-only bundle test uses.
const MFT_ROW = { OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" };

// A YARA hit is a real detection verdict → the velociraptor importer grades it High (unlike the
// ungraded Info MFT telemetry row), so a mix of the two is a graded import the min-severity floor
// can discriminate on. `_Source` names the source artifact, which drives classification.
const YARA_ROW = {
  _Source: "Windows.Detection.Yara",
  Rule: "EvilRule",
  Namespace: "n",
  OSPath: "C:\\bad.dll",
  Created0x10: "2026-06-01T01:00:00Z",
};

// A THOR scanner report line — the shape of an UPLOADED report file (not a row), used to exercise the
// uploads-only import path (ref.isUploadsUrl).
const THOR_LINE = JSON.stringify({
  time: "2025-03-14T21:18:18Z",
  hostname: "WIN11",
  level: "Alert",
  module: "Filescan",
  message: "Malware file found",
  file: "C:\\Tools\\mimikatz.exe",
  sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
});

const FLOW_META = {
  clientId: "C.123",
  flowId: "F.XYZ",
  state: "FINISHED",
  rows: 1,
  created: 1,
  started: 2,
  active: 3,
  results: [] as string[],
};

interface MockVeloClient {
  sourceNamespace(): string;
  huntFlowMeta(huntId: string): Promise<(typeof FLOW_META)[] | undefined>;
  flowMeta(clientId: string, flowId: string): Promise<(typeof FLOW_META)[] | undefined>;
  getHuntArtifacts(huntId: string): Promise<string[]>;
  huntResultsByArtifact(
    huntId: string,
    artifacts: string[],
  ): Promise<{ results: Record<string, unknown[]>; skipped: string[] }>;
  // The import path reads ONE artifact at a time so a large hunt is never resident in full.
  huntArtifactRows(
    huntId: string,
    artifact: string,
  ): Promise<VelociraptorRunResult & { sourcesUnknown?: true }>;
  getFlowInfo(clientId: string, flowId: string): Promise<{ artifacts: string[]; hostname: string }>;
  collectionResults(clientId: string, flowId: string, artifact: string): Promise<VelociraptorRunResult>;
  huntGuiUrlFor(huntId: string): string | undefined;
  flowGuiUrlFor(clientId: string, flowId: string): string | undefined;
  huntUploads(huntId: string): Promise<{ name: string; clientId: string; content: string }[]>;
  flowUploads(
    clientId: string,
    flowId: string,
  ): Promise<{ name: string; clientId: string; content: string }[]>;
}

async function makeApp(
  huntResults: Record<string, unknown[]> = { "Windows.NTFS.MFT": [MFT_ROW] },
  uploads: { name: string; clientId: string; content: string }[] = [],
  sourcesUnknown: string[] = [], // artifacts whose source list the catalog could not give (#1645)
  truncated: string[] = [], // artifacts whose read hits the row cap (#2700)
  withUndo = false, // give the app an import undo store (#2700: Undo forgets the re-import ledger)
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-ext-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });

  const undoStore = new ImportUndoStore(store);
  const importMetaStore = new ImportMetaStore(store);
  // One import at a time per case — the production setting. The external import is an import
  // like any other, so it takes the case's slot and shows in the Background jobs popover (#1428).
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  let rowsFetchCalls = 0;
  let metaRows = 1;
  let lookupCalls = 0; // getHuntArtifacts / getFlowInfo: the first Velociraptor call of a row import
  const client: MockVeloClient = {
    async getHuntArtifacts() {
      lookupCalls++;
      return Object.keys(huntResults);
    },
    async huntResultsByArtifact() {
      rowsFetchCalls++;
      return { results: huntResults, skipped: [] };
    },
    async huntArtifactRows(_huntId: string, artifact: string) {
      rowsFetchCalls++;
      const rows = huntResults[artifact] ?? [];
      const unknown = sourcesUnknown.includes(artifact) ? { sourcesUnknown: true as const } : {};
      return { rows, total: rows.length, truncated: truncated.includes(artifact), ...unknown };
    },
    // #2700: the server's per-flow state — one finished flow listing every artifact, `metaRows` rows.
    sourceNamespace: () => "test-server|root",
    async huntFlowMeta() {
      const results = Object.keys(huntResults);
      return [{ ...FLOW_META, rows: metaRows, results }];
    },
    async flowMeta() {
      return [{ ...FLOW_META, rows: metaRows, results: ["Windows.NTFS.MFT"] }];
    },
    async getFlowInfo() {
      lookupCalls++;
      return { artifacts: ["Windows.NTFS.MFT"], hostname: "DESKTOP-01" };
    },
    async collectionResults() {
      rowsFetchCalls++;
      // A row with NO host column — the route must attribute it to the flow's resolved hostname.
      return { rows: [MFT_ROW], total: 1, truncated: false };
    },
    huntGuiUrlFor(huntId: string) {
      return `https://velo.example/app/index.html?org_id=root#/hunts/${huntId}`;
    },
    flowGuiUrlFor(clientId: string, flowId: string) {
      return `https://velo.example/app/index.html?org_id=root#/collected/${clientId}/${flowId}`;
    },
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
    superTimelineStore,
    importMetaStore,
    jobManager,
    serverClients: veloServerClients(client),
    ...(withUndo ? { importUndoStore: undoStore } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return {
    app,
    store,
    stateStore,
    pipeline,
    importMetaStore,
    jobManager,
    getRowsFetchCalls: () => rowsFetchCalls,
    getLookupCalls: () => lookupCalls,
    undoStore,
    setServerRows: (n: number) => {
      metaRows = n;
    },
  };
}

// The same app with NO Velociraptor client — the "API not configured" gate. Every branch of this route
// fetches from the server (getHuntArtifacts/huntResultsByArtifact/getFlowInfo/collectionResults/*Uploads),
// so the gate is load-bearing, not incidental.
async function makeUnconfiguredApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-ext-off-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
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
    superTimelineStore,
    serverClients: stubServerClients({}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return app;
}

describe("POST /cases/:id/velociraptor/import-external", () => {
  // This route LOOKS like an offline import ("import" + a body you POST), but the body is a hunt/flow
  // REFERENCE, not an export — the rows are fetched from the server. An analyst holding a colleague's
  // export reads a bare "not configured" as a pointless gate, so the 501 must name what it would contact
  // and hand them the genuinely offline route (POST /cases/:id/import-velociraptor).
  it("501s naming the server it would contact, and points at the offline import route", async () => {
    const app = await makeUnconfiguredApp();
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(501);
    expect(res.body.error).toMatch(/server set/);
    expect(res.body.error).toMatch(/fetches/i); // says it makes an outbound call
    expect(res.body.error).toMatch(/import-velociraptor/); // names the offline alternative
  });

  it("400s on an unparseable ref", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "junk" });
    expect(res.status).toBe(400);
  });

  it("400s on a notebook URL instead of silently importing the flow's complete raw rows", async () => {
    // A notebook URL shows the analyst's own filtered VQL results — this server can only pull the
    // flow's complete raw collection (a much larger, differently-scoped row set), so it must refuse
    // rather than silently import the wrong data (#notebook regression).
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/collected/C.dead/F.001/notebook" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/notebook/i);
    expect(res.body.error).toMatch(/extension/i);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0); // nothing imported
  });

  it("imports an external hunt into the forensic timeline", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);
    expect(res.body.kind).toBe("hunt");
    expect(res.body.addedEvents).toBeGreaterThan(0);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBeGreaterThan(0);
  });

  it("stamps veloUrl on FORENSIC-timeline hunt events too, not just the super-only path (#7 regression)", async () => {
    // Bug: the super-only branch stamped veloUrl on every event, but the normal (forensic-timeline-
    // bound) branch dropped it entirely when calling pipeline.importVelociraptor — so a plain hunt/flow
    // import never carried a veloUrl and the forensic timeline's "↗ Velociraptor" link never rendered.
    const { app, stateStore } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);
    const forensic = (await stateStore.load("c1")).forensicTimeline;
    expect(forensic.length).toBeGreaterThan(0);
    expect(
      forensic.every((e) => e.veloUrl === "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC"),
    ).toBe(true);
  });

  // #1645 — the external import used to read only `.rows`, so an artifact whose named sources were
  // never read showed as "the hunt returned no rows yet".
  it("names an artifact not read in full, and never says the hunt returned no rows", async () => {
    const { app, stateStore } = await makeApp(
      { "Windows.System.TaskScheduler": [] },
      [],
      ["Windows.System.TaskScheduler"],
    );
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);
    expect(res.body.artifacts).toEqual([]); // imported, not requested
    expect(res.body.requestedArtifacts).toEqual(["Windows.System.TaskScheduler"]);
    expect(res.body.unreadArtifacts).toEqual([{ name: "Windows.System.TaskScheduler", rows: 0 }]);
    expect(res.body.note).not.toMatch(/returned no rows/);
    expect(res.body.note).toMatch(/not read in full/);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
  });

  it("imports the rows it did read and still names the artifact partly read", async () => {
    const { app, stateStore } = await makeApp(
      { "Windows.NTFS.MFT": [MFT_ROW], "Windows.System.TaskScheduler": [] },
      [],
      ["Windows.NTFS.MFT", "Windows.System.TaskScheduler"],
    );
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);
    expect(res.body.artifacts).toEqual(["Windows.NTFS.MFT"]);
    expect(res.body.addedEvents).toBeGreaterThan(0);
    expect(res.body.unreadArtifacts).toEqual([
      { name: "Windows.NTFS.MFT", rows: 1 },
      { name: "Windows.System.TaskScheduler", rows: 0 },
    ]);
    expect(res.body.note).toBeUndefined();
    // #1651: the rows it did read are stamped, so they never count as full coverage of their class.
    const mft = (await stateStore.load("c1")).forensicTimeline;
    expect(mft.length).toBeGreaterThan(0);
    for (const e of mft) expect(e.partlyReadArtifact).toBe("Windows.NTFS.MFT");
  });

  it("stamps a partly read artifact's rows on the super-only path too (#1651)", async () => {
    const { app } = await makeApp({ "Windows.NTFS.MFT": [MFT_ROW] }, [], ["Windows.NTFS.MFT"]);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true });
    expect(res.status).toBe(200);
    const rows = (await request(app).get("/cases/c1/super-timeline")).body.events as Array<{
      partlyReadArtifact?: string;
    }>;
    expect(rows.length).toBeGreaterThan(0);
    for (const e of rows) expect(e.partlyReadArtifact).toBe("Windows.NTFS.MFT");
  });

  it("still says 'no rows yet' when every read was complete and empty", async () => {
    const { app } = await makeApp({ "Windows.NTFS.MFT": [] });
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.body.note).toBe("the hunt returned no rows yet");
    expect(res.body.artifacts).toEqual([]);
    expect(res.body.unreadArtifacts).toBeUndefined();
  });

  it("imports an external flow attributing events to the resolved host", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "C.dead/F.001" });
    expect(res.status).toBe(200);
    expect(res.body.kind).toBe("flow");
    expect(res.body.hostname).toBe("DESKTOP-01");
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.asset === "DESKTOP-01")).toBe(true);
  });

  it("routes a super-timeline-only external hunt to the super-timeline, not forensic", async () => {
    const { app, stateStore } = await makeApp();
    const before = (await stateStore.load("c1")).forensicTimeline.length;
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true });
    expect(res.status).toBe(200);
    // The response reports the SUPER-TIMELINE count (not the always-0 forensic diff) so the UI shows a
    // real "+N events" rather than the misleading "+0".
    expect(res.body.addedEvents).toBeGreaterThan(0);
    expect((await request(app).get("/cases/c1/super-timeline")).body.total).toBe(res.body.addedEvents);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBe(before);
  });

  it("applies the min-severity floor on the super-only path (drops the below-floor event)", async () => {
    // Mixed graded import: a High YARA detection + an Info telemetry row IN THE SAME ARTIFACT. With
    // minSeverity:high the super-only path must keep ONLY the High event — the floor the forensic path
    // applies via importVelociraptor must hold here too (regression: super-only ignored it silently).
    //
    // Both rows sit in one artifact deliberately. The floor is gate-aware (severityFloor.ts): an
    // all-Info batch imports whole, because a feed with no verdicts has nothing to discriminate on. The
    // import now streams ONE ARTIFACT AT A TIME, so "the batch" is an artifact rather than the whole
    // hunt — the same granularity the bundle collector has always used. Splitting these two rows across
    // two artifacts would therefore test the gate, not the floor.
    const { app } = await makeApp({ "Windows.Detection.Yara": [YARA_ROW, MFT_ROW] });
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true, minSeverity: "high" });
    expect(res.status).toBe(200);
    const st = (await request(app).get("/cases/c1/super-timeline")).body;
    const sevs = (st.events as Array<{ severity: string }>).map((e) => e.severity);
    expect(sevs).toContain("High");
    expect(sevs.some((s) => s === "Info" || s === "Low")).toBe(false); // below-floor row filtered out
  });

  it("keeps every event on the super-only path when no floor is set (floor is a no-op)", async () => {
    // Same mixed import, NO minSeverity → both events land (the floor must not silently drop anything
    // when unset, so default super-only imports are unchanged).
    const { app } = await makeApp({ "Windows.Detection.Yara": [YARA_ROW], "Windows.NTFS.MFT": [MFT_ROW] });
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true });
    expect(res.status).toBe(200);
    const st = (await request(app).get("/cases/c1/super-timeline")).body;
    const sevs = (st.events as Array<{ severity: string }>).map((e) => e.severity);
    expect(sevs).toContain("High");
    expect(sevs).toContain("Info");
  });

  it("does NOT aggregate rows on the super-only path (the super-timeline is the complete record)", async () => {
    // Three MFT rows that would collapse to one aggregated event on the forensic path must stay as
    // three distinct super-timeline events (only differing in path). (Regression: 221 rows → 141.)
    const rows = [
      { OSPath: "C:\\a\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" },
      { OSPath: "C:\\b\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" },
      { OSPath: "C:\\c\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" },
    ];
    const { app } = await makeApp({ "Windows.NTFS.MFT": rows });
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true });
    expect(res.status).toBe(200);
    expect(res.body.addedEvents).toBe(3);
    expect((await request(app).get("/cases/c1/super-timeline")).body.total).toBe(3);
  });

  it("stamps veloUrl (the GUI deep-link) on super-only hunt events (#8)", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true });
    expect(res.status).toBe(200);
    const st = (await request(app).get("/cases/c1/super-timeline")).body;
    expect(st.events.length).toBeGreaterThan(0);
    expect(
      st.events.every(
        (e: { veloUrl?: string }) =>
          e.veloUrl === "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC",
      ),
    ).toBe(true);
  });

  it("stamps veloUrl on super-only flow events using the flow deep-link (#8)", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "C.dead/F.001", superTimelineOnly: true });
    expect(res.status).toBe(200);
    const st = (await request(app).get("/cases/c1/super-timeline")).body;
    expect(st.events.length).toBeGreaterThan(0);
    expect(
      st.events.every(
        (e: { veloUrl?: string }) =>
          e.veloUrl === "https://velo.example/app/index.html?org_id=root#/collected/C.dead/F.001",
      ),
    ).toBe(true);
  });

  it("uploads-tab hunt URL imports ONLY the uploaded THOR report, skipping rows entirely", async () => {
    const { app, stateStore, getRowsFetchCalls } = await makeApp({ "Windows.NTFS.MFT": [MFT_ROW] }, [
      { name: "thor.json", clientId: "C.1", content: THOR_LINE },
    ]);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads" });
    expect(res.status).toBe(200);
    expect(res.body.kind).toBe("hunt");
    expect(res.body.uploadsOnly).toBe(true);
    expect(res.body.imported).toEqual(["thor.json"]);
    expect(res.body.addedEvents).toBeGreaterThan(0);
    expect(getRowsFetchCalls()).toBe(0); // rows were never fetched on the uploads-only path
    const forensic = (await stateStore.load("c1")).forensicTimeline;
    expect(forensic.some((e) => e.description?.toLowerCase().includes("mimikatz"))).toBe(true);
  });

  // #2831: an uploaded report can be a large Velociraptor export, imported in batches. What its
  // cap passes pushed out of the super-timeline is on the import record, also when the import
  // changed nothing in the forensic timeline — here, a second import of the same report.
  it("uploads-tab URL: records the raw rows an uploaded report's batched import pushed out", async () => {
    const dropped = { count: 9, setAside: 1, from: "2025-01-01T00:00:00Z", to: "2025-01-02T00:00:00Z" };
    const content = JSON.stringify([{ ...MFT_ROW, _Source: "Windows.NTFS.MFT" }]);
    const { app, pipeline, importMetaStore } = await makeApp({}, [
      { name: "Windows.NTFS.MFT.json", clientId: "C.1", content },
    ]);
    const realVelo = pipeline.importVelociraptor.bind(pipeline);
    let imports = 0;
    pipeline.importVelociraptor = async (...args) => {
      const state = await realVelo(...args);
      if (++imports === 2) args[2].onSuperEvicted?.(dropped); // what a batched run reports once it committed
      return state;
    };
    const run = () =>
      request(app)
        .post("/cases/c1/velociraptor/import-external")
        .send({ ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads" });

    expect((await run()).status).toBe(200);
    const first = await importMetaStore.load("c1");
    expect(first.addedCount).toBe(1);
    expect(first.superTimelineEvicted?.count ?? 0).toBe(0);

    expect((await run()).status).toBe(200);
    expect(imports).toBe(2);
    const second = await importMetaStore.load("c1");
    expect(second.lastImportFile).not.toBe(first.lastImportFile);
    expect(second.addedCount).toBe(0);
    expect(second.superTimelineEvicted).toEqual(dropped);
  });

  it("uploads-tab flow URL imports via flowUploads, skipping rows", async () => {
    const { app, getRowsFetchCalls } = await makeApp({}, [
      { name: "thor.json", clientId: "C.dead", content: THOR_LINE },
    ]);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/collected/C.dead/F.001/uploads" });
    expect(res.status).toBe(200);
    expect(res.body.kind).toBe("flow");
    expect(res.body.uploadsOnly).toBe(true);
    expect(res.body.addedEvents).toBeGreaterThan(0);
    expect(getRowsFetchCalls()).toBe(0);
  });

  it("uploads-tab URL with no matching uploads returns a note instead of an error", async () => {
    const { app } = await makeApp({ "Windows.NTFS.MFT": [MFT_ROW] }, []);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads" });
    expect(res.status).toBe(200);
    expect(res.body.addedEvents).toBe(0);
    expect(res.body.note).toMatch(/no uploaded report files/i);
  });

  it("rejects combining an uploads-tab URL with superTimelineOnly", async () => {
    const { app } = await makeApp({}, [{ name: "thor.json", clientId: "C.1", content: THOR_LINE }]);
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({
      ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads",
      superTimelineOnly: true,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/super-timeline-only/i);
  });

  it("a normal (non-uploads-tab) hunt URL is unaffected — still rows-only", async () => {
    const { app, getRowsFetchCalls } = await makeApp({ "Windows.NTFS.MFT": [MFT_ROW] }, [
      { name: "thor.json", clientId: "C.1", content: THOR_LINE },
    ]);
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);
    expect(res.body.uploadsOnly).toBeUndefined();
    expect(getRowsFetchCalls()).toBe(1);
  });

  it("skips a generic CSV upload (AI-dependent kind) while AI is off for the case, but still imports the THOR upload alongside it", async () => {
    // makeApp's /cases POST sends aiProvider: null, so AiControlStore's default (enabled: false)
    // applies — the case has no AI configured, exactly the state ingestVeloUploads must respect.
    const csvUpload = {
      name: "scan.csv",
      clientId: "C.1",
      content: "PID,ProcessName\n1,evil.exe\n2,cmd.exe",
    };
    const thorUpload = { name: "thor.json", clientId: "C.1", content: THOR_LINE };
    const { app, stateStore } = await makeApp({}, [csvUpload, thorUpload]);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads" });
    expect(res.status).toBe(200);
    expect(res.body.imported).toEqual(["thor.json"]); // the CSV was skipped, not persisted/dispatched
    expect(res.body.skipped).toEqual(["scan.csv"]);
    const forensic = (await stateStore.load("c1")).forensicTimeline;
    expect(forensic.some((e) => e.description?.toLowerCase().includes("mimikatz"))).toBe(true);
  });

  it("uploads-tab URL with uploads present but none importable still reports a note (not silent)", async () => {
    // AI is off by default in this test's case setup (aiProvider: null), and this content matches no
    // recognizable import format — so it lands in `skipped` one way or another (unknown kind, or an
    // AI-dependent fallback kind while AI is off), leaving `imported` empty either way.
    const { app } = await makeApp({}, [
      { name: "mystery.bin", clientId: "C.1", content: "\x00\x01\x02 not a recognizable report format" },
    ]);
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads" });
    expect(res.status).toBe(200);
    expect(res.body.imported).toEqual([]);
    expect(res.body.note).toBeTruthy();
  });
});

// ── a MULTI-SOURCE artifact in an external flow ────────────────────────────────────────────────
// End-to-end over the REAL VelociraptorClient (a VqlRunner stands in for the binary), because the
// regression this pins lived in the client's own name validation, which a hand-rolled mock cannot
// reproduce. Velociraptor reports a multi-source artifact's results one source at a time, in the
// `Artifact/Source` form — so getFlowInfo() returns "Generic.Scanner.ThorZIP/ThorResultsJson" and
// hands it straight to collectionResults(). Rejecting the slash there dropped the artifact behind a
// per-artifact log line: on a live case the entire THOR scan vanished while the flow's 17
// single-source artifacts imported normally, and the import still reported success.
// THOR's REAL row shape from Generic.Scanner.ThorZIP/ThorResultsJson. That source is literally
//   SELECT _value as Line FROM foreach(row=split(string=FileContent, sep="\n"))
// so each finding arrives as ONE JSON document held in an opaque `Line` string. A row like this has
// no timestamp, host or severity of its own until the payload is unwrapped: it mapped to an undated
// Info event that the default Low forensic floor then dropped, so the import "succeeded" and the
// THOR alert still never appeared.
const THOR_ROW = {
  Line: JSON.stringify({
    time: "2025-12-05T03:26:42Z",
    hostname: "WIN-CASEHOST7",
    level: "Alert",
    module: "Filescan",
    message: "Malware file found",
    file: "C:\\Tools\\mimikatz.exe",
    sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
  }),
};

async function makeRealClientApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-multisrc-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const cfg: VelociraptorApiConfig = {
    apiConfigPath: "/tmp/api.config.yaml",
    binary: "velociraptor",
    timeoutMs: 5000,
    maxRows: 100,
    maxOutputBytes: 1 << 20,
  };
  const asked: string[] = [];
  const runner: VqlRunner = async (statements) => {
    const p = statements[0];
    if (p.includes("FROM flows("))
      return {
        rows: [
          {
            artifacts_with_results: [
              "Generic.Scanner.ThorZIP/ThorExec",
              "Generic.Scanner.ThorZIP/ThorResultsJson",
            ],
          },
        ],
        raw: "",
      };
    if (p.includes("FROM clients("))
      return {
        rows: [{ client_id: "C.14f7b543888d1fbe", os_info: { hostname: "WIN-CASEHOST7" } }],
        raw: "",
      };
    if (p.includes("FROM source(")) {
      const m = /artifact='([^']+)'/.exec(p);
      if (m) asked.push(m[1]);
      return { rows: p.includes("ThorResultsJson") ? [THOR_ROW] : [], raw: "" };
    }
    return { rows: [], raw: "" };
  };
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore,
    serverClients: veloServerClients(new VelociraptorClient(cfg, runner)),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, asked };
}

describe("POST /cases/:id/velociraptor/import-external — multi-source artifacts", () => {
  it("imports a source-qualified artifact from a flow instead of dropping it", async () => {
    const { app, stateStore, asked } = await makeRealClientApp();
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({
      ref: "https://10.0.0.162:8889/app/index.html?org_id=root#/collected/C.14f7b543888d1fbe/F.DA2A4A9E0J2PK.H/results",
    });
    expect(res.status).toBe(200);
    // The qualified refs reached the query verbatim — not rejected as an invalid artifact name.
    expect(asked).toContain("Generic.Scanner.ThorZIP/ThorResultsJson");
    expect(asked).toContain("Generic.Scanner.ThorZIP/ThorExec");
    // …and the source that had rows is reported as imported, not silently absent.
    expect(res.body.artifacts).toContain("Generic.Scanner.ThorZIP/ThorResultsJson");
    // The payload's own fields survive. Without the unwrap this is an undated, host-less Info row
    // carrying the raw JSON as text, and the default Low forensic floor drops it entirely.
    const state = await stateStore.load("c1");
    const thor = state.forensicTimeline.find((e) => e.description.includes("Malware file found"));
    expect(thor).toBeDefined();
    expect(thor?.severity).toBe("Critical"); // graded from THOR's own level: "Alert"
    expect(thor?.timestamp).toContain("2025-12-05"); // its own time, not the collection time
    expect(thor?.asset).toBe("WIN-CASEHOST7");
    expect(thor?.sha256).toBe("4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef");
    // …and the scanned path is extracted as evidence rather than left inside an opaque string.
    expect(state.iocs.some((i) => i.value === "C:\\Tools\\mimikatz.exe")).toBe(true);
  });
});

// Codex review, P1. The hunt and flow branches read EVERY artifact into one object and then stringified
// a second full copy of it. Under the 1,000-row dashboard cap that was survivable; at the 100,000-row
// collection cap a multi-artifact hunt can hold millions of rows and take the process down — the same
// heap exhaustion the bundle collector was rewritten to avoid, reintroduced by raising the cap.
//
// Streaming per artifact is not directly observable from a response, but its consequence is: each
// artifact is read, ingested and released on its own, so one artifact that fails to read no longer
// takes the rest of the collection with it.
describe("POST /cases/:id/velociraptor/import-external — one artifact at a time", () => {
  it("persists and ingests each artifact on its own, never the whole hunt at once", async () => {
    const { app, stateStore, root } = await makeStreamingApp();
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "https://velo.example/app/index.html#/hunts/H.STREAM1" });
    expect(res.status).toBe(200);

    // One evidence file per artifact — the proof that only one artifact's rows were ever held at once.
    // A single combined `velo-hunt_H.STREAM1.json` means the route buffered the entire hunt.
    const files = await readdir(join(root, "c1", "imports"));
    const named = files.filter((f) => f.includes("A.alpha") || f.includes("A.gamma"));
    expect(named).toHaveLength(2);
    expect(files.some((f) => /velo-hunt_H\.STREAM1\.json$/.test(f))).toBe(false);

    // ...and the readable artifacts still landed, with the failed one not taking them down.
    const descs = (await stateStore.load("c1")).forensicTimeline.map((e) => e.description).join(" | ");
    expect(descs).toContain("alpha");
    expect(descs).toContain("gamma");
  });
});

async function makeStreamingApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-stream-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const cfg: VelociraptorApiConfig = {
    apiConfigPath: "/tmp/api.config.yaml",
    binary: "velociraptor",
    timeoutMs: 5000,
    maxRows: 100,
    maxOutputBytes: 1 << 20,
  };
  const runner: VqlRunner = async (statements) => {
    const p = statements[0];
    if (p.includes("FROM hunts("))
      return { rows: [{ artifacts: ["A.alpha", "A.beta", "A.gamma"] }], raw: "" };
    if (p.includes("FROM artifact_definitions(")) return { rows: [], raw: "" };
    if (p.includes("hunt_results(")) {
      if (p.includes("A.beta")) throw new Error("output exceeded 1048576 bytes");
      const name = p.includes("A.alpha") ? "alpha" : "gamma";
      return { rows: [{ Message: `finding ${name}`, Timestamp: "2026-06-01T10:00:00Z" }], raw: "" };
    }
    return { rows: [], raw: "" };
  };
  const app = createApp(store, {
    pipeline,
    stateStore,
    serverClients: veloServerClients(new VelociraptorClient(cfg, runner)),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, root };
}

// The gate at its new granularity, pinned deliberately rather than left to be rediscovered. Streaming
// per artifact means an UNGRADED artifact (all-Info telemetry: MFT, USN, Prefetch) is judged on its own
// and imports whole even under a floor, instead of being filtered because some other artifact in the
// same hunt happened to carry a verdict. This matches how the bundle collector has always behaved; the
// floor itself is still enforced inside a graded artifact (see the super-only floor test above).
describe("POST /cases/:id/velociraptor/import-external — the severity gate is per artifact", () => {
  it("keeps an all-Info artifact under a High floor — it has no verdicts to discriminate on", async () => {
    const { app } = await makeApp({ "Windows.NTFS.MFT": [MFT_ROW] });
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true, minSeverity: "high" });
    expect(res.status).toBe(200);
    const st = (await request(app).get("/cases/c1/super-timeline")).body;
    expect((st.events as unknown[]).length).toBe(1);
  });
});

// The external import used to be a bare request: no job, no slot, no progress. The dashboard showed
// "importing…" for as long as the request ran — minutes on a big flow — with no bar, no jobs chip
// and no way to tell a slow import from a stuck one (#1428). It is an import like any other now.
describe("POST /cases/:id/velociraptor/import-external — runs as a Background job", () => {
  it("leaves a succeeded import job with per-artifact progress for a hunt", async () => {
    const { app, jobManager } = await makeApp({
      "Windows.Detection.Yara": [YARA_ROW],
      "Windows.NTFS.MFT": [MFT_ROW],
    });
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);
    const job = jobManager.list("c1").find((j) => j.kind === "import");
    expect(job?.status).toBe("succeeded");
    expect(job?.label).toContain("H.ABC");
    expect(job?.progress).toEqual({ done: 2, total: 2 });
  });

  it("does the same for a flow", async () => {
    const { app, jobManager } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "C.abc/F.DEF" });
    expect(res.status).toBe(200);
    const job = jobManager.list("c1").find((j) => j.kind === "import");
    expect(job?.status).toBe("succeeded");
    expect(job?.label).toContain("F.DEF");
    expect(job?.progress).toEqual({ done: 1, total: 1 });
  });

  // Same reason the bundle collect takes the slot: it writes the timeline the dashboard's own
  // imports write to, and two writers at once corrupt each other's "+N events" and undo checkpoints.
  it("waits for the case's import slot before writing anything", async () => {
    const { app, stateStore, jobManager } = await makeApp();
    const blocker = jobManager.register({ caseId: "c1", kind: "enrichment", label: "holds the slot" });
    await blocker.durable;
    const pending = request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    await new Promise((r) => setTimeout(r, 50));
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
    await jobManager.finish(blocker.jobId);
    expect((await pending).status).toBe(200);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBeGreaterThan(0);
  });
});

// #1965: a second paste of the same hunt or flow re-read every row (up to the 100,000-row cap) under
// the case's import slot, only to dedup to "+0 events". The route now answers 409 with what is
// already in the case, before any Velociraptor call, unless the analyst chose "Re-import anyway".
describe("POST /cases/:id/velociraptor/import-external — already imported (#1965)", () => {
  type App = Awaited<ReturnType<typeof makeApp>>["app"];
  const post = (app: App, body: Record<string, unknown>) =>
    request(app).post("/cases/c1/velociraptor/import-external").send(body);

  // #2700: the 409 now says which artifacts need importing, so it looks the hunt up (metadata only)
  // — still no row is read.
  it("answers 409 for a hunt already in the case, with no row read", async () => {
    const { app, getRowsFetchCalls } = await makeApp();
    expect((await post(app, { ref: "H.ABC" })).status).toBe(200);
    const reads = getRowsFetchCalls();

    const again = await post(app, { ref: "H.ABC" });
    expect(again.status).toBe(409);
    expect(again.body.alreadyImported).toMatchObject({
      kind: "hunt",
      huntId: "H.ABC",
      artifacts: ["Windows.NTFS.MFT"],
    });
    expect(typeof again.body.alreadyImported.firstImportedAt).toBe("string");
    expect(getRowsFetchCalls()).toBe(reads);
  });

  it("reads and imports as today when the request says reimport: true", async () => {
    const { app, getRowsFetchCalls } = await makeApp();
    await post(app, { ref: "H.ABC" });
    const reads = getRowsFetchCalls();
    const again = await post(app, { ref: "H.ABC", reimport: true });
    expect(again.status).toBe(200);
    expect(again.body.alreadyImported).toBeUndefined();
    expect(getRowsFetchCalls()).toBeGreaterThan(reads);
  });

  it("only a literal true re-imports — a truthy string does not", async () => {
    const { app } = await makeApp();
    await post(app, { ref: "H.ABC" });
    expect((await post(app, { ref: "H.ABC", reimport: "yes" })).status).toBe(409);
  });

  it("answers 409 for a flow already in the case, and reimport: true reads it again", async () => {
    const { app, getRowsFetchCalls } = await makeApp();
    expect((await post(app, { ref: "C.123/F.XYZ" })).status).toBe(200);
    const reads = getRowsFetchCalls();
    const again = await post(app, { ref: "C.123/F.XYZ" });
    expect(again.status).toBe(409);
    expect(again.body.alreadyImported).toMatchObject({ kind: "flow", flowId: "F.XYZ" });
    expect(getRowsFetchCalls()).toBe(reads);
    expect((await post(app, { ref: "C.123/F.XYZ", reimport: true })).status).toBe(200);
    expect(getRowsFetchCalls()).toBeGreaterThan(reads);
  });

  it("does not hold back a different hunt in the same case", async () => {
    const { app } = await makeApp();
    await post(app, { ref: "H.ABC" });
    expect((await post(app, { ref: "H.DEF" })).status).toBe(200);
  });

  // A hunt the Companion collected itself ("Collect now") stores its rows under the same label, so
  // pasting that hunt afterwards warns too. That is correct: the rows are already in the case.
  it("warns for a hunt that a bundle collect already brought in", async () => {
    const { app, store } = await makeApp();
    await store.appendImport("c1", {
      caseId: "c1",
      sequenceNumber: 1,
      importedAt: "2026-10-01T00:00:00.000Z",
      filename: "0001_velo-hunt_H.BUNDLE_Windows.System.Pslist.json",
      originalName: "velo-hunt_H.BUNDLE_Windows.System.Pslist.json",
      rows: 0,
      bytes: 2,
    });
    const res = await post(app, { ref: "H.BUNDLE" });
    expect(res.status).toBe(409);
    expect(res.body.alreadyImported.artifacts).toEqual(["Windows.System.Pslist"]);
  });

  it("leaves the uploads path alone: an uploads URL for an imported hunt still imports", async () => {
    const { app } = await makeApp({ "Windows.NTFS.MFT": [MFT_ROW] }, [
      { name: "thor.jsonl", clientId: "C.1", content: THOR_LINE },
    ]);
    await post(app, { ref: "H.ABC" });
    const res = await post(app, {
      ref: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC/uploads",
    });
    expect(res.status).toBe(200);
    expect(res.body.uploadsOnly).toBe(true);
  });
});

// #2700: a re-import reads only the artifacts that are new, changed or were not read in full.
describe("POST /cases/:id/velociraptor/import-external — only what changed (#2700)", () => {
  type App = Awaited<ReturnType<typeof makeApp>>["app"];
  const post = (app: App, body: Record<string, unknown>) =>
    request(app).post("/cases/c1/velociraptor/import-external").send(body);
  const TWO = { "Windows.NTFS.MFT": [MFT_ROW], "Windows.Detection.Yara": [YARA_ROW] };

  it("the 409 names the cut-short artifact, and 'changed' re-reads only it", async () => {
    const { app, getRowsFetchCalls } = await makeApp(TWO, [], [], ["Windows.Detection.Yara"]);
    expect((await post(app, { ref: "H.ABC" })).status).toBe(200);
    const again = await post(app, { ref: "H.ABC" });
    expect(again.status).toBe(409);
    expect(again.body.alreadyImported).toMatchObject({
      toImport: [{ name: "Windows.Detection.Yara", reason: "truncated" }],
      upToDate: ["Windows.NTFS.MFT"],
      requested: ["Windows.NTFS.MFT", "Windows.Detection.Yara"],
    });
    const reads = getRowsFetchCalls();
    const changed = await post(app, { ref: "H.ABC", reimport: "changed" });
    expect(changed.status).toBe(200);
    expect(getRowsFetchCalls()).toBe(reads + 1);
    expect(changed.body.upToDate).toEqual(["Windows.NTFS.MFT"]);
    expect(changed.body.requestedArtifacts).toEqual(["Windows.NTFS.MFT", "Windows.Detection.Yara"]);
  });

  it("'changed' with everything up to date reads nothing and says so", async () => {
    const { app, getRowsFetchCalls } = await makeApp();
    await post(app, { ref: "H.ABC" });
    const reads = getRowsFetchCalls();
    const res = await post(app, { ref: "H.ABC", reimport: "changed" });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ kind: "hunt", huntId: "H.ABC", artifacts: [], addedEvents: 0 });
    expect(res.body.note).toMatch(/up to date/);
    expect(getRowsFetchCalls()).toBe(reads);
  });

  it("an artifact the server holds more rows for since is re-read", async () => {
    const { app, setServerRows } = await makeApp();
    await post(app, { ref: "H.ABC" });
    setServerRows(5);
    const again = await post(app, { ref: "H.ABC" });
    expect(again.body.alreadyImported.toImport).toEqual([{ name: "Windows.NTFS.MFT", reason: "changed" }]);
  });

  it("importing to a different destination re-reads the artifact", async () => {
    const { app } = await makeApp();
    await post(app, { ref: "H.ABC" });
    const again = await post(app, { ref: "H.ABC", superTimelineOnly: true });
    expect(again.body.alreadyImported.toImport).toEqual([{ name: "Windows.NTFS.MFT", reason: "settings" }]);
  });

  it("a flow re-import tracks its artifacts too", async () => {
    const { app, getRowsFetchCalls } = await makeApp();
    await post(app, { ref: "C.123/F.XYZ" });
    const reads = getRowsFetchCalls();
    const res = await post(app, { ref: "C.123/F.XYZ", reimport: "changed" });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ kind: "flow", flowId: "F.XYZ", hostname: "DESKTOP-01", artifacts: [] });
    expect(getRowsFetchCalls()).toBe(reads);
  });

  it("Undo forgets the record, so the next re-import reads the artifact again", async () => {
    const { app, undoStore, stateStore } = await makeApp(undefined, [], [], [], true);
    await post(app, { ref: "H.ABC" });
    // One checkpoint to undo, whatever this app's import path records.
    const checkpoint = { label: "velo", at: new Date().toISOString(), state: await stateStore.load("c1") };
    await undoStore.save("c1", pushCheckpoint(emptyUndoStack(), checkpoint, 10, undoStore.byteBudget()));
    expect((await request(app).post("/cases/c1/import/undo")).status).toBe(200);
    const again = await post(app, { ref: "H.ABC" });
    expect(again.status).toBe(409); // the audit log still knows the hunt
    expect(again.body.alreadyImported.toImport).toEqual([{ name: "Windows.NTFS.MFT", reason: "no-record" }]);
  });
});
