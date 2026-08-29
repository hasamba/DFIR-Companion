import { describe, it, expect } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VelociraptorRunResult,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

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

interface MockVeloClient {
  getHuntArtifacts(huntId: string): Promise<string[]>;
  huntResultsByArtifact(
    huntId: string,
    artifacts: string[],
  ): Promise<{ results: Record<string, unknown[]>; skipped: string[] }>;
  // The import path reads ONE artifact at a time so a large hunt is never resident in full.
  huntArtifactRows(huntId: string, artifact: string): Promise<VelociraptorRunResult>;
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

  let rowsFetchCalls = 0;
  const client: MockVeloClient = {
    async getHuntArtifacts() {
      return Object.keys(huntResults);
    },
    async huntResultsByArtifact() {
      rowsFetchCalls++;
      return { results: huntResults, skipped: [] };
    },
    async huntArtifactRows(_huntId: string, artifact: string) {
      rowsFetchCalls++;
      const rows = huntResults[artifact] ?? [];
      return { rows, total: rows.length, truncated: false };
    },
    async getFlowInfo() {
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
    velociraptorClient: client as unknown as NonNullable<
      Parameters<typeof createApp>[1]
    >["velociraptorClient"],
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, getRowsFetchCalls: () => rowsFetchCalls };
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
  const app = createApp(store, { pipeline, stateStore, superTimelineStore });
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
    expect(res.body.error).toMatch(/DFIR_VELOCIRAPTOR_API_CONFIG/);
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
    velociraptorClient: new VelociraptorClient(cfg, runner),
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
    velociraptorClient: new VelociraptorClient(cfg, runner),
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
