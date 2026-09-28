import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { privateBundleDir } from "../helpers/bundleDir.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { VelociraptorClient, type VqlRunner } from "../../src/integrations/velociraptor/velociraptorApi.js";

// #1756 — one Windows.Hayabusa.Rules result imported through the native Hayabusa importer from the drop
// folder, but through the Velociraptor row mapper from a fleet pull. The same file then gave different
// event counts, severities and hosts. Every pull path must now land on the importer the drop folder
// picks. Rows mirror the real artifact's shape; values are lab-safe.

const HAYABUSA = "Windows.Hayabusa.Rules";
const CHAINSAW = "Windows.EventLogs.Chainsaw";

function hayabusaRow(
  title: string,
  level: string,
  recordId: number,
  detail: string,
): Record<string, unknown> {
  return {
    Timestamp: `2026-09-20T19:29:${String(recordId % 60).padStart(2, "0")}.000Z`,
    Computer: "WS-01",
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EID: "1",
    Level: level,
    Title: title,
    RecordID: String(recordId),
    Details: `Cmdline: ${detail} ¦ Proc: C:\\Users\\Public\\Sim\\helper.exe ¦ User: WS-01\\lab`,
    _Source: "Windows.Sigma.Base",
  };
}

// Same title, command lines that differ only by punctuation: the two importers key repeats
// differently, so the old split shows up as different counts.
const HAYABUSA_ROWS = [
  hayabusaRow("Renamed Helper Execution", "high", 1170, "helper.exe /d /c echo A-B"),
  hayabusaRow("Renamed Helper Execution", "high", 1171, "helper.exe /d /c echo A_B"),
  hayabusaRow("Renamed Helper Execution", "high", 1172, "helper.exe /d /c echo A.B"),
  hayabusaRow("Suspicious Encoded Command", "med", 1180, "powershell -enc QQBCAEMA"),
  hayabusaRow("Suspicious Encoded Command", "med", 1181, "powershell -enc QQBCAEQA"),
];

const CHAINSAW_ROWS = [
  {
    _Source: CHAINSAW,
    Timestamp: "2026-09-20T19:30:00Z",
    Detection: "Suspicious Service Install",
    Level: "high",
    Computer: "WS-01",
    EventID: 7045,
    Channel: "System",
  },
];

const HUNT_URL = "https://velo.example/app/index.html?org_id=root#/hunts/H.HAYA";
const FLOW_URL = "https://velo.example/app/index.html?org_id=root#/collected/C.lab/F.HAYA";

async function makeBase() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velohaya-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return { root, store, stateStore, pipeline, superTimelineStore: new SuperTimelineStore(store) };
}

async function newCase(app: Parameters<typeof request>[0], caseId: string): Promise<void> {
  await request(app).post("/cases").send({ caseId, name: "n", investigator: "i", aiProvider: null });
}

// The drop-folder path: the same bytes through auto-detect + dispatch.
async function importByDetect(
  app: Parameters<typeof request>[0],
  stateStore: StateStore,
  caseId: string,
  filename: string,
  rows: unknown[],
  artifact: string,
): Promise<ForensicEvent[]> {
  const res = await request(app)
    .post(`/cases/${caseId}/import`)
    .send({ filename, text: JSON.stringify({ [artifact]: rows }) });
  expect(res.status).toBe(202);
  return pollFor(`the ${caseId} detect import to land`, async () => {
    const s = await stateStore.load(caseId);
    return s.forensicTimeline.length > 0 ? s.forensicTimeline : undefined;
  });
}

// What an analyst compares between two cases: one row per event, in time order.
const shape = (events: ForensicEvent[]) =>
  events
    .map((e) => ({ t: e.timestamp, sev: e.severity, asset: e.asset, desc: e.description, src: e.sources }))
    .sort((a, b) => `${a.t}${a.desc}`.localeCompare(`${b.t}${b.desc}`));

// A mock client for the external-import route (hunt + flow refs).
function externalClient(results: Record<string, unknown[]>, partlyRead = false) {
  const read = (artifact: string) => {
    const rows = results[artifact] ?? [];
    return {
      rows,
      total: rows.length,
      truncated: false,
      ...(partlyRead ? { sourcesUnknown: true as const } : {}),
    };
  };
  return {
    async getHuntArtifacts() {
      return Object.keys(results);
    },
    async huntResultsByArtifact() {
      return { results, skipped: [] };
    },
    async huntArtifactRows(_huntId: string, artifact: string) {
      return read(artifact);
    },
    async getFlowInfo() {
      return { artifacts: Object.keys(results), hostname: "WS-01" };
    },
    async collectionResults(_clientId: string, _flowId: string, artifact: string) {
      return read(artifact);
    },
    huntGuiUrlFor: () => HUNT_URL,
    flowGuiUrlFor: () => FLOW_URL,
    async huntUploads() {
      return [];
    },
    async flowUploads() {
      return [];
    },
  };
}

async function makeExternalApp(results: Record<string, unknown[]>, partlyRead = false) {
  const base = await makeBase();
  const app = createApp(base.store, {
    pipeline: base.pipeline,
    stateStore: base.stateStore,
    superTimelineStore: base.superTimelineStore,
    velociraptorClient: externalClient(results, partlyRead) as unknown as NonNullable<
      Parameters<typeof createApp>[1]
    >["velociraptorClient"],
  });
  await newCase(app, "pull");
  await newCase(app, "drop");
  return { app, stateStore: base.stateStore };
}

describe("a Hayabusa result imports the same way on every path (#1756)", () => {
  it("external hunt import matches the drop-folder import of the same file", async () => {
    const { app, stateStore } = await makeExternalApp({ [HAYABUSA]: HAYABUSA_ROWS });
    const res = await request(app).post("/cases/pull/velociraptor/import-external").send({ ref: "H.HAYA" });
    expect(res.status).toBe(200);
    const pulled = (await stateStore.load("pull")).forensicTimeline;
    const dropped = await importByDetect(
      app,
      stateStore,
      "drop",
      `velo-hunt_H.HAYA_${HAYABUSA}.json`,
      HAYABUSA_ROWS,
      HAYABUSA,
    );
    expect(pulled.length).toBeGreaterThan(0);
    expect(pulled.every((e) => e.sources?.includes("Hayabusa"))).toBe(true);
    expect(shape(pulled)).toEqual(shape(dropped));
    expect(pulled.every((e) => e.veloUrl === HUNT_URL)).toBe(true); // the "↗ Velociraptor" link survives
  });

  it("external flow import keeps the flow link and the partly-read mark on the Hayabusa path", async () => {
    const { app, stateStore } = await makeExternalApp({ [HAYABUSA]: HAYABUSA_ROWS }, true);
    const res = await request(app)
      .post("/cases/pull/velociraptor/import-external")
      .send({ ref: "C.lab/F.HAYA" });
    expect(res.status).toBe(200);
    const pulled = (await stateStore.load("pull")).forensicTimeline;
    expect(pulled.length).toBeGreaterThan(0);
    for (const e of pulled) {
      expect(e.sources).toContain("Hayabusa");
      expect(e.veloUrl).toBe(FLOW_URL);
      expect(e.partlyReadArtifact).toBe(HAYABUSA);
      expect(e.asset).toMatch(/^WS-01/);
    }
  });

  it("a Chainsaw artifact stays on the Velociraptor importer (control)", async () => {
    const { app, stateStore } = await makeExternalApp({ [CHAINSAW]: CHAINSAW_ROWS });
    const res = await request(app).post("/cases/pull/velociraptor/import-external").send({ ref: "H.CHSW" });
    expect(res.status).toBe(200);
    const pulled = (await stateStore.load("pull")).forensicTimeline;
    expect(pulled.length).toBeGreaterThan(0);
    expect(pulled.some((e) => e.sources?.includes("Hayabusa"))).toBe(false);
  });

  it(
    "hunt collect matches the drop-folder import of the same file",
    async () => {
      const runner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("artifact_definitions()"))
          return { rows: [{ name: HAYABUSA, description: "Hayabusa", type: "CLIENT" }], raw: "" };
        if (p.includes("hunt(") && p.includes("artifacts=["))
          return { rows: [{ Hunt: { HuntId: "H.HAYA", state: "RUNNING" } }], raw: "" };
        if (p.includes("hunt_results(") && p.includes(HAYABUSA)) return { rows: HAYABUSA_ROWS, raw: "" };
        return { rows: [], raw: "" };
      };
      const base = await makeBase();
      const client = new VelociraptorClient(
        {
          apiConfigPath: "/x/api.yaml",
          binary: "velociraptor",
          timeoutMs: 5000,
          maxRows: 1000,
          maxOutputBytes: 1024 * 1024,
          guiUrl: "https://velo.example/",
        },
        runner,
      );
      const app = createApp(base.store, {
        pipeline: base.pipeline,
        stateStore: base.stateStore,
        importMetaStore: new ImportMetaStore(base.store),
        velociraptorClient: client,
        artifactBundleStore: new ArtifactBundleStore(privateBundleDir(base.root)),
        veloHuntStore: new VeloHuntStore(base.store),
      });
      await newCase(app, "pull");
      await newCase(app, "drop");
      await request(app)
        .post("/bundles")
        .send({ id: "haya", name: "Hayabusa", artifacts: [HAYABUSA] });
      await request(app)
        .post("/cases/pull/velociraptor/run-bundle")
        .send({ bundleId: "haya", waitMinutes: 30 });
      expect((await request(app).post("/cases/pull/velociraptor/collect")).status).toBe(202);
      await pollFor(
        () => "the hunt collect to finish",
        async () => {
          const job = (await request(app).get("/cases/pull/velociraptor/hunt-jobs")).body[0];
          return (job?.status === "imported" || job?.status === "error") && job.collectActive === false
            ? job
            : undefined;
        },
      );
      const pulled = (await base.stateStore.load("pull")).forensicTimeline;
      const dropped = await importByDetect(
        app,
        base.stateStore,
        "drop",
        `velo-hunt_H.HAYA_${HAYABUSA}.json`,
        HAYABUSA_ROWS,
        HAYABUSA,
      );
      expect(pulled.length).toBeGreaterThan(0);
      expect(pulled.every((e) => e.sources?.includes("Hayabusa"))).toBe(true);
      expect(shape(pulled)).toEqual(shape(dropped));
    },
    POLL_TIMEOUT_MS * 2,
  );
});
