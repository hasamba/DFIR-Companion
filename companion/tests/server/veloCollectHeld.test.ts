import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { privateBundleDir } from "../helpers/bundleDir.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";

// #2753: a bundle hunt's artifact over the size limits is stored but not imported until the analyst
// chooses Import anyway, which starts a fresh collect. Synthetic data only.

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 4 * 1024 * 1024,
  guiUrl: "https://velo.example/",
};

const pstreeRow = (i: number, client: string) => ({
  Name: "rundll32.exe",
  Pid: 4000 + i,
  CommandLine: `rundll32.exe C:\\Users\\Public\\payload${i}.dll,Start`,
  Timestamp: "2026-06-01T10:00:00Z",
  ClientId: client,
  Fqdn: client === "C.0000000000000001" ? "ws-alpha.example.test" : "ws-bravo.example.test",
});
// One PC sends 40 rows (about 6 KB), the other one row.
const ROWS = [
  ...Array.from({ length: 40 }, (_, i) => pstreeRow(i, "C.0000000000000001")),
  pstreeRow(99, "C.0000000000000002"),
];

const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("artifact_definitions()"))
    return {
      rows: [{ name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" }],
      raw: "",
    };
  if (p.includes("hunt(") && p.includes("artifacts="))
    return { rows: [{ Hunt: { HuntId: "H.HELD1", state: "RUNNING" } }], raw: "" };
  if (p.includes("hunt_results(") && p.includes("Pstree")) return { rows: ROWS, raw: "" };
  return { rows: [], raw: "" };
};

afterEach(() => {
  delete process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB;
  delete process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB;
});

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-held-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    ...{ provider: undefined, synthesisProvider: undefined, stateStore, store },
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    ...{ pipeline, stateStore, jobManager: new JobManager({ perCaseConcurrency: 1 }) },
    serverClients: veloServerClients(new VelociraptorClient(veloCfg, runner)),
    artifactBundleStore: new ArtifactBundleStore(privateBundleDir(root)),
    veloHuntStore: new VeloHuntStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, drop: join(store.caseDir("c1"), "drop") };
}

type App = Awaited<ReturnType<typeof makeApp>>["app"];

async function collected(app: App): Promise<void> {
  await pollFor("the hunt collect to finish", async () => {
    const jobs = (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body as Array<{
      status?: string;
      collectActive?: boolean;
    }>;
    if (jobs[0]?.status === "error") throw new Error("collect errored");
    return jobs[0]?.status === "imported" && !jobs[0]?.collectActive ? true : undefined;
  });
}

const pstreeEvents = async (stateStore: StateStore): Promise<number> =>
  (await stateStore.load("c1")).forensicTimeline.filter((e) => /payload\d+\.dll/.test(e.description)).length;

const HELD = "_held/H.HELD1/Generic.System.Pstree.json";

describe("bundle hunt — artifacts over the size limits (#2753, #2755)", () => {
  it(
    "saves a held artifact in drop/_held/; Import anyway moves it into drop/ and later collects import it",
    async () => {
      process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.002"; // about 2 KB per PC
      process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0";
      const { app, stateStore, drop } = await makeApp();
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);
      await collected(app);
      expect(await pstreeEvents(stateStore)).toBe(0); // held: not imported
      const saved = await readFile(join(drop, ...HELD.split("/")), "utf8");
      expect(saved.trim().split("\n")).toHaveLength(41); // every downloaded row, one per line

      const listed = (await request(app).get("/cases/c1/drop/held")).body.files;
      expect(listed).toEqual([
        expect.objectContaining({
          rel: HELD,
          origin: "hunt",
          huntId: "H.HELD1",
          reason: "host",
          host: "ws-alpha.example.test",
        }),
      ]);
      const res = await request(app)
        .post("/cases/c1/drop/held/decide")
        .send({ decisions: [{ rel: HELD, decision: "import" }] });
      expect(res.body.moved).toEqual([{ rel: HELD, to: "H.HELD1/Generic.System.Pstree.json" }]);
      expect(existsSync(join(drop, "H.HELD1", "Generic.System.Pstree.json"))).toBe(true); // the drop sweep imports it

      await request(app).post("/cases/c1/velociraptor/collect"); // a later collect follows the decision
      await collected(app);
      expect(await pstreeEvents(stateStore)).toBeGreaterThan(0);
    },
    POLL_TIMEOUT_MS * 3,
  );

  it(
    "Skip moves the held file to _skipped/, and later collects leave the artifact out even when it fits",
    async () => {
      process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.002";
      const { app, stateStore, drop } = await makeApp();
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      await request(app).post("/cases/c1/velociraptor/collect");
      await collected(app);
      const res = await request(app)
        .post("/cases/c1/drop/held/decide")
        .send({ decisions: [{ rel: HELD, decision: "skip" }] });
      expect(res.body.moved[0].to).toBe("_skipped/H.HELD1/Generic.System.Pstree.json");
      expect(existsSync(join(drop, "_skipped", "H.HELD1", "Generic.System.Pstree.json"))).toBe(true);
      process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0";
      await request(app).post("/cases/c1/velociraptor/collect");
      await collected(app);
      expect(await pstreeEvents(stateStore)).toBe(0);
    },
    POLL_TIMEOUT_MS * 3,
  );

  it(
    "0 turns the limits off: the artifact imports on the first collect",
    async () => {
      process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0";
      process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0";
      const { app, stateStore, drop } = await makeApp();
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      await request(app).post("/cases/c1/velociraptor/collect");
      await collected(app);
      expect(await pstreeEvents(stateStore)).toBeGreaterThan(0);
      expect(existsSync(join(drop, "_held"))).toBe(false);
    },
    POLL_TIMEOUT_MS * 3,
  );
});
