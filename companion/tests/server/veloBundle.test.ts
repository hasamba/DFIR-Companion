import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

// A mock runner standing in for the velociraptor binary — branches on the orchestration VQL the
// client emits. The Pslist hunt returns one process row; Netstat returns nothing (not checked in yet).
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("artifact_definitions()")) {
    return { rows: [
      { name: "Windows.System.Pslist", description: "Running processes", type: "CLIENT" },
      { name: "Windows.Network.Netstat", description: "Network connections", type: "CLIENT" },
    ], raw: "" };
  }
  if (p.includes("hunt(") && p.includes("artifacts=[")) {
    return { rows: [{ Hunt: { HuntId: "H.TEST1", state: "RUNNING" } }], raw: "" };
  }
  if (p.includes("hunt_results(")) {
    if (p.includes("Pslist")) return { rows: [{ Name: "powershell.exe", Pid: 1234, CommandLine: "powershell -enc AAAA", Timestamp: "2026-06-01T10:00:00Z" }], raw: "" };
    return { rows: [], raw: "" };
  }
  return { rows: [], raw: "" };
};

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velobundle-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const artifactBundleStore = new ArtifactBundleStore(join(dirname(root), "bundles"));
  const veloHuntStore = new VeloHuntStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const app = createApp(store, {
    pipeline, stateStore, importMetaStore,
    velociraptorClient: new VelociraptorClient(veloCfg, runner),
    artifactBundleStore, veloHuntStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, store };
}

describe("Velociraptor triage bundles — routes", () => {
  let app: Awaited<ReturnType<typeof makeApp>>["app"];
  let stateStore: Awaited<ReturnType<typeof makeApp>>["stateStore"];

  beforeEach(async () => {
    const made = await makeApp();
    app = made.app;
    stateStore = made.stateStore;
  });

  it("GET /velociraptor/artifacts lists the server's CLIENT artifacts", async () => {
    const res = await request(app).get("/velociraptor/artifacts");
    expect(res.status).toBe(200);
    expect(res.body.artifacts.map((a: { name: string }) => a.name)).toContain("Windows.System.Pslist");
  });

  it("bundle CRUD: create, list, and delete a custom bundle", async () => {
    const create = await request(app).post("/bundles").send({ name: "My Triage", artifacts: ["Windows.System.Pslist"] });
    expect(create.status).toBe(201);
    expect(create.body.builtIn).toBe(false);

    const list = await request(app).get("/bundles");
    expect(list.body.some((b: { name: string }) => b.name === "My Triage")).toBe(true);
    expect(list.body.some((b: { id: string }) => b.id === "fast-triage")).toBe(true);

    expect((await request(app).delete(`/bundles/${create.body.id}`)).status).toBe(204);
    expect((await request(app).delete("/bundles/nope-xyz")).status).toBe(404);   // unknown custom id
  });

  it("built-in bundles are editable in place and resettable to the default", async () => {
    const edit = await request(app).post("/bundles").send({ id: "fast-triage", name: "Fast Triage (mine)", artifacts: ["Windows.System.Pslist", "Windows.Network.Netstat"] });
    expect(edit.status).toBe(201);
    expect(edit.body.builtIn).toBe(true);
    expect(edit.body.customized).toBe(true);

    let ft = (await request(app).get("/bundles")).body.find((b: { id: string }) => b.id === "fast-triage");
    expect(ft.name).toBe("Fast Triage (mine)");
    expect(ft.customized).toBe(true);

    expect((await request(app).delete("/bundles/fast-triage")).status).toBe(204);   // reset to default
    ft = (await request(app).get("/bundles")).body.find((b: { id: string }) => b.id === "fast-triage");
    expect(ft.name).toBe("Fast Triage");
    expect(ft.customized).toBe(false);
  });

  it("POST /bundles rejects a bundle with no artifacts", async () => {
    const res = await request(app).post("/bundles").send({ name: "Empty", artifacts: [] });
    expect(res.status).toBe(400);
  });

  it("run-bundle launches a hunt and persists a running job with a collect time", async () => {
    const run = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "fast-triage", waitMinutes: 30 });
    expect(run.status).toBe(202);
    expect(run.body.huntId).toBe("H.TEST1");
    expect(run.body.guiUrl).toContain("H.TEST1");
    expect(typeof run.body.collectAt).toBe("string");

    const job = (await request(app).get("/cases/c1/velociraptor/hunt-job")).body;
    expect(job.status).toBe("running");
    expect(job.huntId).toBe("H.TEST1");
    expect(job.artifacts).toContain("Windows.System.Pslist");
  });

  it("collect imports the hunt results into the timeline and marks the job imported", async () => {
    await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "fast-triage", waitMinutes: 30 });
    const col = await request(app).post("/cases/c1/velociraptor/collect");
    expect(col.status).toBe(202);

    let job: { status: string } | null = null;
    for (let i = 0; i < 100; i++) {
      job = (await request(app).get("/cases/c1/velociraptor/hunt-job")).body;
      if (job && (job.status === "imported" || job.status === "error")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(job?.status).toBe("imported");

    // The Pslist rows the mock hunt returned became forensic-timeline events.
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.length).toBeGreaterThan(0);
  });

  it("run-bundle is 501 when Velociraptor is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velobundle-noclient-"));
    const store = new CaseStore(root);
    const bare = createApp(store, {});   // no velociraptorClient / pipeline
    const res = await request(bare).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "fast-triage" });
    expect(res.status).toBe(501);
  });
});
