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
// client emits. The Pstree hunt returns one process row; other artifacts return nothing (not checked
// in yet). The upload VQL (hunt_flows/uploads/read_file) returns nothing here (covered by its own test).
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("artifact_definitions()")) {
    return { rows: [
      { name: "Windows.System.Pslist", description: "Running processes", type: "CLIENT" },
      { name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" },
    ], raw: "" };
  }
  if (p.includes("hunt(") && p.includes("artifacts=[")) {
    return { rows: [{ Hunt: { HuntId: "H.TEST1", state: "RUNNING" } }], raw: "" };
  }
  if (p.includes("hunt_results(")) {
    if (p.includes("Pstree")) return { rows: [{ Name: "powershell.exe", Pid: 1234, CommandLine: "powershell -enc AAAA", Timestamp: "2026-06-01T10:00:00Z" }], raw: "" };
    return { rows: [], raw: "" };
  }
  return { rows: [], raw: "" };
};

async function makeApp(runnerOverride: VqlRunner = runner) {
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
    velociraptorClient: new VelociraptorClient(veloCfg, runnerOverride),
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
    expect(list.body.some((b: { id: string }) => b.id === "best-practice")).toBe(true);

    expect((await request(app).delete(`/bundles/${create.body.id}`)).status).toBe(204);
    expect((await request(app).delete("/bundles/nope-xyz")).status).toBe(404);   // unknown custom id
  });

  it("built-in bundles are editable in place and resettable to the default", async () => {
    const edit = await request(app).post("/bundles").send({ id: "best-practice", name: "Best Practice (mine)", artifacts: ["Windows.System.Pslist", "Windows.Network.Netstat"] });
    expect(edit.status).toBe(201);
    expect(edit.body.builtIn).toBe(true);
    expect(edit.body.customized).toBe(true);

    let ft = (await request(app).get("/bundles")).body.find((b: { id: string }) => b.id === "best-practice");
    expect(ft.name).toBe("Best Practice (mine)");
    expect(ft.customized).toBe(true);

    expect((await request(app).delete("/bundles/best-practice")).status).toBe(204);   // reset to default
    ft = (await request(app).get("/bundles")).body.find((b: { id: string }) => b.id === "best-practice");
    expect(ft.name).toBe("Best Practice");
    expect(ft.customized).toBe(false);
  });

  it("POST /bundles rejects a bundle with no artifacts", async () => {
    const res = await request(app).post("/bundles").send({ name: "Empty", artifacts: [] });
    expect(res.status).toBe(400);
  });

  it("run-bundle launches a hunt and persists a running job with a collect time", async () => {
    const run = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });
    expect(run.status).toBe(202);
    expect(run.body.huntId).toBe("H.TEST1");
    expect(run.body.guiUrl).toContain("H.TEST1");
    expect(typeof run.body.collectAt).toBe("string");

    const jobs = (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    expect(jobs).toHaveLength(1);
    const job = jobs[0];
    expect(job.status).toBe("running");
    expect(job.huntId).toBe("H.TEST1");
    expect(job.artifacts).toContain("Generic.System.Pstree");
  });

  it("supports MULTIPLE concurrent hunts — a second run keeps the first", async () => {
    // two runs whose mock returns distinct hunt ids
    let n = 0;
    const multiRunner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=[")) { n += 1; return { rows: [{ Hunt: { HuntId: `H.MULTI${n}`, state: "RUNNING" } }], raw: "" }; }
      if (p.includes("hunt_results(")) return { rows: [], raw: "" };
      return { rows: [], raw: "" };
    };
    const made = await makeApp(multiRunner);
    await request(made.app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });
    await request(made.app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });
    const jobs = (await request(made.app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    const ids = jobs.map((j: { huntId: string }) => j.huntId);
    expect(ids).toContain("H.MULTI1");
    expect(ids).toContain("H.MULTI2");
    expect(jobs.every((j: { status: string }) => j.status === "running")).toBe(true);
  });

  it("collect imports the hunt results into the timeline and marks the job imported", async () => {
    await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });
    const col = await request(app).post("/cases/c1/velociraptor/collect");
    expect(col.status).toBe(202);

    let job: { status: string } | null = null;
    for (let i = 0; i < 100; i++) {
      job = (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body[0] ?? null;
      if (job && (job.status === "imported" || job.status === "error")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(job?.status).toBe("imported");

    // The Pstree rows the mock hunt returned became forensic-timeline events.
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.length).toBeGreaterThan(0);
  });

  it("stamps veloUrl on the FORENSIC timeline events a bundle collect produces, not just super-only imports (#7 regression)", async () => {
    // Bug: importVeloHuntResults computed the hunt's GUI deep-link only inside the superTimelineOnly
    // branch and never passed it to pipeline.importVelociraptor on the normal (forensic) branch — so a
    // plain triage-bundle collection (e.g. Best Practice) never carried a veloUrl and the forensic
    // timeline's "↗ Velociraptor" row link never rendered.
    await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });
    await request(app).post("/cases/c1/velociraptor/collect");
    let job: { status: string } | null = null;
    for (let i = 0; i < 100; i++) {
      job = (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body[0] ?? null;
      if (job && (job.status === "imported" || job.status === "error")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(job?.status).toBe("imported");
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.length).toBeGreaterThan(0);
    expect(state.forensicTimeline.every((e) => e.veloUrl === "https://velo.example/app/index.html?org_id=root#/hunts/H.TEST1")).toBe(true);
  });

  it("ingests an uploaded JSON report (THOR) from the hunt even when result rows are empty", async () => {
    const thorLine = JSON.stringify({
      time: "2025-03-14T21:18:18Z", hostname: "WIN11", level: "Alert", module: "Filescan",
      message: "Malware file found", file: "C:\\Tools\\mimikatz.exe",
      sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
    });
    const upRunner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.UP9", state: "RUNNING" } }], raw: "" };
      if (p.includes("hunt_results(")) return { rows: [], raw: "" };   // no result rows — only the upload matters
      if (p.includes("hunt_flows(") || p.includes("read_file(")) return { rows: [{ ClientId: "C.1", Path: "thor.json", Name: "thor.json", Content: thorLine }], raw: "" };
      return { rows: [], raw: "" };
    };
    const made = await makeApp(upRunner);
    await request(made.app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });
    expect((await request(made.app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

    let job: { status: string } | null = null;
    for (let i = 0; i < 100; i++) {
      job = (await request(made.app).get("/cases/c1/velociraptor/hunt-jobs")).body[0] ?? null;
      if (job && (job.status === "imported" || job.status === "error")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(job?.status).toBe("imported");
    // The uploaded THOR JSON was detected + imported into the timeline (rows were empty).
    const state = await made.stateStore.load("c1");
    expect(state.forensicTimeline.length).toBeGreaterThan(0);
  });

  it("collect records skipped (failed) and empty (no findings) artifacts on the job — so a bundle where most artifacts fail isn't silently indistinguishable from one where they simply found nothing", async () => {
    const mixedRunner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("artifact_definitions()")) {
        // All three bundle artifacts exist on the server (so the run-bundle pre-flight passes them
        // through); the DetectRaptor one still FAILS at collect time (too-large fetch) below — the
        // distinction this test asserts is collect-time skipped-vs-empty, not launch-time unknown.
        return { rows: [
          { name: "Windows.System.Pslist", description: "Running processes", type: "CLIENT" },
          { name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" },
          { name: "DetectRaptor.Windows.Detection.Amcache", description: "Amcache detections", type: "CLIENT" },
        ], raw: "" };
      }
      if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.MIX1", state: "RUNNING" } }], raw: "" };
      if (p.includes("hunt_results(")) {
        if (p.includes("Pstree")) return { rows: [{ Name: "powershell.exe", Pid: 1234, CommandLine: "powershell -enc AAAA", Timestamp: "2026-06-01T10:00:00Z" }], raw: "" };
        if (p.includes("Windows.Detection.Amcache") || p.includes("DetectRaptor")) throw new Error("output exceeded 1048576 bytes");
        return { rows: [], raw: "" };
      }
      return { rows: [], raw: "" };
    };
    const made = await makeApp(mixedRunner);
    // Edit the built-in bundle in place so it includes an artifact our mock throws on, alongside
    // one that returns rows and one that returns nothing — exercising all three outcomes at once.
    await request(made.app).post("/bundles").send({
      id: "best-practice", name: "Best Practice",
      artifacts: ["Generic.System.Pstree", "Windows.System.Pslist", "DetectRaptor.Windows.Detection.Amcache"],
    });
    await request(made.app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });
    expect((await request(made.app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

    let job: { status: string; skippedArtifacts?: { name: string; error: string }[]; emptyArtifacts?: string[] } | null = null;
    for (let i = 0; i < 100; i++) {
      job = (await request(made.app).get("/cases/c1/velociraptor/hunt-jobs")).body[0] ?? null;
      if (job && (job.status === "imported" || job.status === "error")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(job?.status).toBe("imported");
    expect(job?.skippedArtifacts).toEqual([{ name: "DetectRaptor.Windows.Detection.Amcache", error: "output exceeded 1048576 bytes" }]);
    expect(job?.emptyArtifacts).toEqual(["Windows.System.Pslist"]);
  });

  it("run-bundle is 501 when Velociraptor is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velobundle-noclient-"));
    const store = new CaseStore(root);
    const bare = createApp(store, {});   // no velociraptorClient / pipeline
    const res = await request(bare).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice" });
    expect(res.status).toBe(501);
  });
});

describe("Velociraptor hunt status polling — routes", () => {
  it("poll-status detects STOPPED and triggers an immediate collect", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.STOP1", state: "RUNNING" } }], raw: "" };
      if (p.includes("FROM hunts()")) return { rows: [{ state: "STOPPED" }], raw: "" };
      if (p.includes("hunt_results(")) return { rows: [{ Name: "cmd.exe", Timestamp: "2026-07-01T10:00:00Z" }], raw: "" };
      return { rows: [], raw: "" };
    };
    const made = await makeApp(runner);
    await request(made.app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });

    const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.STOP1/poll-status");
    expect(poll.status).toBe(200);

    // The poll triggered importVeloHuntResults in the background (fire-and-forget) — wait for it.
    let job: { status: string } | null = null;
    for (let i = 0; i < 100; i++) {
      job = (await request(made.app).get("/cases/c1/velociraptor/hunt-jobs")).body[0] ?? null;
      if (job && (job.status === "imported" || job.status === "error")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(job?.status).toBe("imported");
  });

  it("poll-status marks the job deleted when Velociraptor has no record of the hunt", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.DEL2", state: "RUNNING" } }], raw: "" };
      if (p.includes("FROM hunts()")) return { rows: [], raw: "" };   // hunt not found — deleted
      return { rows: [], raw: "" };
    };
    const made = await makeApp(runner);
    await request(made.app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });

    const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.DEL2/poll-status");
    expect(poll.status).toBe(200);
    expect(poll.body.status).toBe("deleted");

    const jobs = (await request(made.app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    expect(jobs[0].status).toBe("deleted");
  });

  it("poll-status marks the job unreachable when the Velociraptor query throws, without flipping it to deleted", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.UNR2", state: "RUNNING" } }], raw: "" };
      if (p.includes("FROM hunts()")) throw new Error("velociraptor process spawn failed");
      return { rows: [], raw: "" };
    };
    const made = await makeApp(runner);
    await request(made.app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "best-practice", waitMinutes: 30 });

    const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.UNR2/poll-status");
    expect(poll.status).toBe(200);
    expect(poll.body.status).toBe("unreachable");
  });

  it("poll-status is a 404 for an unknown hunt id", async () => {
    const made = await makeApp();
    const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.NOPE/poll-status");
    expect(poll.status).toBe(404);
  });

  it("poll-status is 501 when Velociraptor is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velobundle-noclient2-"));
    const store = new CaseStore(root);
    const bare = createApp(store, {});
    const res = await request(bare).post("/cases/c1/velociraptor/hunt-jobs/H.X/poll-status");
    expect(res.status).toBe(501);
  });
});
