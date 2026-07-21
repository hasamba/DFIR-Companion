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

// Captures the hunt VQL so tests can assert exactly what `spec=dict(...)` was launched with.
const launched: string[] = [];

const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("artifact_definitions()")) {
    return { rows: [
      { name: "Windows.EventLogs.Evtx", description: "Event logs", type: "CLIENT",
        parameters: [{ name: "DateAfter", type: "timestamp" }, { name: "DateBefore", type: "timestamp" }] },
      { name: "Windows.Forensics.Shellbags", description: "Shellbags", type: "CLIENT",
        parameters: [{ name: "UserRegex", type: "string" }] },
    ], raw: "" };
  }
  if (p.includes("hunt(") && p.includes("artifacts=[")) { launched.push(p); return { rows: [{ Hunt: { HuntId: "H.TS1", state: "RUNNING" } }], raw: "" }; }
  return { rows: [], raw: "" };
};

async function makeApp(runnerOverride: VqlRunner = runner) {
  const root = await mkdtemp(join(tmpdir(), "dfir-veloscope-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const artifactBundleStore = new ArtifactBundleStore(join(dirname(root), `bundles-${Date.now()}`));
  const app = createApp(store, {
    pipeline, stateStore, importMetaStore: new ImportMetaStore(store),
    velociraptorClient: new VelociraptorClient(veloCfg, runnerOverride),
    artifactBundleStore, veloHuntStore: new VeloHuntStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await request(app).post("/bundles").send({
    id: "scoped-test", name: "Scoped Test",
    artifacts: ["Windows.EventLogs.Evtx", "Windows.Forensics.Shellbags"],
  });
  return app;
}

describe("bundle time scope — preview", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  beforeEach(async () => { launched.length = 0; app = await makeApp(); });

  it("reports which artifacts get scoped and which collect in full", async () => {
    const res = await request(app).post("/velociraptor/bundles/scoped-test/time-scope-preview").send({ preset: "30d" });
    expect(res.status).toBe(200);
    expect(res.body.scoped).toEqual([
      { artifact: "Windows.EventLogs.Evtx", startParam: "DateAfter", endParam: "DateBefore", source: "detected" },
    ]);
    expect(res.body.unscoped).toEqual([{ artifact: "Windows.Forensics.Shellbags", source: "none" }]);
    expect(res.body.degraded).toBe(false);
    expect(typeof res.body.scope.start).toBe("string");
    expect(res.body.scope.end).toBeUndefined();   // relative preset: no upper bound
  });

  it("honours a saved per-bundle correction", async () => {
    await request(app).post("/bundles").send({
      id: "scoped-test", name: "Scoped Test",
      artifacts: ["Windows.EventLogs.Evtx", "Windows.Forensics.Shellbags"],
      timeScopeParamNames: { "Windows.EventLogs.Evtx": { start: "EarliestTime" } },
    });
    const res = await request(app).post("/velociraptor/bundles/scoped-test/time-scope-preview").send({ preset: "7d" });
    expect(res.body.scoped[0]).toEqual({ artifact: "Windows.EventLogs.Evtx", startParam: "EarliestTime", source: "correction" });
  });

  it("rejects an invalid custom range with the reason", async () => {
    const res = await request(app).post("/velociraptor/bundles/scoped-test/time-scope-preview")
      .send({ start: "2026-06-30T00:00:00Z", end: "2026-06-01T00:00:00Z" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/end must be at or after start/);
  });

  it("404s for an unknown bundle and 400s when no scope is given", async () => {
    expect((await request(app).post("/velociraptor/bundles/nope/time-scope-preview").send({ preset: "7d" })).status).toBe(404);
    expect((await request(app).post("/velociraptor/bundles/scoped-test/time-scope-preview").send({})).status).toBe(400);
  });

  it("reports degraded:true through the route when the server has no parameter metadata for any bundle artifact", async () => {
    // Same two artifact names as the default runner, but the server reports NO parameter metadata for
    // either — the real-world case where a server's artifact_definitions() lookup is blind (e.g. a
    // stripped/older catalog), so auto-detection can't run at all. That's a distinct, worse failure mode
    // than "this one artifact has no date parameter" and the UI renders it as its own warning.
    const noMetaRunner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("artifact_definitions()")) {
        return { rows: [
          { name: "Windows.EventLogs.Evtx", description: "Event logs", type: "CLIENT", parameters: [] },
          { name: "Windows.Forensics.Shellbags", description: "Shellbags", type: "CLIENT", parameters: [] },
        ], raw: "" };
      }
      return { rows: [], raw: "" };
    };
    const degradedApp = await makeApp(noMetaRunner);
    const res = await request(degradedApp).post("/velociraptor/bundles/scoped-test/time-scope-preview").send({ preset: "30d" });
    expect(res.status).toBe(200);
    expect(res.body.degraded).toBe(true);
    expect(res.body.scoped).toEqual([]);
    expect(res.body.unscoped.map((u: { artifact: string }) => u.artifact).sort()).toEqual(
      ["Windows.EventLogs.Evtx", "Windows.Forensics.Shellbags"].sort(),
    );
  });
});
