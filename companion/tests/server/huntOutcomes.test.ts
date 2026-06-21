import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { HuntOutcomeStore } from "../../src/analysis/huntOutcomeStore.js";
import { recordDeploy, vqlFingerprint } from "../../src/analysis/huntOutcomes.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

// Mock velociraptor binary: launchHunt's program contains `hunt(...artifacts='...')` → return a hunt id;
// hunt_results(...) → one generic row so the collect imports an event (a "hit"). Everything else empty.
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts=")) return { rows: [{ Hunt: { HuntId: "H.DEPLOY1", state: "RUNNING" } }], raw: "" };
  if (p.includes("hunt_results(")) return { rows: [{ Message: "suspicious thing", Timestamp: "2026-06-01T10:00:00Z" }], raw: "" };
  return { rows: [], raw: "" };
};

async function makeApp(opts: { provider?: MockProvider; runner?: VqlRunner; withVelo?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-huntoutcomes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = opts.provider;
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const huntOutcomeStore = new HuntOutcomeStore(store);
  const app = createApp(store, {
    pipeline, stateStore,
    importMetaStore: new ImportMetaStore(store),
    veloHuntStore: new VeloHuntStore(store),
    huntOutcomeStore,
    aiConfigured: Boolean(provider),
    ...(opts.withVelo === false ? {} : { velociraptorClient: new VelociraptorClient(veloCfg, opts.runner ?? runner) }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: provider ? "mock" : null });
  return { app, stateStore, store, huntOutcomeStore };
}

describe("hunting feedback loop — routes (#157)", () => {
  it("deploy-hunt (fleet) launches a hunt and records a pending outcome", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/deploy-hunt")
      .send({ vql: "SELECT * FROM pslist()", title: "Hunt rogue processes", source: "fleet", mitreTechniques: ["T1059"] });
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe("hunt");
    expect(res.body.huntId).toBe("H.DEPLOY1");

    const profile = (await request(app).get("/cases/c1/hunt-outcomes")).body;
    expect(profile).toMatchObject({ total: 1, hit: 0, missed: 0, pending: 1 });
    expect(profile.hunts[0]).toMatchObject({ title: "Hunt rogue processes", source: "fleet", status: "deployed", huntId: "H.DEPLOY1" });
    expect(profile.hunts[0].vqlPreview).toContain("pslist");

    // It is also registered as a collectible hunt job (so "Collect now" works).
    const jobs = (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    expect(jobs.some((j: { huntId: string }) => j.huntId === "H.DEPLOY1")).toBe(true);
  });

  it("collecting a deployed hunt fills its outcome as a hit", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT * FROM pslist()", title: "ps hunt", source: "fleet" });
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.DEPLOY1" })).status).toBe(202);

    let hunt: { status: string; foundEvidence?: boolean } | undefined;
    for (let i = 0; i < 100; i++) {
      hunt = (await request(app).get("/cases/c1/hunt-outcomes")).body.hunts[0];
      if (hunt && hunt.status === "collected") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(hunt?.status).toBe("collected");
    expect(hunt?.foundEvidence).toBe(true);
    const profile = (await request(app).get("/cases/c1/hunt-outcomes")).body;
    expect(profile).toMatchObject({ hit: 1, pending: 0 });
  });

  it("deploy-hunt validates vql/title and collection-mode hostname", async () => {
    const { app } = await makeApp();
    expect((await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ title: "no vql" })).status).toBe(400);
    expect((await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT 1" })).status).toBe(400);
    expect((await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT 1", title: "t", mode: "collection" })).status).toBe(400);
  });

  it("deploy-hunt is 501 when Velociraptor is not configured", async () => {
    const { app } = await makeApp({ withVelo: false });
    const res = await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT 1", title: "t" });
    expect(res.status).toBe(501);
  });

  it("GET hunt-outcomes returns an empty profile for a fresh case", async () => {
    const { app } = await makeApp();
    expect((await request(app).get("/cases/c1/hunt-outcomes")).body).toEqual({ total: 0, hit: 0, missed: 0, pending: 0, hunts: [] });
  });

  it("suggest-hunts excludes a VQL that was already deployed", async () => {
    const vql = "SELECT FullPath FROM glob(globs='C:/inetpub/wwwroot/**/*.aspx')";
    const canned = JSON.stringify({ suggestions: [
      { title: "Hunt ASPX webshells", rationale: "spread", vql, severity: "High", mitreTechniques: ["T1505.003"], relatedFindingIds: ["f1"] },
    ] });
    const { app, stateStore, huntOutcomeStore } = await makeApp({ provider: new MockProvider("mock", canned) });

    const s = emptyState("c1");
    s.findings.push({ id: "f1", severity: "Critical", title: "Webshell", description: "ASPX webshell",
      relatedIocs: [], mitreTechniques: ["T1505.003"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
    await stateStore.save(s);

    // Without any prior deploy the suggestion comes through.
    expect((await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({})).body.suggestions).toHaveLength(1);

    // Record the same VQL as already deployed → it must be filtered out next time.
    await huntOutcomeStore.save("c1", recordDeploy([], { source: "fleet", title: "Hunt ASPX webshells", vql, huntId: "H.OLD", deployedAt: "2026-06-20T00:00:00.000Z" }));
    const after = await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({});
    expect(after.body.suggestions).toEqual([]);
    expect(vqlFingerprint(vql)).toBeTruthy();
  });
});
