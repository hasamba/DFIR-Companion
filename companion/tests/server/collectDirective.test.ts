import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { HuntOutcomeStore } from "../../src/analysis/huntOutcomeStore.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};
const runner: VqlRunner = async () => ({ rows: [], raw: "" });

async function makeApp(opts: { withVelo?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-collectdir-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({ stateStore, store, imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }) });
  const app = createApp(store, {
    pipeline, stateStore,
    veloHuntStore: new VeloHuntStore(store),
    huntOutcomeStore: new HuntOutcomeStore(store),
    aiConfigured: false,
    ...(opts.withVelo === false ? {} : { velociraptorClient: new VelociraptorClient(veloCfg, runner) }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app };
}

describe("POST /cases/:id/velociraptor/collect-directive (#8 phase 3)", () => {
  it("is 501 when Velociraptor is not configured", async () => {
    const { app } = await makeApp({ withVelo: false });
    const res = await request(app).post("/cases/c1/velociraptor/collect-directive").send({ hostname: "DC01", artifact: "Windows.NTFS.MFT" });
    expect(res.status).toBe(501);
  });

  it("is 400 when the hostname is missing", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/collect-directive").send({ artifact: "Windows.NTFS.MFT" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/hostname/i);
  });

  it("is 400 when the directive maps to no Velociraptor artifact", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/collect-directive")
      .send({ hostname: "DC01", logSource: "ask the network team about the firewall" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/could not map|manually/i);
  });

  it("resolves a valid artifact and attempts the collection (host not enrolled → 502, not a resolve failure)", async () => {
    const { app } = await makeApp();
    // The mock client store has no enrolled 'DC01', so collectHostResolved throws → 502. This proves the
    // route resolved the artifact VQL and reached the deploy path (a resolve failure would be a 400).
    const res = await request(app).post("/cases/c1/velociraptor/collect-directive")
      .send({ hostname: "DC01", logSource: "Security.evtx 4624" });
    expect([200, 502]).toContain(res.status);
    expect(res.status).not.toBe(400);
  });
});
