import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { DwellWindowStore } from "../../src/analysis/dwellWindowStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

async function makeApp(opts: { withStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-dwell-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const pinged: string[] = [];
  const app = createApp(store, {
    pipeline, stateStore,
    aiConfigured: false,
    ...(opts.withStore === false ? {} : {
      dwellWindowStore: new DwellWindowStore(store),
      onDwellWindow: (caseId: string) => pinged.push(caseId),
    }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, pinged };
}

describe("dwell-window routes", () => {
  it("returns 501 when the store is not configured", async () => {
    const { app } = await makeApp({ withStore: false });
    expect((await request(app).get("/cases/c1/dwell-windows")).status).toBe(501);
  });

  it("GET is empty, POST creates (201), GET then lists one", async () => {
    const { app, pinged } = await makeApp();
    expect((await request(app).get("/cases/c1/dwell-windows")).body).toEqual([]);

    const res = await request(app).post("/cases/c1/dwell-windows").send({
      label: "Attacker session 1", start: "2026-05-20T08:00:00Z", end: "2026-05-20T12:00:00Z",
    });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ label: "Attacker session 1" });
    expect(res.body.id).toBeTruthy();
    expect(pinged).toContain("c1");

    const list = (await request(app).get("/cases/c1/dwell-windows")).body;
    expect(list).toHaveLength(1);
  });

  it("POST 400 on a missing label", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/dwell-windows").send({
      start: "2026-05-20T08:00:00Z", end: "2026-05-20T12:00:00Z",
    });
    expect(res.status).toBe(400);
  });

  it("PUT updates (200), DELETE removes (204), then GET is empty; PUT/DELETE 404 on unknown id", async () => {
    const { app } = await makeApp();
    const created = (await request(app).post("/cases/c1/dwell-windows").send({
      label: "old", start: "2026-05-20T08:00:00Z", end: "2026-05-20T12:00:00Z",
    })).body;

    const updated = await request(app).put(`/cases/c1/dwell-windows/${created.id}`).send({
      label: "new", start: "2026-05-20T08:00:00Z", end: "2026-05-20T12:00:00Z",
    });
    expect(updated.status).toBe(200);
    expect(updated.body.label).toBe("new");

    expect((await request(app).put("/cases/c1/dwell-windows/nope").send({
      label: "x", start: "2026-05-20T08:00:00Z", end: "2026-05-20T12:00:00Z",
    })).status).toBe(404);

    expect((await request(app).delete(`/cases/c1/dwell-windows/${created.id}`)).status).toBe(204);
    expect((await request(app).delete(`/cases/c1/dwell-windows/${created.id}`)).status).toBe(404);
    expect((await request(app).get("/cases/c1/dwell-windows")).body).toEqual([]);
  });

  it("PUT 400 on invalid input (end before start)", async () => {
    const { app } = await makeApp();
    const created = (await request(app).post("/cases/c1/dwell-windows").send({
      label: "w", start: "2026-05-20T08:00:00Z", end: "2026-05-20T12:00:00Z",
    })).body;
    const res = await request(app).put(`/cases/c1/dwell-windows/${created.id}`).send({
      label: "w", start: "2026-05-20T12:00:00Z", end: "2026-05-20T08:00:00Z",
    });
    expect(res.status).toBe(400);
  });

  // NOTE: the derived GET /cases/:id/dwell-windows/:windowId/timeline route was removed in Task ST6 —
  // the super-timeline query route (GET .../super-timeline with from/to/origins) supersedes it. Its
  // coverage now lives in tests/server/superTimeline.test.ts.
});

// ── run-bundle × dwell window (Task 10) ─────────────────────────────────────────────────────────
// An optional dwellWindowId passed to run-bundle is recorded on the launched VeloHuntJob (bookkeeping
// for a window-scoped triage). The Super-Timeline Triage bundle no longer HARD-REQUIRES a window (the
// requiresTimeWindow gate was replaced by the superTimelineOnly routing flag). Mirrors
// veloBundle.test.ts's mock runner + real stores, with the dwellWindowStore wired in alongside.

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

const bundleRunner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.DWELL1", state: "RUNNING" } }], raw: "" };
  if (p.includes("hunt_results(")) return { rows: [], raw: "" };
  return { rows: [], raw: "" };
};

async function makeBundleApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-dwell-bundle-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore,
    velociraptorClient: new VelociraptorClient(veloCfg, bundleRunner),
    artifactBundleStore: new ArtifactBundleStore(join(dirname(root), "bundles")),
    veloHuntStore: new VeloHuntStore(store),
    dwellWindowStore: new DwellWindowStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app };
}

describe("run-bundle × dwell window", () => {
  it("threads dwellWindowId from run-bundle into the resulting VeloHuntJob", async () => {
    const { app } = await makeBundleApp();
    const created = await request(app).post("/cases/c1/dwell-windows").send({
      label: "Session 1", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z",
    });
    const windowId = created.body.id;

    const res = await request(app).post("/cases/c1/velociraptor/run-bundle").send({
      bundleId: "super-timeline-triage", dwellWindowId: windowId, waitMinutes: 30,
    });
    expect(res.status).toBe(202);

    const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
    expect(jobs.body[0].dwellWindowId).toBe(windowId);
  });

  it("launches the super-timeline bundle without a dwellWindowId (no hard requirement anymore)", async () => {
    const { app } = await makeBundleApp();
    const res = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "super-timeline-triage" });
    expect(res.status).toBe(202);
  });
});
