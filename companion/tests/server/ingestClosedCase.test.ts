import { describe, it, expect } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import { privateBundleDir } from "../helpers/bundleDir.js";

// Regression #2071: #2054 froze the 27 /import* routes on a closed or archived case, but seven other
// ways evidence reaches a case did not check the status at all — the Velociraptor bundle/external/
// collect routes, the two tool-run routes, the IRIS import and the drop-folder "Run tools" button.
// Each answered success and wrote evidence into a record the analyst had treated as final.
//
// Every integration below is stubbed so each route clears its own 501 "not configured" gate: an
// unguarded route would answer 400/404/200, never 423, so a 423 here can only come from the guard.
// The open-case baseline proves that — the same requests on an open case get neither 423 nor 501.

const HUNT = { huntId: "H.1", artifacts: ["Windows.EventLogs.Evtx"] };

function stubVelociraptor() {
  return {
    async huntResultsByArtifact() {
      return {
        results: { [HUNT.artifacts[0]]: [{ EventID: 4624 }] },
        skipped: [],
        unread: [],
        truncated: [],
      };
    },
  } as unknown as NonNullable<AppOptions["velociraptorClient"]>;
}

const stubToolRunner = {} as unknown as NonNullable<AppOptions["toolRunner"]>;
const stubIris = {} as unknown as NonNullable<AppOptions["irisClient"]>;

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ingest-closed-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const veloHuntStore = new VeloHuntStore(store);
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    velociraptorClient: stubVelociraptor(),
    artifactBundleStore: new ArtifactBundleStore(privateBundleDir(root)),
    veloHuntStore,
    toolRunner: stubToolRunner,
    dropStatusStore: new DropStatusStore(store),
    irisClient: stubIris,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await veloHuntStore.upsert("c1", {
    ...HUNT,
    bundleId: "b1",
    bundleName: "Bundle",
    launchedAt: "2026-10-01T00:00:00.000Z",
    waitMinutes: 10,
    collectAt: "2026-10-01T00:10:00.000Z",
    status: "imported",
  });
  return { app, store, stateStore };
}

async function importedFiles(store: CaseStore, caseId: string): Promise<string[]> {
  return readdir(join(store.caseDir(caseId), "imports")).catch(() => []);
}

// Each body clears the route's 501 and stops at a 4xx/2xx with no side effect on an OPEN case.
const ROUTES: Array<[string, Record<string, unknown>]> = [
  ["drop/run-pending", {}],
  ["velociraptor/run-bundle", { bundleId: "no-such-bundle" }],
  ["velociraptor/import-external", { ref: "not a velociraptor ref" }],
  ["velociraptor/collect", { huntId: "H.not-tracked" }],
  ["iris-import", {}],
  ["tools/hayabusa/run", {}],
  ["tools/hayabusa/run-upload", {}],
];

describe("ingest routes — closed case refuses evidence (#2071)", () => {
  it.each(ROUTES)("423s /cases/:id/%s on a closed case and writes nothing", async (route, body) => {
    const { app, store, stateStore } = await makeApp();
    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    const before = (await stateStore.load("c1")).forensicTimeline.length;

    const res = await request(app).post(`/cases/c1/${route}`).send(body);

    expect(res.status).toBe(423);
    expect(res.body.error).toBe('Case "c1" is closed — reopen it before importing evidence');
    expect(await importedFiles(store, "c1")).toEqual([]);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBe(before);
  });

  it.each(ROUTES)("does not 423 or 501 /cases/:id/%s on an open case", async (route, body) => {
    const { app } = await makeApp();

    const res = await request(app).post(`/cases/c1/${route}`).send(body);

    expect(res.status).not.toBe(423);
    expect(res.status).not.toBe(501);
  });
});

describe("ingest routes — archived case refuses evidence (#2071)", () => {
  it.each([
    ["iris-import", { irisCaseId: 7 }],
    ["tools/hayabusa/run-upload", { filename: "a.evtx", dataBase64: "AAAA" }],
    ["velociraptor/import-external", { ref: "H.1" }],
  ])("423s /cases/:id/%s on an archived case", async (route, body) => {
    const { app, store } = await makeApp();
    expect((await request(app).post("/cases/c1/archive").send({ removeFromList: true })).status).toBe(200);

    const res = await request(app).post(`/cases/c1/${route}`).send(body);

    expect(res.status).toBe(423);
    expect(res.body.error).toBe('Case "c1" is archived — restore it before importing evidence');
    expect(await importedFiles(store, "c1")).toEqual([]);
  });
});

describe("hunt-rows stays open on a closed case (#2071)", () => {
  it("still returns a closed case's hunt rows — it only reads", async () => {
    const { app } = await makeApp();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });

    const res = await request(app).post("/cases/c1/velociraptor/hunt-rows").send({ huntId: HUNT.huntId });

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
  });
});
