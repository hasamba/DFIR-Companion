import { describe, it, expect } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { MockProvider } from "../../src/providers/provider.js";
import { EVIDENCE_IMPORT_ROUTES } from "../../src/routes/importCaseGuard.js";

// Regression #2054: closed and archived cases still ingested evidence through the per-format import
// routes. Only the unified POST /import and POST /import-file checked the case status inline; the
// shared guard in front of all 27 import routes checked existence only, so POST /import-csv,
// /import-velociraptor, ... on a frozen case answered 202 and wrote the raw file, a custody record
// and events into a record the analyst had already treated as final. The documented contract
// (mkdocs-docs/reference/api.md) is 423 — parity with POST /events and /iocs.

// A canned synthesis provider ONLY so import-csv / import-log would clear their 501 "not configured"
// gate if the status guard were missing — the test then sees the real 202, not a stand-in 501.
async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-closed-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const canned = new MockProvider("mock", "{}");
  const pipeline = buildRuntimePipeline({
    provider: canned,
    synthesisProvider: canned,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  return { app, store, stateStore };
}

async function seedCase(app: Awaited<ReturnType<typeof makeApp>>["app"], caseId: string) {
  await request(app).post("/cases").send({ caseId, name: "n", investigator: "i", aiProvider: null });
}

async function importedFiles(store: CaseStore, caseId: string): Promise<string[]> {
  return readdir(join(store.caseDir(caseId), "imports")).catch(() => []);
}

// Non-empty and format-agnostic: clears each route's "text/csv/json is required" 400 so an UNGUARDED
// route gets as far as parsing or saving the raw file. The guard must answer 423 before any of that.
const anyBody = { filename: "late.dat", text: "x", csv: "x", json: "x", log: "x", eml: "x", path: "x" };
const CSV = "timestamp,message\n2023-01-02T10:00:00Z,encoded powershell from winword\n";

describe("import routes — closed case refuses evidence (#2054)", () => {
  it.each(EVIDENCE_IMPORT_ROUTES)("423s /cases/:id/%s on a closed case and writes nothing", async (route) => {
    const { app, store, stateStore } = await makeApp();
    await seedCase(app, "c1");
    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    const before = (await stateStore.load("c1")).forensicTimeline.length;

    const res = await request(app).post(`/cases/c1/${route}`).send(anyBody);

    expect(res.status).toBe(423);
    expect(res.body.error).toBe('Case "c1" is closed — reopen it before importing evidence');
    expect(await importedFiles(store, "c1")).toEqual([]);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBe(before);
  });
});

describe("import routes — archived case refuses evidence (#2054)", () => {
  it.each(["import-velociraptor", "import-csv", "import-hayabusa"])(
    "423s /cases/:id/%s on an archived case",
    async (route) => {
      const { app, store } = await makeApp();
      await seedCase(app, "c1");
      expect((await request(app).post("/cases/c1/archive").send({ removeFromList: true })).status).toBe(200);

      const res = await request(app)
        .post(`/cases/c1/${route}`)
        .send({ ...anyBody, csv: CSV });

      expect(res.status).toBe(423);
      expect(res.body.error).toBe('Case "c1" is archived — restore it before importing evidence');
      expect(await importedFiles(store, "c1")).toEqual([]);
    },
  );
});

describe("import routes — the status guard does not block open cases", () => {
  it("still accepts a CSV into an open case", async () => {
    const { app } = await makeApp();
    await seedCase(app, "c1");

    const res = await request(app).post("/cases/c1/import-csv").send({ filename: "real.csv", csv: CSV });

    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ accepted: true, rows: 1 });
  });

  it("accepts again once a closed case is reopened", async () => {
    const { app } = await makeApp();
    await seedCase(app, "c1");
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    await request(app).patch("/cases/c1/status").send({ status: "open" });

    const res = await request(app).post("/cases/c1/import-csv").send({ filename: "real.csv", csv: CSV });

    expect(res.status).toBe(202);
  });
});
