// #2760: a damaged state/ai-control.json answered every AI route with a raw parser 500 (and the
// pill said AI was ON while it did). It must fail CLOSED — AI held off — and name the case and the
// file. A damaged state/import-meta.json (derived data) must not take the cockpit down.
import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-corrupt-state-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    importMetaStore: new ImportMetaStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const damage = (file: string, text = "{corrupt") => writeFile(join(store.stateDir("c1"), file), text);
  return { app, damage };
}

describe("corrupt state/ai-control.json (#2760)", () => {
  it("GET /ai-control reports AI held off and names the case and the file, not a parser 500", async () => {
    const { app, damage } = await makeApp();
    await damage("ai-control.json");
    const res = await request(app).get("/cases/c1/ai-control");
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
    expect(res.body.corrupt.file).toBe("ai-control.json");
    expect(res.body.corrupt.message).toContain("c1");
    expect(res.body.corrupt.message).toContain("ai-control.json");
  });

  it("POST /ai-control rewrites the damaged file, which is the in-app repair", async () => {
    const { app, damage } = await makeApp();
    await damage("ai-control.json");
    const res = await request(app).post("/cases/c1/ai-control").send({ enabled: false });
    expect(res.status).toBe(200);
    expect(res.body.corrupt).toBeUndefined();
    const after = await request(app).get("/cases/c1/ai-control");
    expect(after.body).toMatchObject({ enabled: false });
    expect(after.body.corrupt).toBeUndefined();
  });

  it("GET /ai-state reports the switch held off (fail closed) and the damage as an error", async () => {
    const { app, damage } = await makeApp();
    await damage("ai-control.json", "[1,2]");
    const res = await request(app).get("/cases/c1/ai-state");
    expect(res.status).toBe(200);
    expect(res.body.livePaused).toBe(true);
    expect(res.body.state).toBe("error");
    expect(res.body.detail).toContain("ai-control.json");
    expect(res.body.corrupt.message).toContain("ai-control.json");
  });

  // A non-boolean switch ("false", "yes", 1, null) is damage too: AI held off with the same notice,
  // and an AI route is refused instead of spending a model call.
  it.each(['"false"', '"yes"', "1", "null"])(
    "enabled %s holds AI off and refuses synthesis",
    async (value) => {
      const { app, damage } = await makeApp();
      await damage("ai-control.json", `{"enabled":${value},"lastAnalyzedSeq":0}`);
      const get = await request(app).get("/cases/c1/ai-control");
      expect(get.status).toBe(200);
      expect(get.body.enabled).toBe(false);
      expect(get.body.corrupt.file).toBe("ai-control.json");
      expect(get.body.corrupt.message).toContain("enabled");
      const synth = await request(app).post("/cases/c1/synthesize").send({});
      expect(synth.status).toBe(409);
      expect(synth.body.aiOff).toBe(true);
    },
  );
});

describe("corrupt state/import-meta.json (#2760, SYS-102)", () => {
  it("GET /import-meta answers the empty record plus a damage notice naming the file", async () => {
    const { app, damage } = await makeApp();
    await damage("import-meta.json");
    const res = await request(app).get("/cases/c1/import-meta");
    expect(res.status).toBe(200);
    expect(res.body.lastImportedAt).toBe("");
    expect(res.body.corrupt.message).toContain("c1");
    expect(res.body.corrupt.message).toContain("import-meta.json");
  });

  it("does not take the cockpit down", async () => {
    const { app, damage } = await makeApp();
    await damage("import-meta.json", "null");
    const res = await request(app).get("/cases/c1/cockpit");
    expect(res.status).toBe(200);
  });
});
