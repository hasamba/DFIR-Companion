import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

// #2258 — POST /cases/:id/import records the extension's page URL in the import audit log
// (metadata/imports.jsonl), and refuses a sourceUrl that is not a plain http(s) URL BEFORE any
// evidence is written.

const HUNT = JSON.stringify([{ a: 1, b: "x" }]);

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-sourceurl-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

async function auditLines(store: CaseStore): Promise<Record<string, unknown>[]> {
  const raw = await readFile(store.importsLogPath("c1"), "utf8").catch(() => "");
  return raw
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

describe("POST /cases/:id/import — sourceUrl provenance (#2258)", () => {
  it("records a valid sourceUrl in the import audit entry", async () => {
    const { app, store } = await makeApp();
    const url = "https://console.example/app/index.html#/notebooks/N.1";
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ json: HUNT, filename: "velo-hunt.json", sourceUrl: url });
    expect(res.status).not.toBe(400);
    const lines = await auditLines(store);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.sourceUrl).toBe(url);
  });

  it("omits sourceUrl from the audit entry when none is sent", async () => {
    const { app, store } = await makeApp();
    await request(app).post("/cases/c1/import").send({ json: HUNT, filename: "velo-hunt.json" });
    const lines = await auditLines(store);
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toHaveProperty("sourceUrl");
  });

  it("rejects a non-http(s) sourceUrl with 400 and writes no evidence", async () => {
    const { app, store } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ json: HUNT, filename: "velo-hunt.json", sourceUrl: "javascript:alert(1)" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/sourceUrl/);
    expect(await auditLines(store)).toHaveLength(0);
  });
});
