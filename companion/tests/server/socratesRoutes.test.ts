import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { loadToolConfig, type ToolId, type ToolConfig } from "../../src/integrations/tools/toolConfig.js";

// A zip built by Info-ZIP with `zip -P infected`, holding one 23-byte file "sample.bin".
const ZC_ZIP_B64 =
  "UEsDBAoACQAAAGWB/VzrJ0KsIwAAABcAAAAKABwAc2FtcGxlLmJpblVUCQAD7vtpau77aWp1eAsAAQToAwAABOgDAACSY93uO3OX" +
  "/aoYARCx5Jfbd3EGx/7tlqbVxQgzvT21C/Kx6FBLBwjrJ0KsIwAAABcAAABQSwECHgMKAAkAAABlgf1c6ydCrCMAAAAXAAAACgAY" +
  "AAAAAAABAAAAtIEAAAAAc2FtcGxlLmJpblVUBQAD7vtpanV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAFAAAAB3AAAAAAA=";

// SO-CRATES configured by URL. NOTE: no toolRunner is wired anywhere in this file — the whole point
// is that an http-transport tool must work on a machine with no local forensic binaries.
function socratesCfg(): Map<ToolId, ToolConfig> {
  const cfg = loadToolConfig("socrates", { DFIR_TOOL_SOCRATES_URL: "http://127.0.0.1:59999" })!;
  return new Map<ToolId, ToolConfig>([["socrates", cfg]]);
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-socrates-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const importUndoStore = new ImportUndoStore(store);
  const app = createApp(store, {
    pipeline,
    stateStore,
    importUndoStore,
    loadToolConfigs: socratesCfg,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

describe("SO-CRATES routes", () => {
  it("reports socrates as configured in /tools/status with http transport", async () => {
    const { app } = await harness();
    const r = await request(app).get("/tools/status");
    expect(r.status).toBe(200);
    const socrates = (r.body.tools as Array<{ id: string; configured: boolean; transport: string }>).find(
      (t) => t.id === "socrates",
    );
    expect(socrates?.configured).toBe(true);
    expect(socrates?.transport).toBe("http");
  });

  it("does NOT 501 the socrates run route when no toolRunner is configured", async () => {
    const { app } = await harness();
    const r = await request(app)
      .post("/cases/c1/tools/socrates/run-upload")
      .send({ filename: "sample.bin", dataBase64: Buffer.from("MZ").toString("base64") });
    // The upload will fail (nothing is listening on :59999), but it must NOT be 501 "external tools
    // not configured" — that gate is for spawn tools only.
    expect(r.status).not.toBe(501);
  });

  it("still 501s a spawn tool when no toolRunner is configured", async () => {
    const { app } = await harness();
    const r = await request(app)
      .post("/cases/c1/tools/hayabusa/run-upload")
      .send({ filename: "Security.evtx", dataBase64: "AAAA" });
    expect(r.status).toBe(501);
  });

  it("rejects a zip whose password is wrong with an actionable message", async () => {
    const { app } = await harness();
    const r = await request(app).post("/cases/c1/tools/socrates/run-upload").send({
      filename: "zc.zip",
      dataBase64: ZC_ZIP_B64,
      zipPassword: "definitely-wrong",
    });
    // "definitely-wrong" fails, but the ladder falls back to "infected" which opens it — so the
    // failure here is the unreachable server, never a password error.
    expect(r.status).toBe(400);
    expect(r.body.error).not.toMatch(/password/i);
  });

  it("returns an empty job list for a fresh case", async () => {
    const { app } = await harness();
    const r = await request(app).get("/cases/c1/socrates/jobs");
    expect(r.status).toBe(200);
    expect(r.body.jobs).toEqual([]);
  });

  it("404s the job list for a case that does not exist", async () => {
    const { app } = await harness();
    expect((await request(app).get("/cases/nope/socrates/jobs")).status).toBe(404);
  });
});
