import { describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";

// #1806: the dedicated /import-csv and /import-log routes never read the per-case AI switch, so a
// case with AI OFF still sent its CSV/log to the model. They now answer like the unified /import:
// the evidence is saved, 202 `analyzed:false, reason:"ai-off"`, and nothing reaches the model.

const CSV = "Timestamp,Process,PID\n2026-05-20T09:00:00Z,mimikatz.exe,1234\n";
const LOG = "May 28 09:00:01 host sshd[1]: Failed password for root from 192.0.2.5\n";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-dedicated-ai-off-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = new AnalysisPipeline({
    provider: new MockProvider("mock", "must not be called while AI is off"),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const csvSpy = vi.spyOn(pipeline, "analyzeCsv");
  const logSpy = vi.spyOn(pipeline, "analyzeLog");
  const app = createApp(store, { pipeline, stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  return { app, store, csvSpy, logSpy };
}

describe("dedicated CSV/log imports honour the per-case AI switch (#1806)", () => {
  it("/import-csv with AI off saves the evidence and does not call the model", async () => {
    const { app, store, csvSpy } = await makeApp();
    const res = await request(app).post("/cases/c1/import-csv").send({ filename: "r.csv", csv: CSV });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({
      accepted: true,
      kind: "csv",
      rows: 1,
      analyzed: false,
      reason: "ai-off",
    });
    expect(await readFile(join(store.importsDir("c1"), res.body.file), "utf8")).toBe(CSV);
    await new Promise((r) => setTimeout(r, 100));
    expect(csvSpy).not.toHaveBeenCalled();
  });

  it("/import-log with AI off saves the evidence and does not call the model", async () => {
    const { app, store, logSpy } = await makeApp();
    const res = await request(app).post("/cases/c1/import-log").send({ filename: "auth.log", text: LOG });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({
      accepted: true,
      kind: "log",
      lines: 1,
      analyzed: false,
      reason: "ai-off",
    });
    expect(await readFile(join(store.importsDir("c1"), res.body.file), "utf8")).toBe(LOG);
    await new Promise((r) => setTimeout(r, 100));
    expect(logSpy).not.toHaveBeenCalled();
  });

  it.each(["csv", "log"] as const)("with AI on, /import-%s still analyzes", async (kind) => {
    const { app, csvSpy, logSpy } = await makeApp();
    await request(app).post("/cases/c1/ai-control").send({ enabled: true });
    const res =
      kind === "csv"
        ? await request(app).post("/cases/c1/import-csv").send({ filename: "r.csv", csv: CSV })
        : await request(app).post("/cases/c1/import-log").send({ filename: "a.log", text: LOG });
    expect(res.status).toBe(202);
    expect(res.body.analyzed).toBeUndefined();
    await vi.waitFor(() => expect(kind === "csv" ? csvSpy : logSpy).toHaveBeenCalled(), { timeout: 5000 });
  });
});
