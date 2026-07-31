import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { hashManifestValue } from "../../src/analysis/analysisRunHash.js";
import { getSynthesisPrompt } from "../../src/analysis/pipeline.js";
import { defaultReportTemplate } from "../../src/reports/reportTemplate.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { ReportVersionStore } from "../../src/reports/reportVersionStore.js";
import { createApp } from "../../src/server.js";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-run-routes-"));
  const cases = new CaseStore(root);
  const stateStore = new StateStore(cases);
  const analysisRunStore = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  const reportVersionStore = new ReportVersionStore(cases);
  const reportWriter = new ReportWriter(cases, stateStore, {
    analysisRuns: analysisRunStore,
    reportVersions: reportVersionStore,
  });
  const app = createApp(cases, {
    stateStore,
    analysisRunStore,
    reportVersionStore,
    reportWriter,
    appVersion: "0.33.0",
  });
  await request(app).post("/cases").send({
    caseId: "c1",
    name: "n",
    investigator: "i",
    aiProvider: null,
  });
  return { app, analysisRunStore, cases };
}

describe("analysis-run routes", () => {
  it("lists, verifies and compares stored manifests", async () => {
    const { app, analysisRunStore } = await harness();
    await analysisRunStore.record("c1", {
      id: "r1",
      kind: "synthesis",
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:00:01.000Z",
      versions: { schema: "synthesis/v1" },
      input: { artifacts: [], eventIds: [], entityIds: [] },
      configuration: { promptHash: hashManifestValue(getSynthesisPrompt()) },
      output: {
        entityIds: ["f1"],
        hashes: [],
        claims: [{ id: "f1", hash: "old", evidenceEventIds: ["e1"] }],
      },
    });
    await analysisRunStore.record("c1", {
      id: "r2",
      kind: "synthesis",
      startedAt: "2026-07-31T10:01:00.000Z",
      finishedAt: "2026-07-31T10:01:01.000Z",
      versions: { schema: "synthesis/v1" },
      input: { artifacts: [], eventIds: [], entityIds: [] },
      configuration: { promptHash: hashManifestValue(getSynthesisPrompt()) },
      output: {
        entityIds: ["f1", "f2"],
        hashes: [],
        claims: [
          { id: "f1", hash: "new", evidenceEventIds: ["e1", "e2"] },
          { id: "f2", hash: "added", evidenceEventIds: ["e3"] },
        ],
      },
    });

    const listed = await request(app).get("/cases/c1/analysis-runs");
    expect(listed.status).toBe(200);
    expect(listed.body.map((run: { id: string }) => run.id)).toEqual(["r2", "r1"]);
    const manifest = await request(app).get("/cases/c1/analysis-runs/r1");
    expect(manifest.status).toBe(200);
    expect(manifest.body.output.claims[0].evidenceEventIds).toEqual(["e1"]);
    expect((await request(app).get("/cases/c1/analysis-runs/integrity")).body.ok).toBe(true);

    const compared = await request(app).get("/cases/c1/analysis-runs/compare?from=r1&to=r2");
    expect(compared.status).toBe(200);
    expect(compared.body.added).toEqual([{ id: "f2", evidenceEventIds: ["e3"] }]);
    expect(compared.body.changed[0]).toEqual({
      id: "f1",
      beforeEvidenceEventIds: ["e1"],
      afterEvidenceEventIds: ["e1", "e2"],
    });
  });

  it("replays a report into a child run and pins both runs to the report version", async () => {
    const { app, analysisRunStore, cases } = await harness();
    await analysisRunStore.record("c1", {
      id: "report-parent",
      kind: "report",
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:00:01.000Z",
      versions: { schema: "report/v1" },
      input: { artifacts: [], eventIds: [], entityIds: [] },
      configuration: { templateHash: hashManifestValue(defaultReportTemplate()) },
      output: { entityIds: [], hashes: [], claims: [] },
    });

    const replay = await request(app).post("/cases/c1/analysis-runs/report-parent/replay");
    expect(replay.status).toBe(200);
    const runs = await analysisRunStore.list("c1");
    const child = runs.find((run) => run.parentRunId === "report-parent");
    expect(child?.kind).toBe("report");

    const versions = await request(app).get("/cases/c1/report-versions");
    expect(versions.status).toBe(200);
    expect(versions.body[0].analysisRunIds).toEqual(expect.arrayContaining(["report-parent", child?.id]));
    const exported = JSON.parse(
      await readFile(join(cases.reportsDir("c1"), "analysis-runs.json"), "utf8"),
    ) as Array<{ id: string }>;
    expect(exported.map((run) => run.id)).toEqual(expect.arrayContaining(["report-parent", child?.id]));
  });

  it("blocks replay before starting when a pinned provider/model is unavailable", async () => {
    const { app, analysisRunStore } = await harness();
    await analysisRunStore.record("c1", {
      id: "synth-unavailable",
      kind: "synthesis",
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:00:01.000Z",
      versions: { schema: "synthesis/v1" },
      input: { artifacts: [], eventIds: [], entityIds: [] },
      configuration: {
        provider: "missing-provider",
        model: "missing-model",
        promptHash: hashManifestValue(getSynthesisPrompt()),
      },
      output: { entityIds: [], hashes: [], claims: [] },
    });

    const replay = await request(app).post("/cases/c1/analysis-runs/synth-unavailable/replay");
    expect(replay.status).toBe(409);
    expect(replay.body.blockers).toContain("provider/model unavailable: missing-provider/missing-model");
    expect(await analysisRunStore.list("c1")).toHaveLength(1);
  });
});
