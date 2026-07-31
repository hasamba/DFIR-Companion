import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { EXAMPLE_IMPORTER_SPEC } from "../../src/analysis/importerSpec.js";
import { ImporterStore } from "../../src/analysis/importerStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { pollFor } from "../helpers/poll.js";

const MDE_CSV =
  "Timestamp,DeviceName,ActionType,FileName,Severity,SHA256,RemoteIP\n" +
  "2026-06-10T12:00:00Z,HOST01,ProcessCreated,evil.exe,High,abc123,192.0.2.9";

describe("analysis run import recording", () => {
  it("records the stored artifact, importer version, policy, and resulting entities", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-import-run-"));
    const cases = new CaseStore(root);
    const stateStore = new StateStore(cases);
    const runStore = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
    const importerStore = new ImporterStore(join(root, "importers"));
    const pipeline = buildRuntimePipeline({
      stateStore,
      store: cases,
      analysisRunStore: runStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(cases, {
      pipeline,
      stateStore,
      importerStore,
      analysisRunStore: runStore,
      appVersion: "0.33.0",
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await request(app).post("/importers").send({ spec: EXAMPLE_IMPORTER_SPEC });

    const response = await request(app)
      .post("/cases/c1/import")
      .send({ text: MDE_CSV, filename: "advanced-hunting.csv", minSeverity: "medium" });
    expect(response.status).toBe(202);

    const runs = await pollFor("an immutable import manifest", async () => {
      const current = await runStore.list("c1");
      return current.some((run) => run.kind === "import") ? current : null;
    });
    const imported = runs.find((run) => run.kind === "import");
    expect(imported?.versions.importer).toBe("mde-advanced-hunting/custom-v1");
    expect(imported?.input.artifacts[0]).toMatchObject({
      path: "imports/0001_advanced-hunting.csv",
    });
    expect(imported?.input.artifacts[0].sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(imported?.configuration?.filteringPolicy?.forensicMinimumSeverity).toBe("Medium");
    expect(imported?.output.entityIds.length).toBeGreaterThan(0);
  });
});
