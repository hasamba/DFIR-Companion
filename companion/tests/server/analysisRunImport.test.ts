import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { EXAMPLE_IMPORTER_SPEC } from "../../src/analysis/importerSpec.js";
import { ImporterStore } from "../../src/analysis/importerStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { STATE_HASH_ID } from "../../src/analysis/analysisRunSnapshot.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { pollFor } from "../helpers/poll.js";

const MDE_CSV_2 =
  "Timestamp,DeviceName,ActionType,FileName,Severity,SHA256,RemoteIP\n" +
  "2026-06-11T08:00:00Z,HOST02,ProcessCreated,other.exe,High,def456,198.51.100.7";

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

  // #1887: the receipt records what the import changed plus counts, not every id the case holds.
  it("records only the entities an import added and removed, with counts before and after", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-import-delta-"));
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
    const importAndWait = async (text: string, filename: string, count: number) => {
      expect((await request(app).post("/cases/c1/import").send({ text, filename })).status).toBe(202);
      const runs = await pollFor(`import receipt ${count}`, async () => {
        const current = (await runStore.list("c1")).filter((run) => run.kind === "import");
        return current.length >= count ? current : null;
      });
      return runs.sort((a, b) => b.sequence - a.sequence)[0];
    };
    const entities = async () => {
      const state = await stateStore.load("c1");
      return [...state.forensicTimeline.map((e) => e.id), ...state.iocs.map((i) => i.id)];
    };

    const first = await importAndWait(MDE_CSV, "one.csv", 1);
    const afterFirst = await entities();
    expect(first.input).toMatchObject({ eventIds: [], entityIds: [], entityCount: 0 });
    expect(first.output.entityCount).toBe(afterFirst.length);
    expect([...first.output.entityIds].sort()).toEqual([...afterFirst].sort());
    expect(first.output.removedEntityIds).toEqual([]);
    expect(first.output.hashes.map((h) => h.id)).toEqual([STATE_HASH_ID]);

    const second = await importAndWait(MDE_CSV_2, "two.csv", 2);
    const afterSecond = await entities();
    expect(second.input).toMatchObject({ eventIds: [], entityIds: [], entityCount: afterFirst.length });
    expect(second.output.entityCount).toBe(afterSecond.length);
    const added = second.output.entityIds;
    const removed = second.output.removedEntityIds ?? [];
    expect(added.length).toBeGreaterThan(0);
    // before + added - removed is exactly the case after, as a multiset
    const rebuilt = [...afterFirst];
    for (const id of removed) rebuilt.splice(rebuilt.indexOf(id), 1);
    expect([...rebuilt, ...added].sort()).toEqual([...afterSecond].sort());
    // the receipt no longer lists every id the case held
    expect(added.length).toBeLessThan(afterSecond.length);
    const findingIds = (await stateStore.load("c1")).findings.map((f) => f.id);
    for (const id of findingIds) expect(added).not.toContain(id);

    // A replay of the first import records the same changed-only shape.
    const replay = await request(app).post(`/cases/c1/analysis-runs/${first.id}/replay`);
    expect(replay.status).toBe(200);
    const child = (await runStore.list("c1")).find((run) => run.parentRunId === first.id);
    const afterReplay = await entities();
    expect(child?.input).toMatchObject({ eventIds: [], entityIds: [], entityCount: afterSecond.length });
    expect(child?.output.entityCount).toBe(afterReplay.length);
    const replayed = [...afterSecond];
    for (const id of child?.output.removedEntityIds ?? []) replayed.splice(replayed.indexOf(id), 1);
    expect([...replayed, ...(child?.output.entityIds ?? [])].sort()).toEqual([...afterReplay].sort());
    expect(child?.output.hashes.map((h) => h.id)).toEqual([STATE_HASH_ID]);
  });
});
