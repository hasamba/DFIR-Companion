import { beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { analysisRunManifestSchema } from "../../src/analysis/analysisRunTypes.js";
import { recordSynthesisRun } from "../../src/analysis/analysisRunRecorders.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { NO_SCOPE } from "../../src/analysis/scope.js";

// #1887: an import receipt lists what the import added and removed plus counts. Manifests written
// before carry full id lists and no counts; both shapes must parse and verify in one chain.
describe("analysis run receipt shapes (#1887)", () => {
  let cases: CaseStore;
  let store: AnalysisRunStore;
  const dir = () => join(cases.stateDir("c1"), "analysis-runs");

  beforeEach(async () => {
    cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-receipt-shape-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  });

  const record = (id: string, input: object, output: object) =>
    store.record("c1", {
      id,
      kind: "import",
      startedAt: "2026-09-30T10:00:00.000Z",
      finishedAt: "2026-09-30T10:00:01.000Z",
      versions: {},
      input: { artifacts: [], eventIds: [], entityIds: [], ...input },
      output: { entityIds: [], hashes: [], claims: [], ...output },
    });

  it("parses and verifies an old full-list receipt followed by a changed-only one", async () => {
    await record("old", { entityIds: ["e1", "i1"] }, { entityIds: ["f1", "i1", "e1", "e2"] });
    await record("new", { entityCount: 3 }, { entityIds: ["e3"], removedEntityIds: ["e1"], entityCount: 3 });

    const old = await store.get("c1", "old");
    expect(old?.input).not.toHaveProperty("entityCount");
    expect(old?.output).not.toHaveProperty("removedEntityIds");
    const fresh = await store.get("c1", "new");
    expect(fresh?.input.entityCount).toBe(3);
    expect(fresh?.output).toMatchObject({ entityIds: ["e3"], removedEntityIds: ["e1"], entityCount: 3 });
    expect(await store.verify("c1")).toMatchObject({ ok: true, manifests: 2 });
  });

  it("covers the counts and the removed ids with the manifest hash", async () => {
    await record("new", { entityCount: 3 }, { entityIds: ["e3"], removedEntityIds: ["e1"], entityCount: 3 });
    const [name] = (await readdir(dir())).filter((f) => f === "new.json");
    const path = join(dir(), name);
    const onDisk = JSON.parse(await readFile(path, "utf8"));
    onDisk.output.removedEntityIds = [];
    await writeFile(path, JSON.stringify(onDisk));
    const result = await store.verify("c1");
    expect(result.ok).toBe(false);
    expect(result.problems.join(" ")).toMatch(/manifest hash mismatch/);
  });

  it("rejects a negative or fractional count", () => {
    const base = {
      id: "r",
      caseId: "c1",
      schemaVersion: 1,
      sequence: 1,
      kind: "import",
      status: "completed",
      parentRunId: null,
      startedAt: "2026-09-30T10:00:00.000Z",
      finishedAt: "2026-09-30T10:00:01.000Z",
      durationMs: 1000,
      versions: { application: "x" },
      execution: { retries: 0, warnings: [] },
      output: { entityIds: [], hashes: [], claims: [] },
      previousManifestHash: null,
      manifestHash: "a".repeat(64),
    };
    const input = (entityCount: number) => ({ artifacts: [], eventIds: [], entityIds: [], entityCount });
    expect(analysisRunManifestSchema.safeParse({ ...base, input: input(2) }).success).toBe(true);
    expect(analysisRunManifestSchema.safeParse({ ...base, input: input(-1) }).success).toBe(false);
    expect(analysisRunManifestSchema.safeParse({ ...base, input: input(1.5) }).success).toBe(false);
  });
});

// #2603: a synthesis the fallback model answered says so on its run record, the way a deep pass
// does (#2076). configuration.model is the model that answered; the warning names the one stopped.
describe("synthesis run record — safety-filter fallback (#2603)", () => {
  let cases: CaseStore;
  let store: AnalysisRunStore;

  beforeEach(async () => {
    cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-synth-fallback-run-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  });

  const synthesisRun = (extra: object = {}) =>
    recordSynthesisRun(store, "c1", {
      startedAt: "2026-11-12T10:00:00.000Z",
      provider: "codex",
      model: "gpt-6-sol",
      eventIds: [],
      inputState: emptyState("c1"),
      outputState: emptyState("c1"),
      prompt: "p",
      maxEvents: 10,
      thinkingTokens: 0,
      thinkingSource: "off",
      correlationWindowSeconds: 60,
      anonymizationPolicy: {
        enabled: false,
        categories: {},
        redactSecrets: false,
        maskPublicIps: false,
      } as never,
      scope: NO_SCOPE,
      falsePositiveMarkers: 0,
      infoEventsExcluded: false,
      observationsIncluded: false,
      parseRetries: 0,
      coverage: { omittedBudget: 0, omittedHighSeverity: 0, omittedCloudOperations: 0 } as never,
      ...extra,
    });

  it("warns when the fallback model answered", async () => {
    await synthesisRun({ synthFallback: { from: "opus", to: "gpt-6-sol", safetyStops: 1 } });
    const [run] = await store.list("c1");
    expect(run.configuration?.model).toBe("gpt-6-sol");
    expect(run.execution.warnings).toEqual([
      "answered by the fallback model gpt-6-sol after opus's safety filter stopped it 1 time",
    ]);
  });

  it("adds no warning to a run the synthesis model answered", async () => {
    await synthesisRun();
    const [run] = await store.list("c1");
    expect(run.execution.warnings).toEqual([]);
  });
});
