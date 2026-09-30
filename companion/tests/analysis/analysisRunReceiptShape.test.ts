import { beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { analysisRunManifestSchema } from "../../src/analysis/analysisRunTypes.js";

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
