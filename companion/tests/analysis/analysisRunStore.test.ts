import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";

describe("AnalysisRunStore", () => {
  let cases: CaseStore;
  let store: AnalysisRunStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-analysis-runs-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  });

  it("records immutable, hash-chained manifests and lists newest first", async () => {
    const first = await store.record("c1", {
      id: "run-1",
      kind: "import",
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:00:01.000Z",
      versions: { importer: "thor/v1", rules: "rules-a", data: "attack-16" },
      input: {
        artifacts: [{ path: "imports/0001_thor.json", sha256: "a".repeat(64) }],
        eventIds: [],
        entityIds: [],
      },
      output: { entityIds: ["e1"], hashes: [], claims: [] },
    });
    const second = await store.record("c1", {
      id: "run-2",
      kind: "synthesis",
      parentRunId: first.id,
      startedAt: "2026-07-31T10:01:00.000Z",
      finishedAt: "2026-07-31T10:01:03.000Z",
      versions: {},
      input: { artifacts: [], eventIds: ["e1"], entityIds: [] },
      configuration: {
        promptHash: "b".repeat(64),
        provider: "openai",
        model: "gpt-test",
        parameters: { thinkingTokens: 2048 },
      },
      output: {
        entityIds: ["f1"],
        hashes: [],
        claims: [{ id: "f1", hash: "claim-a", evidenceEventIds: ["e1"] }],
      },
    });

    expect(first.previousManifestHash).toBeNull();
    expect(second.previousManifestHash).toBe(first.manifestHash);
    expect([first.sequence, second.sequence]).toEqual([1, 2]);
    expect(second.durationMs).toBe(3000);
    expect((await store.list("c1")).map((run) => run.id)).toEqual(["run-2", "run-1"]);
    expect((await store.verify("c1")).ok).toBe(true);
    await expect(
      store.record("c1", {
        id: "run-2",
        kind: "report",
        startedAt: "2026-07-31T11:00:00.000Z",
        finishedAt: "2026-07-31T11:00:01.000Z",
        versions: {},
        input: { artifacts: [], eventIds: [], entityIds: [] },
        output: { entityIds: [], hashes: [], claims: [] },
      }),
    ).rejects.toThrow(/already exists/i);
  });

  it("chains by append order when a later-finishing run started first", async () => {
    const short = await store.record("c1", {
      id: "short-run",
      kind: "deterministic",
      startedAt: "2026-07-31T10:01:00.000Z",
      finishedAt: "2026-07-31T10:01:01.000Z",
      versions: {},
      input: { artifacts: [], eventIds: [], entityIds: [] },
      output: { entityIds: [], hashes: [], claims: [] },
    });
    const long = await store.record("c1", {
      id: "long-run",
      kind: "synthesis",
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:02:00.000Z",
      versions: {},
      input: { artifacts: [], eventIds: [], entityIds: [] },
      output: { entityIds: [], hashes: [], claims: [] },
    });

    expect(long.previousManifestHash).toBe(short.manifestHash);
    expect(long.sequence).toBe(2);
    expect((await store.verify("c1")).ok).toBe(true);
  });

  it("redacts credential-shaped fields before persistence", async () => {
    const credentialedEndpoint = ["https://", "alice", ":", "secret", "@", "example.invalid/api"].join("");
    const run = await store.record("c1", {
      id: "run-safe",
      kind: "enrichment",
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:00:01.000Z",
      versions: {},
      input: { artifacts: [], eventIds: [], entityIds: ["i1"] },
      configuration: {
        provider: "VirusTotal",
        parameters: {
          apiKey: "should-never-land",
          authorization: "Bearer should-never-land",
          endpoint: credentialedEndpoint,
          maxIocs: 100,
        },
      },
      output: { entityIds: ["i1"], hashes: [], claims: [] },
    });

    const persisted = await readFile(join(cases.stateDir("c1"), "analysis-runs", `${run.id}.json`), "utf8");
    expect(persisted).not.toContain("should-never-land");
    expect(persisted).not.toContain("alice:secret");
    expect(run.configuration?.parameters).toEqual({
      apiKey: "[REDACTED]",
      authorization: "[REDACTED]",
      endpoint: "https://[REDACTED]@example.invalid/api",
      maxIocs: 100,
    });
  });

  it("detects a modified historical manifest", async () => {
    const run = await store.record("c1", {
      id: "run-tamper",
      kind: "deterministic",
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:00:01.000Z",
      versions: { rules: "rules-a" },
      input: { artifacts: [], eventIds: ["e1"], entityIds: [] },
      output: { entityIds: ["e1"], hashes: [], claims: [] },
    });
    const path = join(cases.stateDir("c1"), "analysis-runs", `${run.id}.json`);
    const parsed = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
    await writeFile(path, JSON.stringify({ ...parsed, durationMs: 999999 }), "utf8");

    const result = await store.verify("c1");
    expect(result.ok).toBe(false);
    expect(result.problems).toContain("run-tamper: manifest hash mismatch");
  });

  it("detects deletion of the newest manifest against the pinned ledger head", async () => {
    for (const id of ["kept-run", "deleted-run"]) {
      await store.record("c1", {
        id,
        kind: "deterministic",
        startedAt: "2026-07-31T10:00:00.000Z",
        finishedAt: "2026-07-31T10:00:01.000Z",
        versions: {},
        input: { artifacts: [], eventIds: [], entityIds: [] },
        output: { entityIds: [], hashes: [], claims: [] },
      });
    }
    await unlink(join(cases.stateDir("c1"), "analysis-runs", "deleted-run.json"));

    const result = await store.verify("c1");
    expect(result.ok).toBe(false);
    expect(result.problems).toContain("ledger head mismatch");
  });
});
