import { describe, it, expect, beforeEach } from "vitest";
import { cp, mkdir, mkdtemp, readFile, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import type { AnalysisRunRecordInput } from "../../src/analysis/analysisRunTypes.js";

const BASE_RUN: Omit<AnalysisRunRecordInput, "id"> = {
  kind: "deterministic",
  startedAt: "2026-07-31T10:00:00.000Z",
  finishedAt: "2026-07-31T10:00:01.000Z",
  versions: {},
  input: { artifacts: [], eventIds: [], entityIds: [] },
  output: { entityIds: [], hashes: [], claims: [] },
};

describe("AnalysisRunStore", () => {
  let cases: CaseStore;
  let store: AnalysisRunStore;

  const ledgerDir = (caseId: string) => join(cases.stateDir(caseId), "analysis-runs");

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

  describe("case binding", () => {
    // A renamed archive import copies state/analysis-runs/*.json verbatim, so the
    // manifests still name the source case. The requested case is authoritative.
    async function copyLedgerToC2(runId: string): Promise<void> {
      await cases.createCase({ caseId: "c2", name: "n2", investigator: "i", aiProvider: null });
      await mkdir(ledgerDir("c2"), { recursive: true });
      await cp(join(ledgerDir("c1"), `${runId}.json`), join(ledgerDir("c2"), `${runId}.json`));
    }

    it("refuses a run whose manifest names a different case", async () => {
      const run = await store.record("c1", { ...BASE_RUN, id: "foreign-run" });
      await copyLedgerToC2("foreign-run");

      expect(run.caseId).toBe("c1");
      expect(await store.get("c2", "foreign-run")).toBeNull();
      expect(await store.get("c1", "foreign-run")).not.toBeNull();
    });

    it("omits a manifest that names a different case from the listing", async () => {
      await store.record("c1", { ...BASE_RUN, id: "foreign-run" });
      await copyLedgerToC2("foreign-run");

      expect(await store.list("c2")).toEqual([]);
    });

    it("starts a fresh chain when the directory holds another case's ledger", async () => {
      await store.record("c1", { ...BASE_RUN, id: "src-1" });
      await store.record("c1", { ...BASE_RUN, id: "src-2" });
      // A renamed import copies head.json in too, so the head names the source case
      // and its sequence still matches the manifest count.
      await copyLedgerToC2("src-1");
      await cp(join(ledgerDir("c1"), "src-2.json"), join(ledgerDir("c2"), "src-2.json"));
      await cp(join(ledgerDir("c1"), "head.json"), join(ledgerDir("c2"), "head.json"));

      const own = await store.record("c2", { ...BASE_RUN, id: "own-1" });

      expect(own.sequence).toBe(1);
      expect(own.previousManifestHash).toBeNull();
      expect((await store.list("c2")).map((run) => run.id)).toEqual(["own-1"]);
    });

    it("scopes integrity reporting to the runs the case owns", async () => {
      await store.record("c1", { ...BASE_RUN, id: "src-1" });
      await copyLedgerToC2("src-1");
      await cp(join(ledgerDir("c1"), "head.json"), join(ledgerDir("c2"), "head.json"));
      await store.record("c2", { ...BASE_RUN, id: "own-1" });

      const result = await store.verify("c2");

      expect(result.ok).toBe(true);
      expect(result.manifests).toBe(1);
      expect(result.foreignManifests).toBe(1);
    });
  });

  describe("append cost", () => {
    it("appends without rereading historical manifests", async () => {
      await store.record("c1", { ...BASE_RUN, id: "run-1" });
      const second = await store.record("c1", { ...BASE_RUN, id: "run-2" });
      // An unreadable historical manifest must not block an append: reaching it at
      // all means the append is still scanning the whole ledger.
      await writeFile(join(ledgerDir("c1"), "run-1.json"), "{ not valid json", "utf8");

      const third = await store.record("c1", { ...BASE_RUN, id: "run-3" });

      expect(third.sequence).toBe(3);
      expect(third.previousManifestHash).toBe(second.manifestHash);
    });

    it("rebuilds the next sequence when the pinned head is missing", async () => {
      await store.record("c1", { ...BASE_RUN, id: "run-1" });
      const second = await store.record("c1", { ...BASE_RUN, id: "run-2" });
      await unlink(join(ledgerDir("c1"), "head.json"));

      const third = await store.record("c1", { ...BASE_RUN, id: "run-3" });

      expect(third.sequence).toBe(3);
      expect(third.previousManifestHash).toBe(second.manifestHash);
      expect((await store.verify("c1")).ok).toBe(true);
    });

    it("recovers the tip when a crash left the head one behind the manifests", async () => {
      const first = await store.record("c1", { ...BASE_RUN, id: "run-1" });
      const second = await store.record("c1", { ...BASE_RUN, id: "run-2" });
      // Rewind to the state a crash between the manifest write and the head write
      // leaves behind: run-2 on disk, head still pinned to run-1, marker outstanding.
      await writeFile(
        join(ledgerDir("c1"), "head.json"),
        JSON.stringify({
          schemaVersion: 1,
          caseId: "c1",
          sequence: first.sequence,
          manifestHash: first.manifestHash,
        }),
        "utf8",
      );
      await writeFile(join(ledgerDir("c1"), "pending.json"), JSON.stringify({ id: "run-2" }), "utf8");

      const third = await store.record("c1", { ...BASE_RUN, id: "run-3" });

      expect(third.sequence).toBe(3);
      expect(third.previousManifestHash).toBe(second.manifestHash);
      expect((await store.verify("c1")).ok).toBe(true);
    });

    it("does not fork the chain when a retry of an interrupted append hits the existing manifest", async () => {
      const first = await store.record("c1", { ...BASE_RUN, id: "run-1" });
      const second = await store.record("c1", { ...BASE_RUN, id: "run-2" });
      // The state a crash between the manifest write and the head write leaves behind.
      await writeFile(
        join(ledgerDir("c1"), "head.json"),
        JSON.stringify({
          schemaVersion: 1,
          caseId: "c1",
          sequence: first.sequence,
          manifestHash: first.manifestHash,
        }),
        "utf8",
      );
      await writeFile(join(ledgerDir("c1"), "pending.json"), JSON.stringify({ id: "run-2" }), "utf8");

      // A caller retrying the SAME id must fail, because that manifest is already on disk. The
      // failure must not clear the marker: it is the only remaining signal that the head is stale,
      // and without it the next append trusts the head and reuses run-2's sequence.
      await expect(store.record("c1", { ...BASE_RUN, id: "run-2" })).rejects.toThrow(/already exists/i);

      const third = await store.record("c1", { ...BASE_RUN, id: "run-3" });

      expect(third.sequence).toBe(3);
      expect(third.previousManifestHash).toBe(second.manifestHash);
      expect((await store.verify("c1")).ok).toBe(true);
    });

    it("leaves a deleted manifest visible instead of backfilling its sequence", async () => {
      await store.record("c1", { ...BASE_RUN, id: "run-1" });
      const second = await store.record("c1", { ...BASE_RUN, id: "run-2" });
      await unlink(join(ledgerDir("c1"), "run-2.json"));

      const next = await store.record("c1", { ...BASE_RUN, id: "run-3" });

      // Reusing the vacated sequence would erase the evidence that run-2 ever
      // existed. The new run keeps its own place and still names the missing
      // manifest as its predecessor, so verify() reports the gap permanently.
      expect(next.sequence).toBe(3);
      expect(next.previousManifestHash).toBe(second.manifestHash);
      const result = await store.verify("c1");
      expect(result.ok).toBe(false);
      expect(result.problems).toContain("run-3: ledger sequence mismatch");
      expect(result.problems).toContain("run-3: previous manifest hash mismatch");
    });
  });
});
