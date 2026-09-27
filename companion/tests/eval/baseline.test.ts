import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  MIN_ATTESTED_RUNS,
  baselineFileName,
  baselineKey,
  compareWithBaseline,
  createBaseline,
  readBaseline,
  writeBaseline,
  type EvaluationIdentity,
  type EvaluationSummary,
} from "./baseline.js";

const MOCK_PROFILE = { real: false, runs: 1, mode: "all" } as const;

const SUMMARY: EvaluationSummary = {
  claimPrecision: 1,
  claimRecall: 0.9,
  eventPrecision: 0.8,
  eventRecall: 0.9,
  iocPrecision: 1,
  iocRecall: 1,
  abstentionRate: 1,
  forbiddenConclusions: 0,
  danglingEvidenceRefs: 0,
  confidenceIssues: 0,
  uncertaintyRecall: 1,
  nextStepRecall: 1,
  durationMs: 1000,
  inputTokens: 100,
  outputTokens: 50,
  costUsd: 0.01,
};

describe("pinned model/prompt baselines (#378)", () => {
  it("keys each baseline by provider, model, and prompt hash", () => {
    const baseline = createBaseline(
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      SUMMARY,
      "2026-07-31T00:00:00.000Z",
    );
    expect(baseline.key).toBe(`provider-a/model-1/${"a".repeat(64)}`);
    expect(baselineFileName(baseline)).toMatch(new RegExp(`^provider-a--model-1--${"a".repeat(12)}\\.json$`));
  });

  it("reports quality, cost, and latency regressions separately", () => {
    const baseline = createBaseline(
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      SUMMARY,
      "2026-07-31T00:00:00.000Z",
    );
    const comparison = compareWithBaseline(
      baseline,
      {
        ...SUMMARY,
        claimRecall: 0.7,
        durationMs: 1400,
        costUsd: 0.02,
      },
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "d".repeat(64),
        sourceHash: "e".repeat(64),
        corpusHash: "c".repeat(64),
      },
      MOCK_PROFILE,
    );
    expect(comparison.status).toBe("regressed");
    expect(comparison.qualityRegressions).toContain("claimRecall");
    expect(comparison.resourceRegressions).toEqual(expect.arrayContaining(["durationMs", "costUsd"]));
  });

  it("refuses to compare a different model or corpus", () => {
    const baseline = createBaseline(
      {
        provider: "provider-a",
        model: "model-1",
        promptHash: "a".repeat(64),
        sourceHash: "b".repeat(64),
        corpusHash: "c".repeat(64),
      },
      SUMMARY,
      "2026-07-31T00:00:00.000Z",
    );
    const comparison = compareWithBaseline(
      baseline,
      SUMMARY,
      {
        provider: "provider-a",
        model: "model-2",
        promptHash: "d".repeat(64),
        sourceHash: "e".repeat(64),
        corpusHash: "f".repeat(64),
      },
      MOCK_PROFILE,
    );
    expect(comparison.status).toBe("incompatible");
    expect(comparison.reasons).toEqual(expect.arrayContaining(["model changed", "corpus changed"]));
  });
});

// #1579: a real model scores a few points apart run to run, so a 2-point tolerance on one real run
// flagged noise as regression. Real runs average 3 runs and get a 5-point tolerance; the baseline
// records its run count, mode, and vision model so a 3-run baseline never judges a 1-run candidate.
describe("real-run tolerance and evaluation profile (#1579)", () => {
  const IDENTITY: EvaluationIdentity = {
    provider: "provider-a",
    model: "model-1",
    promptHash: "a".repeat(64),
    sourceHash: "b".repeat(64),
    corpusHash: "c".repeat(64),
  };
  const RECORDED = "2026-07-31T00:00:00.000Z";
  const REAL_3 = { real: true, runs: 3, mode: "all" };
  const WITH_VISION: EvaluationIdentity = {
    ...IDENTITY,
    vision: { provider: "vision-a", model: "vision-1" },
  };
  const directories: string[] = [];

  afterEach(async () => {
    await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  async function tempDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "eval-baseline-"));
    directories.push(dir);
    return dir;
  }

  it("requires at least three runs for an attestation", () => {
    expect(MIN_ATTESTED_RUNS).toBe(3);
  });

  it("lets a real run drop 4 points that a mock run may not", () => {
    const current = { ...SUMMARY, claimRecall: SUMMARY.claimRecall - 0.04 };
    const real = compareWithBaseline(
      createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 3, mode: "all" }),
      current,
      IDENTITY,
      REAL_3,
    );
    const mock = compareWithBaseline(
      createBaseline(IDENTITY, SUMMARY, RECORDED),
      current,
      IDENTITY,
      MOCK_PROFILE,
    );
    expect(real.status).toBe("passed");
    expect(mock.status).toBe("regressed");
    expect(mock.qualityRegressions).toContain("claimRecall");
  });

  it("never gates a real run on precision, which counts every extra finding as wrong (#1579)", () => {
    const baseline = createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 3, mode: "all" });
    const lowerPrecision = {
      ...SUMMARY,
      claimPrecision: SUMMARY.claimPrecision - 0.3,
      eventPrecision: SUMMARY.eventPrecision - 0.3,
      iocPrecision: SUMMARY.iocPrecision - 0.3,
    };
    expect(compareWithBaseline(baseline, lowerPrecision, IDENTITY, REAL_3).status).toBe("passed");
    // A mock run is deterministic, so its precision still gates.
    const mock = compareWithBaseline(
      createBaseline(IDENTITY, SUMMARY, RECORDED),
      lowerPrecision,
      IDENTITY,
      MOCK_PROFILE,
    );
    expect(mock.qualityRegressions).toEqual(
      expect.arrayContaining(["claimPrecision", "eventPrecision", "iocPrecision"]),
    );
  });

  it("fails a real run that drops 6 points", () => {
    const baseline = createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 3, mode: "all" });
    const comparison = compareWithBaseline(
      baseline,
      { ...SUMMARY, claimRecall: SUMMARY.claimRecall - 0.06 },
      IDENTITY,
      REAL_3,
    );
    expect(comparison.status).toBe("regressed");
    expect(comparison.qualityRegressions).toEqual(["claimRecall"]);
  });

  it("keeps lower-is-better counts strict on a real run", () => {
    const baseline = createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 3, mode: "all" });
    const comparison = compareWithBaseline(
      baseline,
      { ...SUMMARY, confidenceIssues: 1 / 3 },
      IDENTITY,
      REAL_3,
    );
    expect(comparison.qualityRegressions).toEqual(["confidenceIssues"]);
  });

  it.each([
    ["run count changed", { runs: 1, mode: "all" }, { real: true, runs: 3, mode: "all" }, WITH_VISION],
    [
      "evaluation mode changed",
      { runs: 3, mode: "all" },
      { real: true, runs: 3, mode: "extraction" },
      WITH_VISION,
    ],
    [
      "vision model or screenshot set changed",
      { runs: 3, mode: "all" },
      REAL_3,
      { ...IDENTITY, vision: { provider: "vision-a", model: "vision-2" } },
    ],
  ] as const)("refuses to compare when the %s", (reason, recorded, profile, identity) => {
    const baseline = createBaseline(WITH_VISION, SUMMARY, RECORDED, recorded);
    const comparison = compareWithBaseline(baseline, SUMMARY, identity, profile);
    expect(comparison.status).toBe("incompatible");
    expect(comparison.reasons).toEqual([reason]);
  });

  it("refuses to compare when the screenshot set changed under the same vision model", () => {
    const sameModel = { provider: "vision-a", model: "vision-1" };
    const recorded = { ...IDENTITY, vision: { ...sameModel, setHash: "a".repeat(64) } };
    const baseline = createBaseline(recorded, SUMMARY, RECORDED, { runs: 3, mode: "all" });
    const candidate = { ...IDENTITY, vision: { ...sameModel, setHash: "b".repeat(64) } };
    expect(compareWithBaseline(baseline, SUMMARY, candidate, REAL_3).reasons).toEqual([
      "vision model or screenshot set changed",
    ]);
  });

  it("refuses to compare when only one side ran a real vision model", () => {
    const baseline = createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 3, mode: "all" });
    const withVision = { ...IDENTITY, vision: { provider: "vision-a", model: "vision-1" } };
    expect(compareWithBaseline(baseline, SUMMARY, withVision, REAL_3).reasons).toEqual([
      "vision model or screenshot set changed",
    ]);
  });

  it("reads an old baseline without runs, mode, or vision as one run in mode all", async () => {
    const dir = await tempDir();
    const path = join(dir, "old.json");
    const old = {
      schemaVersion: 1,
      key: baselineKey(IDENTITY),
      identity: IDENTITY,
      recordedAt: RECORDED,
      summary: SUMMARY,
    };
    await writeFile(path, JSON.stringify(old), "utf8");
    const baseline = await readBaseline(path);
    expect(compareWithBaseline(baseline, SUMMARY, IDENTITY, MOCK_PROFILE).status).toBe("passed");
    expect(compareWithBaseline(baseline, SUMMARY, IDENTITY, REAL_3).reasons).toEqual(["run count changed"]);
  });

  it("keeps the key and file name unchanged for one run and suffixes them for three", () => {
    const one = createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 1, mode: "all" });
    const three = createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 3, mode: "all" });
    expect(one.key).toBe(`provider-a/model-1/${"a".repeat(64)}`);
    expect(baselineFileName(one)).toBe(`provider-a--model-1--${"a".repeat(12)}.json`);
    expect(three.key).toBe(`provider-a/model-1/${"a".repeat(64)}/r3`);
    expect(baselineKey(IDENTITY, 3)).toBe(three.key);
    expect(baselineFileName(three)).toBe(`provider-a--model-1--${"a".repeat(12)}--r3.json`);
  });

  it("round-trips fractional per-run counts and tokens through write and read", async () => {
    const dir = await tempDir();
    const summary = { ...SUMMARY, inputTokens: 100 / 3, outputTokens: 50.5, confidenceIssues: 1 / 3 };
    const identity = { ...IDENTITY, vision: { provider: "vision-a", model: "vision-1" } };
    const baseline = createBaseline(identity, summary, RECORDED, { runs: 3, mode: "all" });
    const path = await writeBaseline(dir, baseline);
    await expect(readBaseline(path)).resolves.toEqual(baseline);
  });

  it("rejects a baseline whose key does not match its own run count", async () => {
    const dir = await tempDir();
    const path = join(dir, "bad.json");
    const bad = {
      ...createBaseline(IDENTITY, SUMMARY, RECORDED, { runs: 3, mode: "all" }),
      key: baselineKey(IDENTITY),
    };
    await writeFile(path, JSON.stringify(bad), "utf8");
    await expect(readBaseline(path)).rejects.toThrow(/baseline key/);
  });
});
