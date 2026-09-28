import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createBaseline } from "./baseline.js";
import { loadSavedCandidate, recompareReport } from "./compareReport.js";
import { buildEvaluationReport, type EvaluationReportInput } from "./report.js";

// #1747: a clean candidate run is kept when its baseline could not be read, and compared later
// without any model call.
const RESOURCES = {
  durationMs: 10,
  calls: 1,
  failedCalls: 0,
  inputTokens: 2,
  outputTokens: 1,
  costUsd: 0.01,
};
const METRICS = {
  claimPrecision: 1,
  claimRecall: 1,
  iocPrecision: 1,
  iocRecall: 1,
  uncertaintyRecall: 1,
  nextStepRecall: 1,
  abstained: true,
  forbiddenConclusions: 0,
  danglingEvidenceRefs: 0,
  confidenceIssues: 0,
  confidenceBandMisses: 0,
};

function candidate(overrides: Partial<EvaluationReportInput> = {}): EvaluationReportInput {
  const runs = [1, 2, 3];
  return {
    identity: {
      provider: "p",
      model: "m",
      promptHash: "a".repeat(64),
      sourceHash: "b".repeat(64),
      corpusHash: "c".repeat(64),
    },
    corpusVersion: "1.1.0",
    cases: runs.map((run) => ({
      id: run === 1 ? "case-1" : `case-1#run${run}`,
      scenario: "ransomware",
      status: "passed" as const,
      metrics: { ...METRICS },
      resources: { ...RESOURCES },
      runIndex: run,
    })),
    extraction: runs.map((run) => ({
      id: run === 1 ? "csv-1" : `csv-1#run${run}`,
      modality: "csv" as const,
      status: "passed" as const,
      precision: 1,
      recall: 1,
      resources: { ...RESOURCES },
      runIndex: run,
      gate: { minPrecision: 0, minRecall: 0.7 },
    })),
    screenshot: [],
    createdAt: "2026-09-28T00:00:00.000Z",
    real: true,
    runs: 3,
    mode: "all",
    expected: { cases: 1, extraction: 1, screenshot: 0 },
    ...overrides,
  };
}

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function saved(report: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "eval-compare-"));
  directories.push(dir);
  const path = join(dir, "report.json");
  await writeFile(path, JSON.stringify(report));
  return path;
}

describe("loadSavedCandidate (#1747)", () => {
  it("accepts a report whose only failure was an unreadable baseline, and drops every derived field", async () => {
    const report = buildEvaluationReport({ ...candidate(), baselineError: "baseline unreadable: ENOENT" });
    expect(report.outcome).toBe("runner_failed");
    const input = await loadSavedCandidate(await saved(report));
    expect(input.baselineError).toBeUndefined();
    expect(input).not.toHaveProperty("summary");
    expect(input).not.toHaveProperty("outcome");
    expect(input.cases).toHaveLength(3);
  });

  it("reads a row without the band-miss count as zero", async () => {
    const report = buildEvaluationReport(candidate());
    const old = {
      ...report,
      cases: report.cases.map((row) => ({
        ...row,
        metrics: { ...METRICS, confidenceBandMisses: undefined },
      })),
    };
    const input = await loadSavedCandidate(await saved(old));
    expect(input.cases.every((row) => row.metrics.confidenceBandMisses === 0)).toBe(true);
  });

  it("refuses a run that really failed, a non-attestable shape, and malformed numbers", async () => {
    const broken = buildEvaluationReport({ ...candidate(), runnerError: "harness crashed" });
    await expect(loadSavedCandidate(await saved(broken))).rejects.toThrow(/runner error/);
    const dead = candidate();
    dead.cases[1] = { ...dead.cases[1], status: "provider_failed", errorKind: "timeout" };
    await expect(loadSavedCandidate(await saved(buildEvaluationReport(dead)))).rejects.toThrow(
      /provider_failed/,
    );
    await expect(
      loadSavedCandidate(
        await saved(buildEvaluationReport(candidate({ runs: 1, cases: candidate().cases.slice(0, 1) }))),
      ),
    ).rejects.toThrow(/at least 3 runs/);
    const negative = buildEvaluationReport(candidate());
    negative.cases[0].metrics.claimRecall = -1;
    await expect(loadSavedCandidate(await saved(negative))).rejects.toThrow();
  });
});

describe("loadSavedCandidate refuses an empty evaluation (#1747, Codex review)", () => {
  it("rejects a report that claims zero cases or zero extraction checks", async () => {
    const empty = buildEvaluationReport(
      candidate({ cases: [], extraction: [], expected: { cases: 0, extraction: 0, screenshot: 0 } }),
    );
    await expect(loadSavedCandidate(await saved(empty))).rejects.toThrow();
    const noCases = buildEvaluationReport(
      candidate({ cases: [], expected: { cases: 0, extraction: 1, screenshot: 0 } }),
    );
    await expect(loadSavedCandidate(await saved(noCases))).rejects.toThrow();
  });
});

describe("recompareReport (#1747)", () => {
  it("recomputes the outcome against a baseline with no model call", async () => {
    const input = await loadSavedCandidate(await saved(buildEvaluationReport(candidate())));
    const same = buildEvaluationReport(candidate());
    const matching = createBaseline(same.identity, same.summary, same.createdAt, { runs: 3, mode: "all" });
    expect(recompareReport(input, matching).outcome).toBe("passed");
    const better = createBaseline(
      same.identity,
      { ...same.summary, costUsd: same.summary.costUsd / 10 },
      same.createdAt,
      {
        runs: 3,
        mode: "all",
      },
    );
    expect(recompareReport(input, better).baselineComparison?.status).toBe("regressed");
  });
});
