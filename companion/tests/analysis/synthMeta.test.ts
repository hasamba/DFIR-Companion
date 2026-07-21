import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SynthMetaStore, buildSynthesisCoverage, coverageLabel, modelPerfLabel } from "../../src/analysis/synthMeta.js";
import type { FindingsDiff } from "../../src/analysis/findingsDiff.js";

const DIFF: FindingsDiff = {
  added: ["Ransomware deployment"],
  removed: ["Benign admin task"],
  severityChanged: [{ title: "Suspicious logon", from: "Medium", to: "Critical" }],
};

describe("SynthMetaStore", () => {
  let store: SynthMetaStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-synthmeta-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SynthMetaStore(cases);
  });

  it("returns an empty meta when none exists", async () => {
    expect(await store.load("c1")).toEqual({ lastSynthesizedAt: "", lastDiff: null });
  });

  it("records a run (timestamp + diff) and loads it back", async () => {
    const at = "2026-06-06T12:00:00.000Z";
    await store.record("c1", DIFF, at);
    const meta = await store.load("c1");
    expect(meta.lastSynthesizedAt).toBe(at);
    expect(meta.lastDiff).toEqual(DIFF);
  });

  it("overwrites the previous record on the next run", async () => {
    await store.record("c1", DIFF, "2026-06-06T12:00:00.000Z");
    const empty: FindingsDiff = { added: [], removed: [], severityChanged: [] };
    await store.record("c1", empty, "2026-06-06T13:00:00.000Z");
    const meta = await store.load("c1");
    expect(meta.lastSynthesizedAt).toBe("2026-06-06T13:00:00.000Z");
    expect(meta.lastDiff).toEqual(empty);
  });

  it("stores and loads performance metrics", async () => {
    const at = "2026-06-18T10:00:00.000Z";
    await store.record("c1", DIFF, at, { durationMs: 12345, eventCount: 500, iocCount: 42 });
    const meta = await store.load("c1");
    expect(meta.durationMs).toBe(12345);
    expect(meta.eventCount).toBe(500);
    expect(meta.iocCount).toBe(42);
  });

  it("loads fine when perf fields are absent (old record format)", async () => {
    await store.record("c1", DIFF, "2026-06-18T10:00:00.000Z");
    const meta = await store.load("c1");
    expect(meta.durationMs).toBeUndefined();
    expect(meta.eventCount).toBeUndefined();
    expect(meta.iocCount).toBeUndefined();
  });

  it("stores and loads a synthesis-coverage snapshot", async () => {
    const coverage = buildSynthesisCoverage({ totalEvents: 412, inWindow: 412, scoped: 407, considered: 287, omittedHighSeverity: 8, promptTokensEstimate: 61000 });
    await store.record("c1", DIFF, "2026-07-14T10:00:00.000Z", { durationMs: 1, eventCount: 287, iocCount: 3, coverage });
    const meta = await store.load("c1");
    expect(meta.coverage).toEqual(coverage);
  });

  // Per-model quality telemetry (issue #74).
  it("stores and loads per-model quality fields", async () => {
    await store.record("c1", DIFF, "2026-07-18T10:00:00.000Z", {
      durationMs: 1, eventCount: 287, iocCount: 3,
      synthModel: "anthropic/claude-sonnet-5",
      findingsCount: 12,
      highSeverityBackfillCount: 2,
      parseRetries: 1,
    });
    const meta = await store.load("c1");
    expect(meta.synthModel).toBe("anthropic/claude-sonnet-5");
    expect(meta.findingsCount).toBe(12);
    expect(meta.highSeverityBackfillCount).toBe(2);
    expect(meta.parseRetries).toBe(1);
  });

  it("loads fine when per-model quality fields are absent (old record format)", async () => {
    await store.record("c1", DIFF, "2026-07-18T10:00:00.000Z");
    const meta = await store.load("c1");
    expect(meta.synthModel).toBeUndefined();
    expect(meta.findingsCount).toBeUndefined();
    expect(meta.highSeverityBackfillCount).toBeUndefined();
    expect(meta.parseRetries).toBeUndefined();
    expect(meta.secondOpinionPerf).toBeUndefined();
  });

  it("records a second-opinion agreement snapshot without disturbing the rest of the meta", async () => {
    await store.record("c1", DIFF, "2026-07-18T10:00:00.000Z", { durationMs: 1, eventCount: 287, iocCount: 3, synthModel: "anthropic/claude-sonnet-5" });
    const perf = { modelA: "anthropic/claude-sonnet-5", modelB: "openai/gpt-5", agreementCount: 8, deltaCount: 2, agreementRate: 0.8, at: "2026-07-18T10:05:00.000Z" };
    await store.recordSecondOpinionPerf("c1", perf);
    const meta = await store.load("c1");
    expect(meta.secondOpinionPerf).toEqual(perf);
    expect(meta.synthModel).toBe("anthropic/claude-sonnet-5"); // untouched by the merge
  });

  it("clears the second-opinion snapshot with null", async () => {
    const perf = { modelA: "a", modelB: "b", agreementCount: 1, deltaCount: 1, agreementRate: 0.5, at: "2026-07-18T10:05:00.000Z" };
    await store.recordSecondOpinionPerf("c1", perf);
    await store.recordSecondOpinionPerf("c1", null);
    const meta = await store.load("c1");
    expect(meta.secondOpinionPerf).toBeNull();
  });

  it("a plain record() wipes a previously-recorded second-opinion snapshot (same posture as secondLook)", async () => {
    const perf = { modelA: "a", modelB: "b", agreementCount: 1, deltaCount: 1, agreementRate: 0.5, at: "2026-07-18T10:05:00.000Z" };
    await store.recordSecondOpinionPerf("c1", perf);
    await store.record("c1", DIFF, "2026-07-18T11:00:00.000Z", { durationMs: 1, eventCount: 1, iocCount: 0 });
    const meta = await store.load("c1");
    expect(meta.secondOpinionPerf).toBeUndefined();
  });
});

describe("modelPerfLabel", () => {
  it("returns null when nothing was recorded", () => {
    expect(modelPerfLabel({})).toBeNull();
  });

  it("describes the synthesis model, findings, and backfill/retry counts", () => {
    const label = modelPerfLabel({ synthModel: "anthropic/claude-sonnet-5", findingsCount: 12, highSeverityBackfillCount: 2, parseRetries: 1 });
    expect(label).toMatch(/anthropic\/claude-sonnet-5/);
    expect(label).toMatch(/12 finding/);
    expect(label).toMatch(/2 recovered by the high-severity safety net/);
    expect(label).toMatch(/1 parse retry/);
  });

  it("omits the backfill/retry clauses when zero", () => {
    const label = modelPerfLabel({ synthModel: "anthropic/claude-sonnet-5", findingsCount: 12, highSeverityBackfillCount: 0, parseRetries: 0 });
    expect(label).not.toMatch(/safety net/);
    expect(label).not.toMatch(/retry/);
  });

  it("adds a second-opinion agreement clause", () => {
    const label = modelPerfLabel({
      secondOpinionPerf: { modelA: "anthropic/claude-sonnet-5", modelB: "openai/gpt-5", agreementCount: 8, deltaCount: 2, agreementRate: 0.8, at: "2026-07-18T10:05:00.000Z" },
    });
    expect(label).toMatch(/openai\/gpt-5/);
    expect(label).toMatch(/anthropic\/claude-sonnet-5/);
    expect(label).toMatch(/8 finding/);
    expect(label).toMatch(/2 disagreement/);
    expect(label).toMatch(/80% agreement/);
  });
});

describe("buildSynthesisCoverage", () => {
  it("splits omissions into scope / legitimate / budget and clamps to non-negative", () => {
    const c = buildSynthesisCoverage({ totalEvents: 500, inWindow: 412, scoped: 407, considered: 287, omittedHighSeverity: 8, promptTokensEstimate: 61000 });
    expect(c.inWindow).toBe(412);
    expect(c.considered).toBe(287);
    expect(c.omittedScope).toBe(88);         // 500 - 412
    expect(c.omittedLegitimate).toBe(5);     // 412 - 407
    expect(c.omittedBudget).toBe(120);       // 407 - 287
    expect(c.omittedHighSeverity).toBe(8);
    expect(c.promptTokensEstimate).toBe(61000);
  });

  it("never goes negative when everything fit", () => {
    const c = buildSynthesisCoverage({ totalEvents: 10, inWindow: 10, scoped: 10, considered: 10, omittedHighSeverity: 0, promptTokensEstimate: 500 });
    expect(c.omittedScope).toBe(0);
    expect(c.omittedLegitimate).toBe(0);
    expect(c.omittedBudget).toBe(0);
  });
});

describe("coverageLabel", () => {
  it("reads 'considered N of M' and breaks omissions down", () => {
    const label = coverageLabel(buildSynthesisCoverage({ totalEvents: 412, inWindow: 412, scoped: 407, considered: 287, omittedHighSeverity: 8, promptTokensEstimate: 61000 }));
    expect(label).toMatch(/considered 287 of 412/i);
    expect(label).toMatch(/120 size/i);
    expect(label).toMatch(/5 filtered/i);
    expect(label).toMatch(/8 high-severity/i);
  });

  it("omits the breakdown when nothing was left out", () => {
    const label = coverageLabel(buildSynthesisCoverage({ totalEvents: 10, inWindow: 10, scoped: 10, considered: 10, omittedHighSeverity: 0, promptTokensEstimate: 500 }));
    expect(label).toMatch(/considered 10 of 10/i);
    expect(label).not.toMatch(/omitted/i);
  });
});

describe("coverage with grouped detections", () => {
  it("counts grouped events as considered and names the grouping in the label", () => {
    const c = buildSynthesisCoverage({
      totalEvents: 900,
      inWindow: 900,
      scoped: 900,
      considered: 900,
      groupEntries: 120,
      groupedEvents: 780,
      omittedHighSeverity: 0,
      promptTokensEstimate: 42_000,
    });
    expect(c.considered).toBe(900);
    expect(c.omittedBudget).toBe(0);
    expect(c.groupEntries).toBe(120);
    expect(c.groupedEvents).toBe(780);

    const label = coverageLabel(c);
    expect(label).toContain("considered 900 of 900 in-window events");
    expect(label).toContain("780 shown as 120 grouped entries");
  });

  it("omits the grouping clause when nothing was grouped", () => {
    const c = buildSynthesisCoverage({
      totalEvents: 10,
      inWindow: 10,
      scoped: 10,
      considered: 10,
      groupEntries: 0,
      groupedEvents: 0,
      omittedHighSeverity: 0,
      promptTokensEstimate: 900,
    });
    expect(coverageLabel(c)).not.toContain("grouped");
  });
});
