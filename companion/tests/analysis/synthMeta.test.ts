import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SynthMetaStore, buildSynthesisCoverage, coverageLabel } from "../../src/analysis/synthMeta.js";
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
