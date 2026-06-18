import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
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
});
