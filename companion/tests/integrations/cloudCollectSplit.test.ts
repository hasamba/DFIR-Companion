import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import { decideSplit, describeDuration, leaves } from "../../src/integrations/cloudCollect/collectSplit.js";
import type { CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type {
  CloudCollectSession,
  CollectSourceInfo,
  ManifestSplit,
  SubWindowStatus,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import { faultFs, kill, pipelineImporter, tempCase, type TempCase } from "../helpers/cloudCollectFakes.js";
import { denseSession, denseSource, fakeClock, type DenseRecord } from "../helpers/cloudCollectDense.js";

// #2312 — the split tree: capped windows split to the minimum, fall back on partitions, give up as
// "too dense", and a crash anywhere mid-split resumes to the same tree with no gap or duplicate.

const WINDOW = { start: "2026-10-01T10:00:00.000Z", end: "2026-10-01T11:00:00.000Z" };
const T0 = Date.parse(WINDOW.start);
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

/** 30 records spread over the hour, plus 12 in ONE second (6 per region). */
function records(): DenseRecord[] {
  const spread = Array.from({ length: 30 }, (_, i) => ({
    at: T0 + i * 120_000 + 5_000,
    region: "us-east-1",
  }));
  const dense = Array.from({ length: 12 }, (_, i) => ({
    at: T0 + 30 * 60_000 + 7_000 + i * 50,
    region: i % 2 ? "eu-west-1" : "us-east-1",
  }));
  return [...spread, ...dense];
}

async function start(t: TempCase, fs: CollectFs, session: CloudCollectSession) {
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab",
      provider: "aws",
      sources: ["ct"],
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
}

function run(
  t: TempCase,
  fs: CollectFs,
  session: CloudCollectSession,
  source: CollectSourceInfo,
  resume = false,
) {
  return runCollection(
    { fs, session, importer: pipelineImporter(t), sources: [source], now, clock: fakeClock() },
    t.dir,
    { resume },
  );
}

async function manifestOf(t: TempCase) {
  return parseManifest(await readFile(collectionPaths(t.dir).manifest, "utf8"));
}

async function events(t: TempCase) {
  return (await t.stateStore.load("c1")).forensicTimeline.length;
}

/** Every time split's children tile the parent exactly: no gap, no overlap, no repeated id. */
function expectTiled(subWindows: SubWindowStatus[], splits: ManifestSplit[]) {
  const ids = subWindows.map((s) => s.id);
  expect(new Set(ids).size).toBe(ids.length);
  for (const split of splits.filter((s) => s.mode === "time")) {
    const parent = subWindows.find((s) => s.id === split.subWindowId)!;
    const [a, b] = split.children;
    expect(a.window.start).toBe(parent.window.start);
    expect(a.window.end).toBe(b.window.start);
    expect(b.window.end).toBe(parent.window.end);
  }
}

async function uncappedBaseline() {
  const t = await tempCase();
  const fs = faultFs();
  const session = denseSession({ records: records(), cap: 1000 });
  await start(t, fs, session);
  const cp = await run(t, fs, session, denseSource({ minWindowMs: 1000 }));
  return { cp, events: await events(t) };
}

describe("decideSplit (#2312)", () => {
  const sw = (
    window: { start: string; end: string },
    partition?: Record<string, string>,
  ): SubWindowStatus => ({
    id: "s:0",
    source: "s",
    window,
    state: "capped",
    pages: 1,
    records: 10,
    restarts: 0,
    ...(partition ? { partition } : {}),
  });

  it("halves on a whole second while both halves stay at or above the minimum", () => {
    const d = decideSplit(sw(WINDOW), denseSource({ minWindowMs: 60_000 }), undefined, 1);
    expect(d.mode).toBe("time");
    expect(d.children.map((c) => c.window)).toEqual([
      { start: WINDOW.start, end: "2026-10-01T10:30:00.000Z" },
      { start: "2026-10-01T10:30:00.000Z", end: WINDOW.end },
    ]);
    expect(d.children.map((c) => c.id)).toEqual(["s:0.0", "s:0.1"]);
  });

  it("at the minimum window: partition fallback, then too dense", () => {
    const minute = { start: WINDOW.start, end: "2026-10-01T10:01:30.000Z" };
    const graph = denseSource({ minWindowMs: 60_000, partition: { key: "recordType", values: ["a", "b"] } });
    const p = decideSplit(sw(minute), graph, ["a", "b"], 1);
    expect(p.mode).toBe("partition");
    expect(p.children.map((c) => c.partition)).toEqual([{ recordType: "a" }, { recordType: "b" }]);
    expect(p.children.every((c) => c.window === minute)).toBe(true);
    expect(decideSplit(sw(minute, { recordType: "a" }), graph, ["a", "b"], 3).mode).toBe("too-dense");
    expect(decideSplit(sw(minute), denseSource({ minWindowMs: 60_000 }), undefined, 1).mode).toBe(
      "too-dense",
    );
  });

  it("names durations plainly", () => {
    expect(describeDuration(60_000)).toBe("1 min");
    expect(describeDuration(1000)).toBe("1 s");
    expect(describeDuration(250)).toBe("250 ms");
  });
});

describe("window splitting in the engine (#2312)", () => {
  it("splits to the minimum window, then marks it too dense and moves on", async () => {
    const base = await uncappedBaseline();
    expect(base.cp.status).toBe("complete");
    const t = await tempCase();
    const fs = faultFs();
    const session = denseSession({ records: records(), cap: 10 });
    await start(t, fs, session);
    const cp = await run(t, fs, session, denseSource({ minWindowMs: 1000 }));
    const m = await manifestOf(t);
    const splits = m.entries.filter((e): e is ManifestSplit => e.type === "split");
    expect(splits.filter((s) => s.mode === "time").length).toBeGreaterThan(5);
    expect(splits.filter((s) => s.mode === "too-dense")).toHaveLength(1);
    expectTiled(cp.subWindows, splits);
    expect(cp.status).toBe("partial");
    expect(cp.missing).toHaveLength(1);
    expect(cp.missing[0].reason).toMatch(/incomplete — too dense/);
    const dense = Date.parse(cp.missing[0].window.end) - Date.parse(cp.missing[0].window.start);
    expect(dense).toBeGreaterThanOrEqual(1000);
    expect(dense).toBeLessThan(2000);
    // Every leaf but the dense one is done; the capped parents' pages were imported and deduped.
    expect(leaves(cp.subWindows).filter((s) => s.state !== "done")).toHaveLength(1);
    expect(await events(t)).toBe(base.events - 2);
  });

  it("falls back on partitions at the minimum window before giving up", async () => {
    const base = await uncappedBaseline();
    const t = await tempCase();
    const fs = faultFs();
    const session = denseSession({
      records: records(),
      cap: 10,
      partitionValues: ["us-east-1", "eu-west-1"],
    });
    await start(t, fs, session);
    const source = denseSource({ minWindowMs: 1000, partition: { key: "region" } });
    const cp = await run(t, fs, session, source);
    const splits = (await manifestOf(t)).entries.filter((e): e is ManifestSplit => e.type === "split");
    const partition = splits.filter((s) => s.mode === "partition");
    expect(partition).toHaveLength(1);
    expect(partition[0].children.map((c) => c.partition)).toEqual([
      { region: "us-east-1" },
      { region: "eu-west-1" },
    ]);
    expect(session.calls.some((c) => c.partition?.region === "eu-west-1")).toBe(true);
    expect(cp.status).toBe("complete");
    expect(cp.missing).toEqual([]);
    expect(await events(t)).toBe(base.events);
  });

  it("a page cap counts as capped and splits", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = denseSession({ records: records().slice(0, 30), cap: 1000, perPage: 4 });
    await start(t, fs, session);
    const cp = await run(t, fs, session, denseSource({ minWindowMs: 1000, maxPagesPerWindow: 3 }));
    const m = await manifestOf(t);
    expect(m.pages.some((p) => p.capped === "page-cap")).toBe(true);
    expect(cp.status).toBe("complete");
  });
});

describe("a crash mid-split resumes the tree (#2312)", () => {
  it("at every manifest append: same tree, same pages, same events — no gap, no duplicate", async () => {
    const source = denseSource({ minWindowMs: 1000 });
    const ref = await tempCase();
    const refFs = faultFs();
    const refSession = denseSession({ records: records(), cap: 10 });
    await start(ref, refFs, refSession);
    const refCp = await run(ref, refFs, refSession, source);
    const refManifest = await manifestOf(ref);
    const refEvents = await events(ref);
    const appends = refManifest.entries.length - 1;
    const leafWindows = (subs: SubWindowStatus[]) =>
      leaves(subs).map((s) => `${s.id} ${s.window.start} ${s.window.end} ${s.state}`);
    const points = [...new Set([2, 3, 4, Math.floor(appends / 2), appends - 2, appends - 1])];
    for (const k of points) {
      const t = await tempCase();
      const fs = faultFs();
      const session = denseSession({ records: records(), cap: 10 });
      await start(t, fs, session);
      let count = 0;
      fs.inject("appendSync", (p) => p.endsWith("manifest.jsonl") && ++count === k, kill);
      await expect(run(t, fs, session, source)).rejects.toThrow(/simulated kill/);
      fs.clear();
      const cp = await run(t, fs, session, source, true);
      const m = await manifestOf(t);
      expect(cp.status, `crash at append ${k}`).toBe(refCp.status);
      expect(leafWindows(cp.subWindows), `crash at append ${k}`).toEqual(leafWindows(refCp.subWindows));
      expect(m.pages.length, `crash at append ${k}`).toBe(refManifest.pages.length);
      expect(await events(t), `crash at append ${k}`).toBe(refEvents);
      expectTiled(
        cp.subWindows,
        m.entries.filter((e): e is ManifestSplit => e.type === "split"),
      );
    }
  }, 60_000);
});
