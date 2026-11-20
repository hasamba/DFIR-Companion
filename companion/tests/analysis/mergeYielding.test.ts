import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mergeDelta, runTimelineChain, timelinePasses } from "../../src/analysis/stateMerge.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { fixedPoints } from "../../src/analysis/incrementalMergeRows.js";
import { clampOutlierYears } from "../../src/analysis/timeYearClamp.js";
import {
  fixedPointsYielding,
  mergeDeltaYielding,
  runTimelineChainYielding,
} from "../../src/analysis/mergeYielding.js";
import { mapYielding } from "../../src/analysis/yieldToEventLoop.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { fixtureTimeline } from "./fixtures/mergeLoadFixture.js";
import { loopLag } from "./helpers/loopLag.js";

// #2716: the whole-case merge and the index pass after it ran as one synchronous block, minutes long
// on a large import. The yielding versions must give the same answer, in the same order, and must let
// timers run while they work.

const AT = "2026-02-01T00:00:00.000Z";
const CTX = { windowSequence: 1, timestamp: AT, sourceScreenshots: ["fixture.json"] };
const sha = (v: unknown): string => createHash("sha256").update(JSON.stringify(v)).digest("hex");

function fixtureDelta(count: number): AnalysisDelta {
  return {
    findings: [],
    iocs: [{ id: "i1", type: "ip", value: "198.51.100.7" }],
    mitreTechniques: [],
    forensicEvents: fixtureTimeline(count),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "fixture note",
    summary: "",
  } as never;
}

// Recorded from the chain and merge BEFORE the pass list was introduced (#2716): the refactor and
// both runners must reproduce the old outputs byte for byte, not merely agree with each other.
const FROZEN = {
  merge: "b5998e8eb42c4288edf77f70c6834365b2cca1d77eb5f8f7e8264768add059bd",
  chain: "cf1f431630f04fa932ee6561a1e2cf68743c61cc3bbba402410515ede1ab481e",
  fixed: "4e488ed8017933ef7989bbd7df2054677f2a64d8d6b2b3c04562751348eb1902",
};

describe("the yielding merge gives the synchronous merge's result (#2716)", () => {
  it("the chain and the merge still produce the outputs recorded before the pass list", () => {
    const events = fixtureTimeline(600);
    const merged = mergeDelta(emptyState("c1"), fixtureDelta(600), CTX);
    expect(sha(runTimelineChain(events, [], AT))).toBe(FROZEN.chain);
    expect(sha(merged)).toBe(FROZEN.merge);
    expect(sha(fixedPoints(merged.forensicTimeline, AT))).toBe(FROZEN.fixed);
    // The fixture is not inert: passes rewrite rows and correlation folds the duplicates.
    expect(merged.forensicTimeline.length).toBeLessThan(600);
  });

  it("runTimelineChainYielding, mergeDeltaYielding and fixedPointsYielding reproduce them", async () => {
    const events = fixtureTimeline(600);
    const input = structuredClone(events);
    expect(sha(await runTimelineChainYielding(events, [], AT))).toBe(FROZEN.chain);
    const merged = await mergeDeltaYielding(emptyState("c1"), fixtureDelta(600), CTX);
    expect(sha(merged)).toBe(FROZEN.merge);
    expect(sha(await fixedPointsYielding(merged.forensicTimeline, AT))).toBe(FROZEN.fixed);
    expect(events).toEqual(input); // never mutates its input
  });

  it("matches the synchronous merge on a state that already holds rows, IOCs and a second import", async () => {
    const first = mergeDelta(emptyState("c1"), fixtureDelta(300), CTX);
    const second = deltaSchema.parse({ ...fixtureDelta(450), timelineNote: "second" });
    const ctx2 = { ...CTX, timestamp: "2026-02-02T00:00:00.000Z" };
    expect(await mergeDeltaYielding(first, second, ctx2)).toEqual(mergeDelta(first, second, ctx2));
  });

  it("passes the clamp and coverage switches through exactly as runTimelineChain does", async () => {
    const events = fixtureTimeline(240);
    const keep = (e: readonly unknown[]) => [...e] as never;
    expect(await runTimelineChainYielding(events, [], AT, keep, false)).toEqual(
      runTimelineChain(events, [], AT, keep, false),
    );
    expect(timelinePasses([], AT, clampOutlierYears, true).length).toBeGreaterThan(20);
  });

  it("mapYielding returns map's values in order", async () => {
    const items = Array.from({ length: 5000 }, (_, i) => i);
    expect(await mapYielding(items, (n, i) => n * 2 + i, 0)).toEqual(items.map((n, i) => n * 2 + i));
  });
});

describe("the yielding merge lets the event loop run (#2716)", () => {
  it("a timer keeps firing during a large merge, where the synchronous merge starves it", async () => {
    const delta = fixtureDelta(6000);
    const sync = await loopLag(async () => {
      mergeDelta(emptyState("c1"), delta, CTX);
    });
    const yielding = await loopLag(() => mergeDeltaYielding(emptyState("c1"), delta, CTX));
    // The synchronous merge is one block: the timer cannot fire until it ends.
    expect(sync.ticks).toBeLessThanOrEqual(1);
    // The yielding merge hands the loop a turn between ~35 passes and its stages.
    expect(yielding.ticks).toBeGreaterThanOrEqual(10);
    // Shorter than the one synchronous block. Not a fixed ratio: on a loaded CI runner (Windows) a
    // single GC pause inside a slice put the longest gap at 66–79% of the sync block. The tick count
    // above is what proves the loop ran during the merge.
    expect(yielding.maxGapMs).toBeLessThan(Math.max(250, sync.maxGapMs));
  });
});

describe("the full-state merge under the case lock (#2716)", () => {
  let root: string;
  let store: StateStore;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-merge-yield-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "c1", investigator: "i", aiProvider: null });
    store = new StateStore(cases);
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("still serializes with the next critical section, though timers ran during the merge", async () => {
    const lock = new StateLock();
    const delta = deltaSchema.parse(fixtureDelta(1500));
    const order: string[] = [];
    let ticksDuringMerge = 0;
    const timer = setInterval(() => ticksDuringMerge++, 1);
    const merge = lock.runExclusive("c1", async () => {
      await mergeIntoCase(store, "c1", delta, CTX, (s) => mergeDeltaYielding(s, delta, CTX));
      order.push("merge done");
    });
    const next = lock.runExclusive("c1", async () => {
      order.push("next started");
    });
    await Promise.all([merge, next]);
    clearInterval(timer);
    expect(order).toEqual(["merge done", "next started"]);
    expect(ticksDuringMerge).toBeGreaterThan(0);
    const stored = (await store.load("c1")).forensicTimeline.map((e) => e.id);
    expect(stored).toEqual(mergeDelta(emptyState("c1"), delta, CTX).forensicTimeline.map((e) => e.id));
  });

  it("indexes nothing from the merge's copy when a write commits during the index pass", async () => {
    const delta = deltaSchema.parse(fixtureDelta(120));
    const original = store.mergeIndexWrite.bind(store);
    store.mergeIndexWrite = async (...args: Parameters<typeof original>) => {
      // An outside write commits while the sliced index pass computes, before its write is posted.
      const [r] = await store.forensicRowsById("c1", ["fx1"]);
      await store.updateForensicRows("c1", [{ ...r, event: { ...r.event, severity: "Critical" } }]);
      return original(...args);
    };
    await mergeIntoCase(store, "c1", delta, CTX, (s) => mergeDeltaYielding(s, delta, CTX));
    store.mergeIndexWrite = original;
    // The worker refused the stale index, so the case is still marked for a full merge, and the
    // outside write survived.
    const snap = await store.mergeSnapshot("c1");
    expect(snap?.stale.length ?? 0).toBeGreaterThan(50);
    const [row] = await store.forensicRowsById("c1", ["fx1"]);
    expect(row.event.severity).toBe("Critical");
  });
});
