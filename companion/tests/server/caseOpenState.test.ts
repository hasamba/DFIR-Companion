// #2126: the case-open panel GETs share one full-state load and keep the last one, for ONE case, at
// its exact revision, for five idle minutes. These pin the rules that make that safe: one load per
// burst, a hit within the idle period, eviction after it, a fresh read after any write, replacement
// on a case switch, a load that raced a write never kept, a departed caller never cancelling the load
// for the others, and a deleted case released at once.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { forgetCaseKeyedState } from "../../src/storage/caseKeyedState.js";
import { wholeCaseLoads } from "../../src/analysis/wholeCaseLoadLimit.js";
import { REPORT_LITE_IDLE_MS } from "../../src/reports/reportLiteCache.js";
import { caseOpenState, caseOpenStateHeld } from "../../src/routes/caseOpenState.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T10:00:00Z",
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

const flush = () => new Promise((r) => setImmediate(r));

async function until(check: () => boolean, ms = 2000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("condition not reached");
    await new Promise((r) => setTimeout(r, 5));
  }
}
const ids = (s: InvestigationState) => s.forensicTimeline.map((e) => e.id);

let root: string;
let cases: CaseStore;
let stateStore: StateStore;

async function seed(caseId: string, rows: string[]): Promise<void> {
  await stateStore.save({ ...emptyState(caseId), forensicTimeline: rows.map(ev) });
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-2126-"));
  cases = new CaseStore(root);
  for (const caseId of ["c1", "c2"]) {
    await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  }
  stateStore = new StateStore(cases);
  await seed("c1", ["a", "b"]);
  await seed("c2", ["x"]);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("case-open shared state (#2126)", () => {
  it("concurrent panel reads of one case share one full load", async () => {
    const load = vi.spyOn(stateStore, "load");
    const reader = caseOpenState(cases, stateStore);
    const states = await Promise.all(Array.from({ length: 8 }, () => reader.load("c1")));
    expect(load).toHaveBeenCalledTimes(1);
    expect(load.mock.calls[0]).toEqual(["c1"]); // the shared load takes no caller's signal
    expect(new Set(states).size).toBe(1);
    expect(ids(states[0])).toEqual(["a", "b"]);
  });

  it("a later read within the idle period is a hit at the same revision", async () => {
    const reader = caseOpenState(cases, stateStore);
    const first = await reader.load("c1");
    const load = vi.spyOn(stateStore, "load");
    expect(await caseOpenState(cases, stateStore).load("c1")).toBe(first);
    expect(load).not.toHaveBeenCalled();
    expect(caseOpenStateHeld(stateStore)).toBe(1);
  });

  it("the kept state is released after five idle minutes", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const reader = caseOpenState(cases, stateStore);
    await reader.load("c1");
    expect(caseOpenStateHeld(stateStore)).toBe(1);
    vi.advanceTimersByTime(REPORT_LITE_IDLE_MS - 1_000);
    expect(caseOpenStateHeld(stateStore)).toBe(1);
    vi.advanceTimersByTime(1_001);
    expect(caseOpenStateHeld(stateStore)).toBe(0);
    const load = vi.spyOn(stateStore, "load");
    await reader.load("c1");
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("any write changes the revision: the next read sees it", async () => {
    const reader = caseOpenState(cases, stateStore);
    expect(ids(await reader.load("c1"))).toEqual(["a", "b"]);
    await seed("c1", ["a", "b", "c"]);
    expect(ids(await reader.load("c1"))).toEqual(["a", "b", "c"]);
  });

  it("loading another case replaces the kept one", async () => {
    const reader = caseOpenState(cases, stateStore);
    await reader.load("c1");
    await reader.load("c2");
    expect(caseOpenStateHeld(stateStore)).toBe(1);
    const load = vi.spyOn(stateStore, "load");
    await reader.load("c2");
    expect(load).not.toHaveBeenCalled();
    await reader.load("c1");
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("a load that raced a write is not kept, and a read after the write never gets pre-write data", async () => {
    const original = stateStore.load.bind(stateStore);
    const readDone = deferred();
    const release = deferred();
    vi.spyOn(stateStore, "load").mockImplementationOnce(async (caseId, opts) => {
      const before = await original(caseId, opts);
      readDone.resolve();
      await release.promise;
      return before;
    });
    const reader = caseOpenState(cases, stateStore);
    const early = reader.load("c1");
    await readDone.promise;
    await seed("c1", ["a", "b", "c"]); // the write lands while the early load is still in flight
    const late = reader.load("c1"); // starts after the write: must not join the early load
    release.resolve();
    expect(ids(await early)).toEqual(["a", "b"]); // asked before the write finished
    expect(ids(await late)).toEqual(["a", "b", "c"]);
    expect(ids(await reader.load("c1"))).toEqual(["a", "b", "c"]); // the raced load was not kept
  });

  it("one caller leaving ends only its own wait; the shared load runs on for the others", async () => {
    const original = stateStore.load.bind(stateStore);
    const release = deferred();
    const load = vi.spyOn(stateStore, "load").mockImplementation(async (caseId, opts) => {
      await release.promise;
      return original(caseId, opts);
    });
    const reader = caseOpenState(cases, stateStore);
    const gone = new AbortController();
    const a = reader.load("c1", { signal: gone.signal });
    const b = reader.load("c1", { signal: new AbortController().signal });
    await flush();
    gone.abort();
    await expect(a).rejects.toMatchObject({ name: "AbortError" });
    release.resolve();
    expect(ids(await b)).toEqual(["a", "b"]);
    expect(load).toHaveBeenCalledTimes(1);
    expect(caseOpenStateHeld(stateStore)).toBe(1); // still kept for the next panel
  });

  it("a queued load every caller left never reads the case", async () => {
    const busy = [deferred(), deferred()];
    const holders = busy.map((b) => wholeCaseLoads.run(() => b.promise));
    const load = vi.spyOn(stateStore, "load");
    const reader = caseOpenState(cases, stateStore);
    const one = new AbortController();
    const two = new AbortController();
    const a = reader.load("c1", { signal: one.signal });
    const b = reader.load("c1", { signal: two.signal });
    try {
      await until(() => wholeCaseLoads.waiting === 1); // one shared load queued for both
      await flush();
      expect(wholeCaseLoads.waiting).toBe(1);
      one.abort();
      two.abort();
      await expect(a).rejects.toMatchObject({ name: "AbortError" });
      await expect(b).rejects.toMatchObject({ name: "AbortError" });
      expect(wholeCaseLoads.waiting).toBe(0);
    } finally {
      busy.forEach((d) => d.resolve());
      await Promise.all(holders);
    }
    expect(load).not.toHaveBeenCalled();
  });

  it("a deleted case's kept state is released at once", async () => {
    await caseOpenState(cases, stateStore).load("c1");
    forgetCaseKeyedState(root, "c2"); // another case: kept
    expect(caseOpenStateHeld(stateStore)).toBe(1);
    forgetCaseKeyedState(root, "c1");
    expect(caseOpenStateHeld(stateStore)).toBe(0);
  });

  it("the shared state is deep-frozen under the test runner", async () => {
    const state = await caseOpenState(cases, stateStore).load("c1");
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.forensicTimeline)).toBe(true);
    expect(Object.isFrozen(state.forensicTimeline[0])).toBe(true);
    // StateStore.load itself still hands every write caller its own mutable copy.
    const own = await stateStore.load("c1");
    expect(Object.isFrozen(own.forensicTimeline)).toBe(false);
  });
});
