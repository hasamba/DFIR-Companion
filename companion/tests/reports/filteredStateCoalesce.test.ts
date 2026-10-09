import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { wholeCaseLoads } from "../../src/analysis/wholeCaseLoadLimit.js";

// #1915: the dashboard fans out to many report projections of one case at once. They share the
// whole-case load instead of each materialising its own copy — but a projection requested after an
// edit finished always reflects that edit (a stale report is an integrity bug).

let caseStore: CaseStore;
let stateStore: StateStore;
let writer: ReportWriter;

const event = (id: string, timestamp: string): ForensicEvent => ({
  id,
  timestamp,
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

async function seed(ids: string[]): Promise<void> {
  const state = emptyState("c1");
  ids.forEach((id, i) => state.forensicTimeline.push(event(id, `2026-06-01T1${i}:00:00Z`)));
  await stateStore.save(state);
}

const ids = async (): Promise<string[]> =>
  (await writer.filteredState("c1")).forensicTimeline.map((e) => e.id);

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-coalesce-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  writer = new ReportWriter(caseStore, stateStore, {
    scope: new ScopeStore(caseStore),
    falsePositives: new FalsePositiveStore(caseStore),
  });
  await seed(["a", "b"]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ReportWriter shares concurrent whole-case loads (#1915)", () => {
  it("a dashboard-style fan-out of six projections loads the case at most twice", async () => {
    const load = vi.spyOn(stateStore, "load");
    const results = await Promise.all([
      writer.swimlane("c1"),
      writer.timelineGaps("c1"),
      writer.iocSources("c1"),
      writer.anomalies("c1"),
      writer.phases("c1"),
      writer.filteredState("c1"),
    ]);
    expect(load.mock.calls.length).toBeLessThanOrEqual(2);
    expect((results[5] as { forensicTimeline: unknown[] }).forensicTimeline).toHaveLength(2);
  });

  it("the report-lite and full loads are separate cohorts that never join each other (#2057)", async () => {
    const load = vi.spyOn(stateStore, "load");
    const [lite, full] = await Promise.all([
      writer.filteredState("c1", true),
      writer.filteredState("c1"),
      writer.swimlane("c1"),
      writer.timelineGaps("c1"),
      writer.anomalies("c1"),
      writer.phases("c1"),
    ]);
    const calls = load.mock.calls.map((args) => JSON.stringify(args));
    expect(calls.sort()).toEqual(
      [JSON.stringify(["c1"]), JSON.stringify(["c1", { slimCanonical: true }])].sort(),
    );
    expect(lite).not.toBe(full);
    expect((lite as { forensicTimeline: unknown[] }).forensicTimeline).toHaveLength(2);
  });

  it("a request that arrives after an import finished sees the new event, even with an older load still running", async () => {
    const original = stateStore.load.bind(stateStore);
    let releaseFirst!: () => void;
    const firstHeld = new Promise<void>((r) => (releaseFirst = r));
    let firstRead!: () => void;
    const firstReadDone = new Promise<void>((r) => (firstRead = r));
    vi.spyOn(stateStore, "load").mockImplementationOnce(async (caseId: string) => {
      const before = await original(caseId); // read BEFORE the import below
      firstRead();
      await firstHeld;
      return before;
    });
    const early = ids();
    await firstReadDone;
    await seed(["a", "b", "c"]); // the "import" completes while the early load is still running
    const late = ids(); // the analyst's refresh after the import finished
    releaseFirst();
    expect(await early).toEqual(["a", "b"]);
    expect(await late).toEqual(["a", "b", "c"]);
  });

  it("a scope edit made between two requests is applied to the second", async () => {
    expect(await ids()).toEqual(["a", "b"]);
    await new ScopeStore(caseStore).save("c1", {
      start: "2026-06-01T10:30:00Z",
      end: "2026-06-01T23:00:00Z",
    });
    expect(await ids()).toEqual(["b"]);
  });

  it("a failed load is not remembered: the next request loads again", async () => {
    vi.spyOn(stateStore, "load").mockRejectedValueOnce(new Error("disk busy"));
    await expect(writer.timelineGaps("c1")).rejects.toThrow("disk busy");
    expect(await ids()).toEqual(["a", "b"]);
  });

  it("every whole-case load, report or not, runs under one process-wide permit", async () => {
    const run = vi.spyOn(wholeCaseLoads, "run");
    await stateStore.load("c1");
    expect(run).toHaveBeenCalledTimes(1);
    expect(wholeCaseLoads.active).toBe(0);
    // A report projection takes its permit before the load and keeps it for the whole projection;
    // the StateStore.load inside reuses it instead of queueing for a second one.
    const original = stateStore.load.bind(stateStore);
    let activeDuringLoad = -1;
    vi.spyOn(stateStore, "load").mockImplementationOnce(async (caseId: string) => {
      activeDuringLoad = wholeCaseLoads.active;
      const loaded = await original(caseId);
      expect(wholeCaseLoads.active).toBe(1);
      return loaded;
    });
    await writer.timelineGaps("c1");
    expect(activeDuringLoad).toBe(1);
    expect(wholeCaseLoads.active).toBe(0);
  });
});
