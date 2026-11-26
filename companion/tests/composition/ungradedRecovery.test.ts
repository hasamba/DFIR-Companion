// #2891: the start-up sweep. Every case is asked once (one query, no lock); a case with rows still
// waiting for the content tagger is re-graded inside its import section — never nested in another one.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { ungradedRowRecovery } from "../../src/composition/ungradedRecovery.js";
import { forensicGradePendingRows } from "../../src/analysis/gradeMark.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { RouteContext } from "../../src/routes/context.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ev = (id: string, extra: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-05-02T10:00:00Z",
  description: `row ${id}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: ["0001_a.json"],
  ...extra,
});

let root: string;
let cases: CaseStore;
let stateStore: StateStore;
let warn: ReturnType<typeof vi.spyOn>;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-ungraded-sweep-"));
  cases = new CaseStore(root);
  for (const caseId of ["c1", "c2"])
    await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

function context(importLock: ImportLock): RouteContext {
  const options = {
    stateStore,
    superTimelineStore: new SuperTimelineStore(cases),
    forensicGateControlStore: new ForensicGateControlStore(cases),
  };
  const runStateExclusive = <T>(_c: string, fn: () => Promise<T>): Promise<T> => fn();
  const demote = createImportDemote({ options, runStateExclusive });
  return {
    options,
    store: cases,
    runStateExclusive,
    serverLogger: getServerLogger(),
    demoteForensic: demote.demoteForensic,
    importLock,
  } as unknown as RouteContext;
}

async function seed(caseId: string, rows: ForensicEvent[]): Promise<void> {
  const state = await stateStore.load(caseId);
  await stateStore.save({ ...state, forensicTimeline: rows });
}

describe("start-up re-grade sweep (#2891)", () => {
  it("re-grades only the case with waiting rows, inside its import section", async () => {
    await seed("c1", [ev("w1", { importBatchId: "b1", gradePending: true })]);
    await seed("c2", [ev("old", { importBatchId: "b0" })]); // graded before #2891: untouched
    const lock = new ImportLock();
    let release!: () => void;
    const holder = lock.runExclusive("c1", () => new Promise<void>((r) => (release = r)));
    const sweep = ungradedRowRecovery(context(lock))();
    await new Promise((r) => setTimeout(r, 50));
    expect((await forensicGradePendingRows(stateStore, "c1")).length).toBe(1); // waits for the section
    release();
    await holder;
    await sweep;
    expect((await stateStore.load("c1")).forensicTimeline).toEqual([]); // tagged (no rule) → demoted
    expect((await stateStore.load("c2")).forensicTimeline.map((e) => e.id)).toEqual(["old"]);
    expect(warn.mock.calls.some(([m]: unknown[]) => /c1: start-up re-grade — 1 row/.test(String(m)))).toBe(
      true,
    );
    expect(warn.mock.calls.some(([m]: unknown[]) => /c2: start-up re-grade/.test(String(m)))).toBe(false);
  });
});
