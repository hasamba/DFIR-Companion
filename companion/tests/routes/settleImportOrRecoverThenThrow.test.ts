// #2891 (gap 3): the import paths that REPORT a settle failure (dedicated import routes, CrowdStrike
// NG-SIEM search, Watson paste, cloud collection pages, the import replay) used to leave the rows
// the importer had already merged unstamped and untagged; the next import's case-wide demote moved
// them out as Info. The guarded settle now settles them first, then rethrows, so the import still
// fails visibly. Real stores (state, super-timeline, forensic gate, demote).
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { settleImportOrRecoverThenThrow } from "../../src/routes/importRowRecovery.js";
import type { SettleDeps } from "../../src/routes/importSettle.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { failSettleAfterStamp } from "../helpers/settleFailure.js";

const MINE = "0009_dedicated.json";

const ev = (id: string, severity: ForensicEvent["severity"], description = `row ${id}`): ForensicEvent => ({
  id,
  timestamp: "2026-05-02T10:00:00Z",
  description,
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [MINE],
  sources: ["Sysmon"],
});

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let options: AppOptions;
let lock: StateLock;
let warn: ReturnType<typeof vi.spyOn>;
const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-settle-rethrow-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  lock = new StateLock();
  options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: new ForensicGateControlStore(cases),
  };
  warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

/** The tagger stand-in raises "marker" rows to High, as a one-rule ruleset would. */
function deps(offered: ForensicEvent[][] = []) {
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  const demoteForensic = vi.fn(demote.demoteForensic);
  const d: SettleDeps = {
    stateStore,
    runStateExclusive: runExclusive,
    superTimelineStore: superStore,
    autoTagImported: async (caseId, added) => {
      offered.push(added);
      await runExclusive(caseId, async () => {
        const state = await stateStore.load(caseId);
        const raise = (e: ForensicEvent) =>
          added.some((a) => a.id === e.id) && e.description.includes("marker")
            ? { ...e, severity: "High" as const }
            : e;
        await stateStore.save({ ...state, forensicTimeline: state.forensicTimeline.map(raise) });
      });
    },
    demoteForensic,
  };
  return { d, demoteForensic };
}

async function importRows(d: SettleDeps, rows: ForensicEvent[]) {
  const baseline = await captureImportBaseline(stateStore, "c1");
  await runExclusive("c1", async () => {
    const state = await stateStore.load("c1");
    await stateStore.save({ ...state, forensicTimeline: [...state.forensicTimeline, ...rows] });
  });
  try {
    return await settleImportOrRecoverThenThrow(
      d,
      { caseId: "c1", storedNames: [MINE], tag: "t" },
      baseline,
      MINE,
    );
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

const forensic = async () => new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
async function superIds(): Promise<string[]> {
  const ids: string[] = [];
  for await (const b of superStore.eventBatches("c1")) for (const e of b) ids.push(e.id);
  return ids.sort();
}
const warned = (re: RegExp): boolean => warn.mock.calls.some(([m]: unknown[]) => re.test(String(m)));
const ROWS = () => [ev("marker-1", "Info", "ntds marker"), ev("plain-1", "Info")];

describe("settleImportOrRecoverThenThrow (#2891)", () => {
  it("a settle that fails after stamping: rows are graded before the next demote, and the error still surfaces", async () => {
    const fired = failSettleAfterStamp(stateStore);
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    await expect(importRows(d, ROWS())).rejects.toThrow("out of memory");
    expect(fired()).toBe(true);

    const after = await forensic();
    expect(after.get("marker-1")?.severity).toBe("High"); // tagged before the demote
    expect(after.has("plain-1")).toBe(false); // demoted — into the super-timeline, not lost
    expect(await superIds()).toEqual(["marker-1", "plain-1"]);
    expect(new Set(offered.flat().map((e) => e.importBatchId)).size).toBe(1); // one batch, re-used
    expect(warned(/settled 2 row\(s\) of 0009_dedicated\.json whose settle failed/)).toBe(true);
  });

  it("a successful settle is unchanged: one tagger pass, one demote, no recovery", async () => {
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensic } = deps(offered);
    const settled = await importRows(d, ROWS());
    expect(settled.timelineDiff.added).toHaveLength(1); // the graded row stays
    expect(demoteForensic).toHaveBeenCalledTimes(1);
    expect(offered).toHaveLength(1);
    expect(warned(/settled \d+ row\(s\)/)).toBe(false);
  });

  it("a failure AFTER demote rethrows without re-stamping or demoting again", async () => {
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensic } = deps(offered);
    const real = createImportDemote({ options, runStateExclusive: runExclusive }).demoteForensic;
    let demoted = false;
    demoteForensic.mockImplementation(async (caseId: string) => {
      const out = await real(caseId);
      demoted = true;
      return out;
    });
    const realOutline = stateStore.forensicOutline.bind(stateStore);
    vi.spyOn(stateStore, "forensicOutline").mockImplementation(async (...args) => {
      if (demoted) throw new Error("outline read failed");
      return realOutline(...args);
    });
    await expect(importRows(d, ROWS())).rejects.toThrow("outline read failed");
    expect(demoteForensic).toHaveBeenCalledTimes(1);
    expect(offered).toHaveLength(1);
    expect((await forensic()).get("marker-1")?.severity).toBe("High");
    expect(warned(/settled \d+ row\(s\)/)).toBe(false);
  });

  it("when the recovery fails too, the ORIGINAL settle error still surfaces", async () => {
    failSettleAfterStamp(stateStore);
    const { d } = deps();
    const realLedger = stateStore.loadOverviewWithoutIocs.bind(stateStore);
    let calls = 0;
    vi.spyOn(stateStore, "loadOverviewWithoutIocs").mockImplementation(async (caseId) => {
      if (++calls > 1) throw new Error("ledger unreadable"); // the settle's read passes, the recovery's fails
      return realLedger(caseId);
    });
    await expect(importRows(d, ROWS())).rejects.toThrow("out of memory");
    expect(warned(/did not work either: ledger unreadable/)).toBe(true);
  });
});
