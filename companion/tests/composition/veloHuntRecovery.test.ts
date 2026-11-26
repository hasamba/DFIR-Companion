// #2851: a hunt collect a restart cut off while IMPORTING leaves whole-file rows in the forensic
// timeline that never crossed the seam. Start-up settles exactly those rows — this hunt's, without an
// import stamp — and nothing else, once. Real stores (state, super-timeline, forensic gate, demote).
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { buildManualEvent } from "../../src/analysis/manualEntry.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import {
  holdImportsDuring,
  huntFilePattern,
  importingMarks,
  recoverFailedHuntSettle,
  settleAfterFailedSettle,
  settleInterruptedHuntRows,
  uploadStoredNames,
  type HuntRecoveryDeps,
} from "../../src/composition/veloHuntRecovery.js";
import {
  createVeloHuntStatusTimers,
  INTERRUPTED_IMPORT_MESSAGE,
} from "../../src/composition/veloHuntStatusTimers.js";
import { createHuntEvictions, settleHuntCollect } from "../../src/composition/veloHuntSettle.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import type { DemoteOptions } from "../../src/analysis/gradeMark.js";

const MINE = "0003_velo-hunt_H.1_Windows.System.Pslist.json";
const OTHER = "0004_velo-hunt_H.10_Windows.System.Pslist.json";
const UPLOAD = "0005_thor-report.json";

function ev(
  id: string,
  severity: ForensicEvent["severity"],
  extra: Partial<ForensicEvent> = {},
): ForensicEvent {
  return {
    id,
    timestamp: "2026-05-02T10:00:00Z",
    description: `row ${id}`,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [MINE],
    sources: ["Velociraptor"],
    ...extra,
  };
}

let root: string;
let cases: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let lock: StateLock;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-hunt-recovery-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  lock = new StateLock();
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

/** The tagger stand-in raises "marker" rows to High, as a one-rule ruleset would. */
function deps(offered: ForensicEvent[][]) {
  const options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: new ForensicGateControlStore(cases),
  } as unknown as AppOptions;
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  const demoteForensicForCase = vi.fn(demote.demoteForensicForCase);
  const d: HuntRecoveryDeps = {
    options,
    importLock: new ImportLock(),
    runStateExclusive: runExclusive,
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
    demoteForensicForCase,
  };
  return { d, demoteForensicForCase };
}

async function addRows(rows: ForensicEvent[]): Promise<void> {
  await runExclusive("c1", async () => {
    const state: InvestigationState = await stateStore.load("c1");
    await stateStore.save({ ...state, forensicTimeline: [...state.forensicTimeline, ...rows] });
  });
}

async function superIds(): Promise<string[]> {
  const ids: string[] = [];
  for await (const b of superStore.eventBatches("c1")) for (const e of b) ids.push(e.id);
  return ids.sort();
}

const forensic = async () => (await stateStore.load("c1")).forensicTimeline;

describe("settleInterruptedHuntRows (#2851)", () => {
  it("matches this hunt's stored files only, with the stored-name sanitising", () => {
    const re = huntFilePattern("H.1");
    expect(re.test(MINE)).toBe(true);
    expect(re.test(OTHER)).toBe(false); // H.10 is another hunt
    expect(re.test("velo-hunt_H.1_x.json")).toBe(false); // not a stored name
    expect(huntFilePattern("H 1/x").test("0001_velo-hunt_H_1_x_A.json")).toBe(true);
  });

  it("selects only this hunt's unstamped rows, then stamps, dual-writes, tags and demotes them", async () => {
    const manual = buildManualEvent({
      timestamp: "2026-05-02T11:00:00Z",
      description: "note",
      severity: "Info",
    });
    await addRows([
      ev("marker-1", "Info", { description: "notepad marker" }),
      ev("plain-1", "Info"),
      ev("graded-1", "High"),
      ev("batched-1", "Info", { importBatchId: "b-1", importedAt: "2026-05-01T00:00:00Z" }),
      ev("other-1", "Medium", { sourceScreenshots: [OTHER] }),
      ev("promoted-1", "Info", { promotedAt: "2026-05-02T00:00:00Z" }),
      { ...manual, sourceScreenshots: [MINE] },
    ]);
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    expect(await settleInterruptedHuntRows(d, "c1", "H.1")).toBe(3);

    const offeredRows = offered.flat();
    expect(offeredRows.map((e) => e.id).sort()).toEqual(["graded-1", "marker-1", "plain-1"]);
    // The tagger sees the STAMPED rows, one batch id for the recovery.
    const batchIds = new Set(offeredRows.map((e) => e.importBatchId));
    expect(batchIds.size).toBe(1);
    expect([...batchIds][0]).toEqual(expect.any(String));
    expect(offeredRows.every((e) => typeof e.importedAt === "string")).toBe(true);

    const after = new Map((await forensic()).map((e) => [e.id, e]));
    expect(after.get("marker-1")?.severity).toBe("High"); // tagger before demote
    expect(after.has("plain-1")).toBe(false); // demoted, into the super-timeline
    expect(after.get("graded-1")?.importBatchId).toEqual([...batchIds][0]);
    expect(after.get("batched-1")).toBeUndefined(); // an Info row of the batched path: the demote's
    expect(after.get("other-1")?.importBatchId).toBeUndefined(); // another hunt's row, untouched
    expect(after.get("promoted-1")?.importBatchId).toBeUndefined();
    expect(after.get(manual.id)?.importBatchId).toBeUndefined();
    const sup = await superIds();
    for (const id of ["graded-1", "marker-1", "plain-1"]) expect(sup).toContain(id);
    expect(sup).not.toContain("other-1");
  });

  it("a second run changes nothing — no tagger call, no demote", async () => {
    await addRows([ev("marker-1", "Info", { description: "marker" }), ev("graded-1", "High")]);
    const first = deps([]);
    expect(await settleInterruptedHuntRows(first.d, "c1", "H.1")).toBe(2);
    const before = JSON.stringify(await forensic());
    const superBefore = await superIds();
    const offered: ForensicEvent[][] = [];
    const second = deps(offered);
    expect(await settleInterruptedHuntRows(second.d, "c1", "H.1")).toBe(0);
    expect(offered).toEqual([]);
    expect(second.demoteForensicForCase).not.toHaveBeenCalled();
    expect(JSON.stringify(await forensic())).toBe(before);
    expect(await superIds()).toEqual(superBefore);
  });

  it("leaves a batched artifact cut off mid-run alone (its rows are stamped per batch)", async () => {
    const stamp = { importBatchId: "batch-1", importedAt: "2026-05-01T00:00:00Z" };
    await addRows([ev("b-1", "High", stamp), ev("b-2", "Medium", stamp)]);
    const before = JSON.stringify(await forensic());
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensicForCase } = deps(offered);
    expect(await settleInterruptedHuntRows(d, "c1", "H.1")).toBe(0);
    expect(offered).toEqual([]);
    expect(demoteForensicForCase).not.toHaveBeenCalled();
    expect(JSON.stringify(await forensic())).toBe(before);
  });

  // #2852 case 2: an uploaded report's rows are stored under the report's own name, not the hunt's.
  it("also settles the rows of the uploaded reports the job named — exact stored names only", async () => {
    await addRows([
      ev("art-1", "High"),
      ev("up-1", "Info", { description: "thor marker", sourceScreenshots: [UPLOAD] }),
      ev("up-other", "Medium", { sourceScreenshots: ["0009_other-report.json"] }),
    ]);
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    expect(await settleInterruptedHuntRows(d, "c1", "H.1", { uploadFiles: [UPLOAD] })).toBe(2);
    expect(
      offered
        .flat()
        .map((e) => e.id)
        .sort(),
    ).toEqual(["art-1", "up-1"]);
    const after = new Map((await forensic()).map((e) => [e.id, e]));
    expect(after.get("up-1")?.severity).toBe("High"); // tagged before the demote
    expect(after.get("up-other")?.importBatchId).toBeUndefined();
  });

  it("without the stored names (an older job) an upload's rows are not selected", async () => {
    await addRows([ev("up-1", "Medium", { sourceScreenshots: [UPLOAD] })]);
    const { d, demoteForensicForCase } = deps([]);
    expect(await settleInterruptedHuntRows(d, "c1", "H.1")).toBe(0);
    expect(demoteForensicForCase).not.toHaveBeenCalled();
  });

  it("a failing super-timeline append keeps the rows in the forensic timeline", async () => {
    await addRows([ev("plain-1", "Info"), ev("graded-1", "High")]);
    vi.spyOn(superStore, "appendReporting").mockRejectedValue(new Error("disk full"));
    vi.spyOn(superStore, "append").mockRejectedValue(new Error("disk full"));
    const { d } = deps([]);
    await settleInterruptedHuntRows(d, "c1", "H.1");
    const ids = (await forensic()).map((e) => e.id).sort();
    expect(ids).toEqual(["graded-1", "plain-1"]); // never in neither record
  });
});

// #2852 case 1: the collect's own settle failed in-process — the rows it did not reach are settled
// at once, inside the section the collect still holds (the import lock is not re-entrant).
describe("settleAfterFailedSettle (#2852)", () => {
  it("settles the collect's unstamped rows while the collect holds the import section", async () => {
    await addRows([
      ev("marker-1", "Info", { description: "marker" }),
      ev("up-1", "High", { sourceScreenshots: [UPLOAD] }),
    ]);
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      const settledInside = await d.importLock.runPastHolds("c1", () =>
        settleAfterFailedSettle(d, "c1", "H.1", [UPLOAD]),
      );
      expect(settledInside).toEqual({ settled: 2 });
      expect(
        offered
          .flat()
          .map((e) => e.id)
          .sort(),
      ).toEqual(["marker-1", "up-1"]);
      expect(warn.mock.calls.some(([m]) => /settle failed/.test(String(m)) && /H\.1/.test(String(m)))).toBe(
        true,
      );
    } finally {
      warn.mockRestore();
    }
  });

  it("never throws: a second failure is logged with the case and hunt id", async () => {
    await addRows([ev("plain-1", "Info")]);
    vi.spyOn(stateStore, "loadOverviewWithoutIocs").mockRejectedValue(new Error("out of memory"));
    const { d } = deps([]);
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      await expect(settleAfterFailedSettle(d, "c1", "H.1", [])).resolves.toEqual({
        settled: 0,
        error: "out of memory",
      });
      const lines = warn.mock.calls.map(([m]) => String(m));
      expect(lines.some((l) => l.includes("c1") && l.includes("H.1") && l.includes("out of memory"))).toBe(
        true,
      );
    } finally {
      warn.mockRestore();
    }
  });

  it("reports a second failure to its caller, not only to the log (#2888)", async () => {
    await addRows([ev("plain-1", "Info")]);
    vi.spyOn(stateStore, "loadOverviewWithoutIocs").mockRejectedValue(new Error("out of memory"));
    const { d } = deps([]);
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      const out = await recoverFailedHuntSettle(d, "c1", { huntId: "H.1" }, { error: "x", seamFailed: true });
      expect(out).toEqual({ settled: 0, error: "out of memory" });
    } finally {
      warn.mockRestore();
    }
  });

  it("uploadStoredNames: the stored names, or nothing for a collect without uploads", () => {
    expect(uploadStoredNames([{ storedName: "0001_a.json" }, { storedName: "0002_b.json" }])).toEqual([
      "0001_a.json",
      "0002_b.json",
    ]);
    expect(uploadStoredNames([])).toBeUndefined();
  });

  it("importingMarks: the uploads' stored names and a fresh batch id per collect (#2888)", () => {
    const a = importingMarks([{ storedName: "0001_a.json" }]);
    const b = importingMarks([]);
    expect(a.importingUploads).toEqual(["0001_a.json"]);
    expect(b.importingUploads).toBeUndefined();
    expect(a.importingBatchId).toEqual(expect.any(String));
    expect(b.importingBatchId).toEqual(expect.any(String));
    expect(a.importingBatchId).not.toBe(b.importingBatchId);
  });
});

// #2888: the settle stamps first. A settle that failed partway through the stamp, or after it (the
// dual-write's page reads), left rows carrying its batch id that the unstamped-only selector skipped.
// The collect now picks that batch id itself, so the recovery can select those rows too.
describe("a settle that failed after it stamped some or all rows (#2888)", () => {
  const FAILED = "batch-of-the-failed-settle";
  const failedStamp = { importBatchId: FAILED, importedAt: "2026-05-02T12:00:00Z" };

  async function partlyStamped(): Promise<void> {
    await addRows([
      ev("stamped-marker", "Info", { description: "marker", ...failedStamp }),
      ev("stamped-plain", "Info", failedStamp),
      ev("unstamped-marker", "Info", { description: "marker" }),
      ev("earlier-batch", "Medium", { importBatchId: "b-earlier", importedAt: "2026-05-01T00:00:00Z" }),
    ]);
  }

  it("selects the unstamped rows AND those of the failed batch, re-stamped with that same id", async () => {
    await partlyStamped();
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    expect(await settleInterruptedHuntRows(d, "c1", "H.1", { batchId: FAILED })).toBe(3);
    const rows = offered.flat();
    expect(rows.map((e) => e.id).sort()).toEqual(["stamped-marker", "stamped-plain", "unstamped-marker"]);
    expect(rows.every((e) => e.importBatchId === FAILED)).toBe(true); // a retry finds them again
    const after = new Map((await forensic()).map((e) => [e.id, e]));
    expect(after.get("stamped-marker")?.severity).toBe("High"); // tagged before the demote
    expect(after.get("unstamped-marker")?.severity).toBe("High");
    expect(after.has("stamped-plain")).toBe(false); // demoted, after the tagger
    expect(after.get("earlier-batch")?.importBatchId).toBe("b-earlier"); // another batch: left alone
    expect(await superIds()).toEqual(expect.arrayContaining(["stamped-plain", "stamped-marker"]));
  });

  it("in-process: a settle whose seam call threw is fully re-graded, partly stamped or not", async () => {
    await partlyStamped();
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      const job = { huntId: "H.1", importingBatchId: FAILED };
      const out = await recoverFailedHuntSettle(d, "c1", job, { error: "out of memory", seamFailed: true });
      expect(out).toEqual({ settled: 3 });
      expect(
        offered
          .flat()
          .map((e) => e.id)
          .sort(),
      ).toEqual(["stamped-marker", "stamped-plain", "unstamped-marker"]);
    } finally {
      warn.mockRestore();
    }
  });

  it("a failure AFTER a complete settle (record or Undo entry) does not re-stamp its rows", async () => {
    await addRows([ev("stamped-marker", "Info", { description: "marker", ...failedStamp })]);
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensicForCase } = deps(offered);
    const job = { huntId: "H.1", importingBatchId: FAILED };
    expect(await recoverFailedHuntSettle(d, "c1", job, { error: "disk full" })).toEqual({ settled: 0 });
    expect(offered).toEqual([]);
    expect(demoteForensicForCase).not.toHaveBeenCalled();
  });

  it("a clean settle runs no recovery at all", async () => {
    await addRows([ev("unstamped-marker", "Info", { description: "marker" })]);
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensicForCase } = deps(offered);
    const job = { huntId: "H.1", importingBatchId: FAILED };
    expect(await recoverFailedHuntSettle(d, "c1", job, {})).toBeUndefined();
    expect(offered).toEqual([]);
    expect(demoteForensicForCase).not.toHaveBeenCalled();
  });

  it("a batch id read back from a damaged job file is ignored, not matched", async () => {
    await addRows([ev("stamped-plain", "Info", failedStamp)]);
    const { d, demoteForensicForCase } = deps([]);
    const opts = { batchId: 42 as unknown as string };
    expect(await settleInterruptedHuntRows(d, "c1", "H.1", opts)).toBe(0);
    expect(demoteForensicForCase).not.toHaveBeenCalled();
  });
});

// Codex review: a failure in the settle's post-demote reads (the diffs) was taken for unfinished
// grading — rows re-selected by batch id, re-stamped with a new time, tagged and demoted a second time.
describe("a collect settle that fails AFTER its demote is not re-graded (review)", () => {
  it("in-process and on restart: one tagger pass, one demote, the import time unchanged", async () => {
    const before = await stateStore.load("c1");
    await addRows([ev("marker-1", "Info", { description: "marker" }), ev("plain-1", "Info")]);
    const huntStore = new VeloHuntStore(cases);
    const job = { ...JOB, collectPhase: "importing" as const, importingBatchId: "B-1" };
    await huntStore.upsert("c1", job);
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    const realDemote = createImportDemote({
      options: d.options,
      runStateExclusive: runExclusive,
    });
    let demoted = false;
    // Forwards the rows the tagger finished on (#2891): the demote holds every other marked row.
    const demote = vi.fn(async (caseId: string, opts?: DemoteOptions) => {
      const out = await realDemote.demoteForensicForCase(caseId, opts);
      demoted = true;
      return out;
    });
    const realOutline = stateStore.forensicOutline.bind(stateStore);
    vi.spyOn(stateStore, "forensicOutline").mockImplementation(async (...args) => {
      if (demoted) throw new Error("outline read failed");
      return realOutline(...args);
    });
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      const options = { ...(d.options as AppOptions), veloHuntStore: huntStore };
      const settled = await settleHuntCollect(
        {
          options,
          autoTagImported: d.autoTagImported,
          demoteForensicForCase: demote,
          runStateExclusive: runExclusive,
          pushImportCheckpoint: vi.fn(),
        },
        {
          ...{ caseId: "c1", huntId: "H.1", stateBefore: before, importedAny: true, lastFile: MINE },
          ...{ bundleName: "B", artifactCount: 1, superTimelineAddedCount: 0 },
          ...{ capDropped: createHuntEvictions(), importBatchId: "B-1" },
        },
      );
      expect(settled.error).toMatch(/outline read failed/);
      expect(settled.seamFailed).toBeUndefined(); // grading finished: not a seam failure
      const hd = { ...d, demoteForensicForCase: demote };
      await recoverFailedHuntSettle(hd, "c1", job, settled);
      // The job no longer names the batch, so a restart does not re-select its graded rows.
      const stored = await huntStore.get("c1", "H.1");
      expect(stored?.importingBatchId).toBeUndefined();
      const restart = { uploadFiles: stored?.importingUploads, batchId: stored?.importingBatchId };
      expect(await settleInterruptedHuntRows(hd, "c1", "H.1", restart)).toBe(0);

      expect(offered).toHaveLength(1); // one tagger pass: the settle's
      expect(demote).toHaveBeenCalledTimes(1); // one case-wide demote: the settle's
      const first = offered[0].find((e) => e.id === "marker-1");
      const after = new Map((await forensic()).map((e) => [e.id, e]));
      expect(after.get("marker-1")?.severity).toBe("High");
      expect(after.get("marker-1")?.importedAt).toBe(first?.importedAt);
      expect(after.get("marker-1")?.importBatchId).toBe("B-1");
      expect(after.has("plain-1")).toBe(false);
    } finally {
      warn.mockRestore();
      vi.restoreAllMocks();
    }
  });
});

const JOB: VeloHuntJob = {
  bundleId: "b",
  bundleName: "B",
  artifacts: ["Windows.System.Pslist"],
  huntId: "H.1",
  launchedAt: "2026-11-08T00:00:00.000Z",
  waitMinutes: 10,
  collectAt: "2026-11-08T00:10:00.000Z",
  status: "collecting",
};

function timers(
  huntStore: VeloHuntStore,
  settle: (c: string, h: string, files?: readonly string[], batchId?: string) => Promise<unknown>,
  importLock?: ImportLock,
) {
  const options = {
    veloHuntStore: huntStore,
    serverClients: veloServerClients({ huntStatus: async () => ({ state: "RUNNING" }) }),
  } as unknown as AppOptions;
  return createVeloHuntStatusTimers({
    store: cases,
    options,
    startVeloHuntCollect: () => undefined,
    isCollecting: (_c, h) => h === "H.live",
    settleInterrupted: settle,
    importLock,
  });
}

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

// Codex review of #2851: an import that reached the case before the settle demoted the stranded rows
// untagged. Start-up now holds imports — every case while it enumerates, an affected case until its
// settle has run — and always lets go.
describe("start-up holds imports until the case's recovery has run (#2851 review)", () => {
  it("holds an import into the affected case until its settle ends; another case only while enumerating", async () => {
    await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, collectPhase: "importing" });
    const importLock = new ImportLock();
    let endSettle!: () => void;
    const order: string[] = [];
    const t = timers(
      huntStore,
      () => new Promise<void>((r) => (endSettle = () => (order.push("settle"), r()))),
      importLock,
    );
    const resuming = t.resumeVeloHuntStatusPolls({ startup: true });
    // Asked for while the sweep is still enumerating (synchronously after start-up began).
    const c1 = importLock.runExclusive("c1", async () => void order.push("c1 import"));
    const c2 = importLock.runExclusive("c2", async () => void order.push("c2 import"));
    await c2; // c2 has no interrupted hunt: it waits only for the enumeration
    await flush();
    expect(order).toEqual(["c2 import"]);
    endSettle();
    await c1;
    expect(order).toEqual(["c2 import", "settle", "c1 import"]);
    await resuming;
    t.stopVeloHuntStatusPollsForCase("c1");
  });

  it("lets go when the settle throws", async () => {
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, collectPhase: "importing" });
    const importLock = new ImportLock();
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      const t = timers(
        huntStore,
        async () => {
          throw new Error("out of memory");
        },
        importLock,
      );
      const resuming = t.resumeVeloHuntStatusPolls({ startup: true });
      await expect(importLock.runExclusive("c1", async () => "imported")).resolves.toBe("imported");
      await resuming;
      t.stopVeloHuntStatusPollsForCase("c1");
    } finally {
      warn.mockRestore();
    }
  });

  it("a case with nothing interrupted is not held once the sweep has run", async () => {
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, huntId: "H.run", status: "running" });
    const importLock = new ImportLock();
    const t = timers(huntStore, () => new Promise(() => {}), importLock);
    await t.resumeVeloHuntStatusPolls({ startup: true });
    void importLock.runExclusive("c1", () => new Promise(() => {}));
    expect(importLock.isBusy("c1")).toBe(true); // queued at once: no hold
    t.stopVeloHuntStatusPollsForCase("c1");
  });

  it("a hold past its timeout lets go with a WARN; a settled one clears its timer", async () => {
    const importLock = new ImportLock();
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      holdImportsDuring(importLock, "c1", new Promise(() => {}), 30); // a settle that hangs
      await expect(importLock.runExclusive("c1", async () => "imported")).resolves.toBe("imported");
      expect(warn.mock.calls.some(([m]) => /no longer wait/.test(String(m)) && /c1/.test(String(m)))).toBe(
        true,
      );
      warn.mockClear();
      holdImportsDuring(importLock, "c1", Promise.resolve(), 30);
      await importLock.runExclusive("c1", async () => undefined);
      await new Promise((r) => setTimeout(r, 60));
      expect(warn).not.toHaveBeenCalled();
      holdImportsDuring(undefined, "c1", new Promise(() => {})); // no lock wired: nothing to hold
    } finally {
      warn.mockRestore();
    }
  });
});

describe("start-up recovery runs the settle for an interrupted import only (#2851)", () => {
  it("settles a collect stored as importing — after marking it — and no other", async () => {
    const huntStore = new VeloHuntStore(cases);
    for (const [huntId, collectPhase] of [
      ["H.importing", "importing"],
      ["H.fetching", "fetching"],
      ["H.queued", "queued"],
      ["H.live", "importing"],
    ] as const)
      await huntStore.upsert("c1", { ...JOB, huntId, collectPhase });
    await huntStore.upsert("c1", { ...JOB, huntId: "H.nophase" });
    const seen: { huntId: string; status?: string }[] = [];
    const t = timers(huntStore, async (c, h) => {
      seen.push({ huntId: h, status: (await huntStore.get(c, h))?.status });
    });
    await t.resumeVeloHuntStatusPolls({ startup: true });
    expect(seen).toEqual([{ huntId: "H.importing", status: "error" }]); // marked first
    expect((await huntStore.get("c1", "H.importing"))?.error).toBe(INTERRUPTED_IMPORT_MESSAGE);
    t.stopVeloHuntStatusPollsForCase("c1");
  });

  it("hands the settle the uploaded reports' stored names the job recorded (#2852)", async () => {
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, collectPhase: "importing", importingUploads: [UPLOAD] });
    const seen: (readonly string[] | undefined)[] = [];
    const t = timers(huntStore, async (_c, _h, files) => void seen.push(files));
    await t.resumeVeloHuntStatusPolls({ startup: true });
    expect(seen).toEqual([[UPLOAD]]);
    t.stopVeloHuntStatusPollsForCase("c1");
  });

  it("hands the settle the batch id the collect recorded, so stamped-but-untagged rows are found (#2888)", async () => {
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, collectPhase: "importing", importingBatchId: "B-1" });
    const seen: (string | undefined)[] = [];
    const t = timers(huntStore, async (_c, _h, _files, batchId) => void seen.push(batchId));
    await t.resumeVeloHuntStatusPolls({ startup: true });
    expect(seen).toEqual(["B-1"]);
    t.stopVeloHuntStatusPollsForCase("c1");
  });

  it("a restart after a post-stamp failure re-grades the stamped rows through the real settle (#2888)", async () => {
    const stamp = { importBatchId: "B-1", importedAt: "2026-05-02T12:00:00Z" };
    await addRows([
      ev("stamped-marker", "Info", { description: "marker", ...stamp }),
      ev("p", "Info", stamp),
    ]);
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, collectPhase: "importing", importingBatchId: "B-1" });
    const offered: ForensicEvent[][] = [];
    const { d } = deps(offered);
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      const t = timers(huntStore, (c, h, files, batchId) =>
        settleInterruptedHuntRows(d, c, h, { uploadFiles: files, batchId }),
      );
      await t.resumeVeloHuntStatusPolls({ startup: true });
      expect(
        offered
          .flat()
          .map((e) => e.id)
          .sort(),
      ).toEqual(["p", "stamped-marker"]);
      const after = new Map((await forensic()).map((e) => [e.id, e]));
      expect(after.get("stamped-marker")?.severity).toBe("High");
      expect(after.has("p")).toBe(false);
      t.stopVeloHuntStatusPollsForCase("c1");
    } finally {
      warn.mockRestore();
    }
  });

  it("a settle that fails is logged with the case and hunt id; start-up and the mark stand", async () => {
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, collectPhase: "importing" });
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    try {
      const t = timers(huntStore, async () => {
        throw new Error("out of memory");
      });
      await expect(t.resumeVeloHuntStatusPolls({ startup: true })).resolves.toBeUndefined();
      const lines = warn.mock.calls.map(([m]) => String(m));
      expect(lines.some((l) => l.includes("c1") && l.includes("H.1") && l.includes("out of memory"))).toBe(
        true,
      );
      expect(await huntStore.get("c1", "H.1")).toMatchObject({
        status: "error",
        error: INTERRUPTED_IMPORT_MESSAGE,
      });
      t.stopVeloHuntStatusPollsForCase("c1");
    } finally {
      warn.mockRestore();
    }
  });

  it("does not wait for the settle before re-arming status polls", async () => {
    const huntStore = new VeloHuntStore(cases);
    await huntStore.upsert("c1", { ...JOB, collectPhase: "importing" });
    await huntStore.upsert("c1", { ...JOB, huntId: "H.run", status: "running" });
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const info = vi.spyOn(getServerLogger(), "info").mockImplementation(() => {});
    try {
      const t = timers(huntStore, () => held);
      const resuming = t.resumeVeloHuntStatusPolls({ startup: true });
      await vi.waitFor(() =>
        expect(info.mock.calls.some(([m]) => String(m).includes("resumed status polling for 1 hunt"))).toBe(
          true,
        ),
      );
      release();
      await resuming;
      t.stopVeloHuntStatusPollsForCase("c1");
    } finally {
      info.mockRestore();
    }
  });
});
