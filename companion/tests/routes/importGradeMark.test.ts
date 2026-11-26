// #2891 gaps 1 and 2: the per-row grade mark. The import stamp now writes `gradePending` on every row
// the import added, and only the tagger's finished run removes it (survivors of the demote) — so:
//   - the case-wide demote never moves a row still waiting for the tagger (a crash between the stamp
//     and the tag, or a tagger that failed internally);
//   - start-up recovery finds those rows and grades them (dual-write → tagger → demote);
//   - rows from before this change carry no mark and are grandfathered as graded.
// Real stores (state, super-timeline, forensic gate, demote).
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
import { settleForensicImport, type SettleDeps } from "../../src/routes/importSettle.js";
import { regradePendingRows } from "../../src/composition/ungradedRecovery.js";
import { forensicGradePendingRows, type TagOutcome } from "../../src/analysis/gradeMark.js";
import { recoveryDepsFromSettle } from "../../src/routes/importRowRecovery.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const MINE = "0011_upload.json";

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
const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-grade-mark-"));
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
  vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

type Tagger = (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;

/** The tagger stand-in raises "marker" rows to High, as a one-rule ruleset would. */
const raiseMarkers: Tagger = async (caseId, added) => {
  await runExclusive(caseId, async () => {
    const state = await stateStore.load(caseId);
    const raise = (e: ForensicEvent) =>
      added.some((a) => a.id === e.id) && e.description.includes("marker")
        ? { ...e, severity: "High" as const }
        : e;
    await stateStore.save({ ...state, forensicTimeline: state.forensicTimeline.map(raise) });
  });
  return { ungraded: [] };
};

function deps(tag: Tagger, offered: ForensicEvent[][] = []) {
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  const demoteForensic = vi.fn(demote.demoteForensic);
  const d: SettleDeps = {
    stateStore,
    runStateExclusive: runExclusive,
    superTimelineStore: superStore,
    autoTagImported: async (caseId, added) => {
      offered.push(added);
      return tag(caseId, added);
    },
    demoteForensic,
  };
  return { d, demoteForensic, demote };
}

async function importRows(d: SettleDeps, rows: ForensicEvent[]) {
  const baseline = await captureImportBaseline(stateStore, "c1");
  await runExclusive("c1", async () => {
    const state = await stateStore.load("c1");
    await stateStore.save({ ...state, forensicTimeline: [...state.forensicTimeline, ...rows] });
  });
  try {
    return await settleForensicImport(d, "c1", baseline, MINE);
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

const forensic = async () => new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
async function superRows(): Promise<ForensicEvent[]> {
  const rows: ForensicEvent[] = [];
  for await (const b of superStore.eventBatches("c1")) rows.push(...b);
  return rows;
}
const ROWS = () => [ev("marker-1", "Info", "ntds marker"), ev("plain-1", "Info")];
const pending = async () => (await forensicGradePendingRows(stateStore, "c1")).map((r) => r.event.id).sort();

describe("the per-row grade mark (#2891)", () => {
  it("a normal import is unchanged: one tagger pass, one demote, and no mark left anywhere", async () => {
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensic } = deps(raiseMarkers, offered);
    await importRows(d, ROWS());
    const after = await forensic();
    expect(after.get("marker-1")?.severity).toBe("High");
    expect(after.get("marker-1")?.gradePending).toBeUndefined();
    expect(after.has("plain-1")).toBe(false); // demoted into the super-timeline
    expect(offered).toHaveLength(1);
    expect(offered[0].every((e) => e.gradePending === undefined)).toBe(true); // tagger input unchanged
    expect(demoteForensic).toHaveBeenCalledTimes(1);
    expect(await pending()).toEqual([]);
    expect((await superRows()).every((e) => e.gradePending === undefined)).toBe(true);
  });

  it("a crash between the stamp and the tag: the next demote keeps the rows, start-up recovery grades them", async () => {
    const { d, demote } = deps(async () => {
      throw new Error("killed"); // the process died here
    });
    await expect(importRows(d, ROWS())).rejects.toThrow("killed");
    expect(await pending()).toEqual(["marker-1", "plain-1"]);

    // Another import's case-wide demote, before any restart: nothing waiting for the tagger moves.
    expect(await demote.demoteForensic("c1")).toEqual([]);
    expect([...(await forensic()).keys()].sort()).toEqual(["marker-1", "plain-1"]);

    // Start-up: the rows are graded — tagged, then demoted — and the marks are gone.
    const offered: ForensicEvent[][] = [];
    const startup = deps(raiseMarkers, offered);
    const done = await regradePendingRows(recoveryDepsFromSettle(startup.d), "c1");
    expect(done).toMatchObject({ regraded: 2, held: 0 });
    const after = await forensic();
    expect(after.get("marker-1")?.severity).toBe("High");
    expect(after.has("plain-1")).toBe(false);
    expect(await pending()).toEqual([]);
    expect(
      offered
        .flat()
        .map((e) => e.id)
        .sort(),
    ).toEqual(["marker-1", "plain-1"]);
    expect((await superRows()).map((e) => e.id).sort()).toEqual(["marker-1", "plain-1"]);
    expect((await superRows()).every((e) => e.gradePending === undefined)).toBe(true);
  });

  it("a tagger that fails internally: its rows stay marked and in the record, and are graded later", async () => {
    const { d, demote } = deps(async (_c, added) => ({ ungraded: added.map((e) => e.id) }));
    await importRows(d, ROWS());
    expect(await pending()).toEqual(["marker-1", "plain-1"]);
    expect((await forensic()).get("plain-1")?.severity).toBe("Info"); // held, not demoted untagged
    expect(await demote.demoteForensic("c1")).toEqual([]); // a later case-wide demote holds them too

    const startup = deps(raiseMarkers);
    await regradePendingRows(recoveryDepsFromSettle(startup.d), "c1");
    expect((await forensic()).get("marker-1")?.severity).toBe("High");
    expect((await forensic()).has("plain-1")).toBe(false);
    expect(await pending()).toEqual([]);
  });

  it("a tagger that fails on one row only holds that row; the rest of the import settles normally", async () => {
    const { d } = deps(async (caseId, added) => {
      await raiseMarkers(caseId, added);
      return { ungraded: ["plain-1"] };
    });
    await importRows(d, [...ROWS(), ev("plain-2", "Info")]);
    const after = await forensic();
    expect(after.get("marker-1")?.gradePending).toBeUndefined();
    expect(after.has("plain-2")).toBe(false);
    expect(await pending()).toEqual(["plain-1"]);
  });

  it("rows from before this change carry no mark: start-up recovery does nothing, the demote is as before", async () => {
    await runExclusive("c1", async () => {
      const state = await stateStore.load("c1");
      const old = (e: ForensicEvent) => ({
        ...e,
        importedAt: "2026-01-01T00:00:00Z",
        importBatchId: "b-old",
      });
      await stateStore.save({ ...state, forensicTimeline: ROWS().map(old) });
    });
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensic, demote } = deps(raiseMarkers, offered);
    expect(await regradePendingRows(recoveryDepsFromSettle(d), "c1")).toMatchObject({ regraded: 0 });
    expect(offered).toHaveLength(0);
    expect(demoteForensic).not.toHaveBeenCalled();
    expect((await demote.demoteForensic("c1")).map((e) => e.id).sort()).toEqual(["marker-1", "plain-1"]);
  });

  it("promoted and manual rows are never re-tagged or demoted; a mark on them is only cleared", async () => {
    await runExclusive("c1", async () => {
      const state = await stateStore.load("c1");
      const promoted = { ...ev("promo-1", "Info", "ntds marker"), promotedAt: "2026-05-03T00:00:00Z" };
      const manual = { ...ev("manual-1", "Info", "typed marker"), sources: ["manual"] };
      const marked = [promoted, manual].map((e) => ({
        ...e,
        importBatchId: "b1",
        gradePending: true as const,
      }));
      await stateStore.save({ ...state, forensicTimeline: marked });
    });
    const offered: ForensicEvent[][] = [];
    const { d } = deps(raiseMarkers, offered);
    await regradePendingRows(recoveryDepsFromSettle(d), "c1");
    const after = await forensic();
    expect(after.get("promo-1")?.severity).toBe("Info"); // kept, at its stored severity
    expect(after.get("manual-1")?.severity).toBe("Info");
    expect(offered.flat()).toHaveLength(0);
    expect(await pending()).toEqual([]);
  });

  it("start-up recovery also stamps and grades the rows of that file the paged stamp never reached", async () => {
    await runExclusive("c1", async () => {
      const state = await stateStore.load("c1");
      const stamped = {
        ...ev("marker-1", "Info", "ntds marker"),
        importBatchId: "b1",
        importedAt: "2026-05-02T11:00:00Z",
      };
      await stateStore.save({
        ...state,
        forensicTimeline: [{ ...stamped, gradePending: true as const }, ev("late-1", "Info", "late marker")],
      });
    });
    const { d } = deps(raiseMarkers);
    await regradePendingRows(recoveryDepsFromSettle(d), "c1");
    const after = await forensic();
    expect(after.get("late-1")).toMatchObject({ severity: "High", importBatchId: "b1" });
    expect(after.get("late-1")?.importedAt).toBe("2026-05-02T11:00:00Z");
    expect(await pending()).toEqual([]);
  });

  it("the mark survives a whole-case save round trip", async () => {
    const state = await stateStore.load("c1");
    await stateStore.save({ ...state, forensicTimeline: [{ ...ev("x", "Info"), gradePending: true }] });
    await stateStore.save(await stateStore.load("c1"));
    expect((await forensic()).get("x")?.gradePending).toBe(true);
  });
});
