// #2890: a streamed import (and the disk, macOS-twin and drop-folder member paths that share its
// settle tail) whose settle fails, or whose pre-import snapshot is missing, used to swallow it: its
// rows stayed unsettled and the next import's case-wide demote moved them out UNTAGGED. Now the tail
// logs a WARN and settles this import's rows by stored name, before the section is let go.
// Real stores (state, super-timeline, forensic gate, demote).
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import { buildManualEvent } from "../../src/analysis/manualEntry.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { settleStreamedImport, type StreamedSettleDeps } from "../../src/composition/importIngestSettle.js";
import { recoverImportRows, type RowRecoveryDeps } from "../../src/routes/importRowRecovery.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const MINE = "0007_security.evtx.jsonl";
const OTHER = "0006_earlier.csv";

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
    sources: ["Sysmon"],
    ...extra,
  };
}

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let metaStore: ImportMetaStore;
let options: AppOptions;
let lock: StateLock;
let warn: ReturnType<typeof vi.spyOn>;

const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-streamed-settle-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  metaStore = new ImportMetaStore(cases);
  lock = new StateLock();
  options = {
    stateStore,
    superTimelineStore: superStore,
    importMetaStore: metaStore,
    forensicGateControlStore: new ForensicGateControlStore(cases),
  };
  warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

/** The tagger stand-in raises "marker" rows to High, as a one-rule ruleset would. */
function settleDeps(offered: ForensicEvent[][] = []) {
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  const demoteForensic = vi.fn(demote.demoteForensic);
  const d: StreamedSettleDeps = {
    options,
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
    demote: { ...demote, demoteForensic },
  };
  return { d, demoteForensic };
}

async function addRows(rows: ForensicEvent[]): Promise<void> {
  await runExclusive("c1", async () => {
    const state = await stateStore.load("c1");
    await stateStore.save({ ...state, forensicTimeline: [...state.forensicTimeline, ...rows] });
  });
}

const forensic = async () => new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));

async function superIds(): Promise<string[]> {
  const ids: string[] = [];
  for await (const b of superStore.eventBatches("c1")) for (const e of b) ids.push(e.id);
  return ids.sort();
}

const warned = (re: RegExp): boolean => warn.mock.calls.some(([m]: unknown[]) => re.test(String(m)));

/** The import: snapshot, then merge rows (the importer), then the shared settle tail. */
async function streamedImport(d: StreamedSettleDeps, rows: ForensicEvent[], snapshot = true) {
  const baseline = snapshot ? await captureImportBaseline(stateStore, "c1") : null;
  await addRows(rows);
  try {
    return await settleStreamedImport(d, { caseId: "c1", kind: "evtx", storedName: MINE, baseline });
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

/** Fail the first page read of rows that already carry a stamp: the settle's dual-write, AFTER the stamp. */
function failAfterStamp(): void {
  const real = stateStore.forensicRowsById.bind(stateStore);
  let failed = false;
  vi.spyOn(stateStore, "forensicRowsById").mockImplementation(async (caseId, ids) => {
    const rows = await real(caseId, ids);
    if (!failed && rows.length && rows.every((r) => r.event.importBatchId)) {
      failed = true;
      throw new Error("out of memory");
    }
    return rows;
  });
}

describe("settleStreamedImport recovers a failed or skipped settle (#2890)", () => {
  it("a settle that fails after stamping: the rows are still dual-written, tagged and demoted", async () => {
    failAfterStamp();
    const offered: ForensicEvent[][] = [];
    const { d } = settleDeps(offered);
    await expect(
      streamedImport(d, [ev("marker-1", "Info", { description: "ntds marker" }), ev("plain-1", "Info")]),
    ).resolves.toEqual({ addedEvents: 0, addedIocs: 0 });

    const after = await forensic();
    expect(after.get("marker-1")?.severity).toBe("High"); // tagged before the demote
    expect(after.has("plain-1")).toBe(false); // demoted — into the super-timeline, not lost
    expect(await superIds()).toEqual(["marker-1", "plain-1"]);
    // Re-stamped with the settle's OWN preset id: one batch across the failed settle and the recovery.
    const ids = new Set(offered.flat().map((e) => e.importBatchId));
    expect(ids.size).toBe(1);
    expect(after.get("marker-1")?.importBatchId).toEqual([...ids][0]);
    expect(warned(/settle failed: out of memory/)).toBe(true);
    expect(warned(/settled 2 row\(s\) of 0007_security\.evtx\.jsonl whose settle failed/)).toBe(true);
  });

  it("a settle that fails MID-stamp: stamped and unstamped rows alike are settled, under one batch", async () => {
    const real = stateStore.updateForensicRows.bind(stateStore);
    let failed = false;
    vi.spyOn(stateStore, "updateForensicRows").mockImplementation(async (caseId, rows) => {
      if (!failed && rows.length > 1 && rows.every((r) => r.event.importBatchId)) {
        failed = true;
        await real(caseId, rows.slice(0, 1)); // the first row's stamp lands, then the write fails
        throw new Error("out of memory");
      }
      return real(caseId, rows);
    });
    const offered: ForensicEvent[][] = [];
    const { d } = settleDeps(offered);
    await streamedImport(d, [ev("marker-1", "Info", { description: "marker" }), ev("plain-1", "Info")]);
    expect(failed).toBe(true);
    const after = await forensic();
    expect(after.get("marker-1")?.severity).toBe("High");
    expect(after.has("plain-1")).toBe(false);
    expect(await superIds()).toEqual(["marker-1", "plain-1"]);
    const tagged = offered.flat();
    expect(tagged.map((e) => e.id).sort()).toEqual(["marker-1", "plain-1"]);
    expect(new Set(tagged.map((e) => e.importBatchId)).size).toBe(1);
  });

  it("a missing pre-import snapshot: the rows are still graded, and the gap is logged", async () => {
    const { d } = settleDeps();
    await streamedImport(
      d,
      [ev("marker-1", "Info", { description: "marker" }), ev("plain-1", "Info")],
      false,
    );
    const after = await forensic();
    expect(after.get("marker-1")?.severity).toBe("High");
    expect(after.get("marker-1")?.importBatchId).toEqual(expect.any(String));
    expect(after.has("plain-1")).toBe(false);
    expect(await superIds()).toEqual(["marker-1", "plain-1"]);
    expect(warned(/no pre-import snapshot/)).toBe(true);
  });

  it("a failed import record after a complete settle re-stamps nothing and demotes once", async () => {
    vi.spyOn(metaStore, "record").mockRejectedValue(new Error("disk full"));
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensic } = settleDeps(offered);
    await streamedImport(d, [ev("graded-1", "High"), ev("plain-1", "Info")]);
    expect(demoteForensic).toHaveBeenCalledTimes(1);
    expect(offered).toHaveLength(1); // one tagger pass: the settle's
    const stamp = offered[0][0].importBatchId;
    expect((await forensic()).get("graded-1")?.importBatchId).toBe(stamp);
    expect(warned(/settled \d+ row\(s\)/)).toBe(false);
  });

  it("a failure AFTER demote (the post-demote outline read) re-grades nothing (review)", async () => {
    const offered: ForensicEvent[][] = [];
    const { d, demoteForensic } = settleDeps(offered);
    const realDemote = createImportDemote({ options, runStateExclusive: runExclusive }).demoteForensic;
    let demoted = false;
    demoteForensic.mockImplementation(async (caseId: string) => {
      const out = await realDemote(caseId);
      demoted = true;
      return out;
    });
    const realOutline = stateStore.forensicOutline.bind(stateStore);
    vi.spyOn(stateStore, "forensicOutline").mockImplementation(async (...args) => {
      if (demoted) throw new Error("outline read failed");
      return realOutline(...args);
    });
    await expect(
      streamedImport(d, [ev("marker-1", "Info", { description: "marker" }), ev("plain-1", "Info")]),
    ).resolves.toEqual({ addedEvents: 0, addedIocs: 0 });

    expect(demoteForensic).toHaveBeenCalledTimes(1); // one case-wide demote: the settle's
    expect(offered).toHaveLength(1); // one tagger pass: the settle's
    const first = offered[0].find((e) => e.id === "marker-1");
    const after = (await forensic()).get("marker-1");
    expect(after?.severity).toBe("High");
    expect(after?.importedAt).toBe(first?.importedAt); // provenance unchanged
    expect(after?.importBatchId).toBe(first?.importBatchId);
    expect(warned(/after grading completed: outline read failed/)).toBe(true);
    expect(warned(/settled \d+ row\(s\)/)).toBe(false);
  });

  it("a recovery after a post-stamp failure keeps the failed settle's import time", async () => {
    const stamped: ForensicEvent[] = [];
    const real = stateStore.forensicRowsById.bind(stateStore);
    let failed = false;
    vi.spyOn(stateStore, "forensicRowsById").mockImplementation(async (caseId, ids) => {
      const rows = await real(caseId, ids);
      if (!failed && rows.length && rows.every((r) => r.event.importBatchId)) {
        failed = true;
        stamped.push(...rows.map((r) => r.event));
        await new Promise((r) => setTimeout(r, 5)); // a re-stamp would carry a later instant
        throw new Error("out of memory");
      }
      return rows;
    });
    const { d } = settleDeps();
    await streamedImport(d, [ev("marker-1", "Info", { description: "marker" })]);
    const first = stamped.find((e) => e.id === "marker-1");
    expect(first?.importedAt).toEqual(expect.any(String));
    expect((await forensic()).get("marker-1")?.importedAt).toBe(first?.importedAt);
  });

  it("never throws when the recovery fails too, and says so", async () => {
    const { d } = settleDeps();
    vi.spyOn(stateStore, "loadOverviewWithoutIocs").mockRejectedValue(new Error("out of memory"));
    await expect(streamedImport(d, [ev("plain-1", "Info")])).resolves.toEqual({
      addedEvents: 0,
      addedIocs: 0,
    });
    expect(warned(/did not work either: out of memory/)).toBe(true);
  });
});

describe("settleStreamedImport carries the settled counts for the import message (#2982)", () => {
  it("counts the rows the settle kept, graded after the tagger, post-demote", async () => {
    const { d } = settleDeps();
    const r = await streamedImport(d, [
      ev("graded-1", "High"),
      ev("marker-1", "Info", { description: "marker" }),
      ev("plain-1", "Info"),
    ]);
    expect(r.counts).toMatchObject({ added: 2, highCritical: 2 });
  });

  it("a settle it had to recover returns no counts — unknown, never zero", async () => {
    const { d } = settleDeps();
    const r = await streamedImport(d, [ev("plain-1", "Info")], false);
    expect(r.counts).toBeUndefined();
  });
});

describe("recoverImportRows (#2890)", () => {
  it("selects only the named import's unsettled rows", async () => {
    const manual = buildManualEvent({
      timestamp: "2026-05-02T11:00:00Z",
      description: "note",
      severity: "Info",
    });
    await addRows([
      ev("mine-1", "High"),
      ev("other-1", "Medium", { sourceScreenshots: [OTHER] }),
      ev("stamped-1", "Medium", { importBatchId: "another-import", importedAt: "2026-05-01T00:00:00Z" }),
      ev("promoted-1", "High", { promotedAt: "2026-05-02T00:00:00Z" }),
      { ...manual, sourceScreenshots: [MINE] },
    ]);
    const { d } = settleDeps();
    const deps: RowRecoveryDeps = {
      stateStore,
      runStateExclusive: runExclusive,
      superTimelineStore: superStore,
      autoTagImported: d.autoTagImported,
      demote: d.demote.demoteForensic,
    };
    const out = await recoverImportRows(deps, { caseId: "c1", storedNames: [MINE], tag: "t", cause: "c" });
    expect(out).toEqual({ settled: 1 });
    const after = await forensic();
    expect(after.get("mine-1")?.importBatchId).toEqual(expect.any(String));
    expect(after.get("other-1")?.importBatchId).toBeUndefined();
    expect(after.get("stamped-1")?.importBatchId).toBe("another-import");
    expect(after.get("promoted-1")?.importBatchId).toBeUndefined();
    expect(after.get(manual.id)?.importBatchId).toBeUndefined();
    expect(await superIds()).toEqual(["mine-1"]);
  });

  it("nothing selected: no demote", async () => {
    await addRows([ev("other-1", "Info", { sourceScreenshots: [OTHER] })]);
    const demote = vi.fn(async () => undefined);
    const deps: RowRecoveryDeps = { stateStore, autoTagImported: async () => {}, demote };
    await expect(
      recoverImportRows(deps, { caseId: "c1", storedNames: [MINE], tag: "t", cause: "c" }),
    ).resolves.toEqual({ settled: 0 });
    expect(demote).not.toHaveBeenCalled();
  });
});
