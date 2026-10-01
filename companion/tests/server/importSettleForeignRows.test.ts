import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { settleForensicImport, type SettleDeps } from "../../src/routes/importSettle.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import { buildManualEvent } from "../../src/analysis/manualEntry.js";
import { baselineCheckpoint } from "../../src/analysis/importUndoRows.js";
import { applyUndoDelta } from "../../src/analysis/importUndoDelta.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #1904: the import section holds the IMPORT lock, not the state lock, so an analyst can add a
// manual event, or promote a super-timeline row, while an import runs. Those rows land between the
// baseline capture and the settle. They are not the import's rows: the settle must not stamp them
// with the import's importedAt / importBatchId, copy them into the super-timeline, or offer them
// to the tagger. Real stores, real interleaving: the writes happen exactly where the race puts them.

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
    sourceScreenshots: [],
    sources: ["Hayabusa"],
    ...extra,
  };
}

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let gate: ForensicGateControlStore;
let lock: StateLock;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-settle-foreign-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  gate = new ForensicGateControlStore(cases);
  lock = new StateLock();
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

function deps(tagged: string[]): SettleDeps {
  const options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: gate,
  } as unknown as AppOptions;
  return {
    stateStore,
    runStateExclusive: runExclusive,
    superTimelineStore: superStore,
    autoTagImported: async (_caseId, added) => {
      tagged.push(...added.map((e) => e.id));
    },
    demoteForensic: createImportDemote({ options, runStateExclusive: runExclusive }).demoteForensic,
  };
}

// What the manual-event route does (routes/caseLifecycle.ts POST /cases/:id/events).
async function addManual(severity: ForensicEvent["severity"], description: string): Promise<ForensicEvent> {
  const event = buildManualEvent({ timestamp: "2026-05-02T11:00:00Z", description, severity });
  await runExclusive("c1", async () => {
    const state = await stateStore.load("c1");
    await stateStore.save({ ...state, forensicTimeline: [...state.forensicTimeline, event] });
  });
  return event;
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
  return ids;
}

describe("settleForensicImport — rows another writer added while the import ran (#1904)", () => {
  it("an Undo of the import keeps a manual event the analyst added while it ran", async () => {
    await addRows([ev("old", "High")]);
    const baseline = await captureImportBaseline(stateStore, "c1");
    try {
      await addRows([ev("imp-1", "High")]);
      const manual = await addManual("Medium", "analyst note during import");
      await addRows([ev("imp-2", "High")]);
      await settleForensicImport(deps([]), "c1", baseline, "label");
      const checkpoint = await baselineCheckpoint(stateStore, baseline, "label", "at");
      const undone = applyUndoDelta(await stateStore.load("c1"), checkpoint!.delta!);
      expect(undone.forensicTimeline.map((e) => e.id)).toEqual(["old", manual.id]);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  });

  it("keeps that manual event on the whole-timeline undo too (ids not unique)", async () => {
    await addRows([ev("dup", "High"), ev("dup", "Medium")]);
    const baseline = await captureImportBaseline(stateStore, "c1");
    try {
      await addRows([ev("imp-1", "High")]);
      const manual = await addManual("Medium", "analyst note during import");
      await settleForensicImport(deps([]), "c1", baseline, "label");
      const checkpoint = await baselineCheckpoint(stateStore, baseline, "label", "at");
      const undone = applyUndoDelta(await stateStore.load("c1"), checkpoint!.delta!);
      expect(undone.forensicTimeline.map((e) => e.id)).toEqual(["dup", "dup", manual.id]);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  });

  it("stamps, dual-writes and tags only the import's own rows", async () => {
    await addRows([ev("old", "High")]);
    const baseline = await captureImportBaseline(stateStore, "c1");
    try {
      // Interleaved: the importer's merge, the analyst's manual events, a promotion, more import rows.
      await addRows([ev("imp-1", "High")]);
      const m1 = await addManual("Medium", "analyst note one");
      const m2 = await addManual("High", "analyst note two");
      await addRows([ev("promoted-1", "Low", { sources: ["MFT"], promotedAt: new Date().toISOString() })]);
      await addRows([ev("imp-2", "Info"), ev("imp-3", "High")]);

      const tagged: string[] = [];
      const settled = await settleForensicImport(deps(tagged), "c1", baseline, "label");

      const after = new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
      for (const m of [m1, m2]) {
        const row = after.get(m.id)!;
        expect(row).toBeDefined();
        expect(row.importedAt).toBeUndefined();
        expect(row.importBatchId).toBeUndefined();
        expect(row.sources).toEqual(["manual"]);
      }
      const promoted = after.get("promoted-1")!;
      expect(promoted.importedAt).toBeUndefined();
      expect(promoted.importBatchId).toBeUndefined();

      const imp1 = after.get("imp-1")!;
      expect(imp1.importBatchId).toBeTruthy();
      expect(after.get("imp-3")!.importBatchId).toBe(imp1.importBatchId);

      const sup = await superIds();
      expect(sup).toEqual(expect.arrayContaining(["imp-1", "imp-2", "imp-3"]));
      expect(sup).not.toContain(m1.id);
      expect(sup).not.toContain(m2.id);
      expect(sup).not.toContain("promoted-1");
      expect(tagged.sort()).toEqual(["imp-1", "imp-2", "imp-3"]);
      expect((await settled.addedEvents()).map((e) => e.id).sort()).toEqual(["imp-1", "imp-3"]);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  });

  it("keeps an import row that carries an older promotion stamp (correlation) as the import's own", async () => {
    await addRows([ev("old", "High")]);
    const earlier = new Date(Date.now() - 60_000).toISOString();
    const baseline = await captureImportBaseline(stateStore, "c1");
    try {
      // A new import row that correlation folded with a row promoted BEFORE this import started.
      await addRows([ev("imp-corr", "High", { promotedAt: earlier })]);
      const tagged: string[] = [];
      await settleForensicImport(deps(tagged), "c1", baseline, "label");
      const row = (await stateStore.load("c1")).forensicTimeline.find((e) => e.id === "imp-corr")!;
      expect(row.importBatchId).toBeTruthy();
      expect(await superIds()).toContain("imp-corr");
      expect(tagged).toEqual(["imp-corr"]);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  });

  it("keeps an import row whose sources name 'manual' (an AI import may emit it) as the import's own", async () => {
    const baseline = await captureImportBaseline(stateStore, "c1");
    try {
      await addRows([ev("ai-row", "High", { sources: ["manual"] })]);
      const tagged: string[] = [];
      await settleForensicImport(deps(tagged), "c1", baseline, "label");
      const row = (await stateStore.load("c1")).forensicTimeline.find((e) => e.id === "ai-row")!;
      expect(row.importBatchId).toBeTruthy();
      expect(tagged).toEqual(["ai-row"]);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  });

  // #1919: the case-wide demote at the end of every import kept a below-floor row only when it was
  // promoted, so a manual Info event the analyst wrote left the forensic timeline on the next import.
  it("the import's demote keeps a manual Info event and still demotes the imported Info rows", async () => {
    const manual = await addManual("Info", "analyst context note");
    const baseline = await captureImportBaseline(stateStore, "c1");
    try {
      await addRows([ev("imp-info", "Info"), ev("imp-high", "High")]);
      await settleForensicImport(deps([]), "c1", baseline, "label");
      const ids = (await stateStore.load("c1")).forensicTimeline.map((e) => e.id);
      expect(ids).toContain(manual.id);
      expect(ids).toContain("imp-high");
      expect(ids).not.toContain("imp-info");
      const sup = await superIds();
      expect(sup).toContain("imp-info");
      expect(sup).not.toContain(manual.id);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  });
});
