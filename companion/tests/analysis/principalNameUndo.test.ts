// #2490: Undo of the import that taught the case a principal name restores the ledger without it, and
// every forensic row loses the suffix — the rows the delta restores and a row another writer added
// after the import alike. Redo puts the name back.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import {
  ImportUndoStore,
  applyRedo,
  applyUndo,
  deltaCheckpoint,
  emptyUndoStack,
  pushCheckpoint,
  runUndoStep,
} from "../../src/analysis/importUndo.js";

const SP = "3f2a1b4c-1111-2222-3333-444455556666";
const RAW = `Azure Microsoft.Authorization/roleAssignments/write by ${SP}: Owner → x`;
const NAMED = `Azure Microsoft.Authorization/roleAssignments/write by ${SP} (backup-automation): Owner → x`;

const row = (id: string, named: boolean): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00.000Z",
  description: named ? NAMED : RAW,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["Azure Activity"],
  ...(named ? { callerName: "backup-automation" } : {}),
});

describe("caller names follow Undo and Redo (#2490)", () => {
  const S0: InvestigationState = { ...emptyState("c1"), forensicTimeline: [row("az1", false)] };
  const S1: InvestigationState = {
    ...S0,
    principalNames: [{ id: SP, names: ["backup-automation"] }],
    forensicTimeline: [row("az1", true)],
  };
  let undoStore: ImportUndoStore;
  let state: InvestigationState;
  const deps = () => ({
    undoStore,
    stateStore: {
      load: async () => state,
      save: async (s: InvestigationState) => {
        state = s;
      },
    },
    importLock: { runExclusive: <T>(_c: string, fn: () => Promise<T>) => fn() },
    runStateExclusive: <T>(_c: string, fn: () => Promise<T>) => fn(),
  });
  const text = (id: string) => state.forensicTimeline.find((e) => e.id === id)?.description;

  beforeEach(async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-undo-names-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    undoStore = new ImportUndoStore(cases);
    // A row another writer added after the import, already named.
    state = { ...S1, forensicTimeline: [...S1.forensicTimeline, row("later", true)] };
    await undoStore.save(
      "c1",
      pushCheckpoint(emptyUndoStack(), deltaCheckpoint("m365 (signins.json)", "t", S0, S1)),
    );
  });

  it("undo forgets the name and takes it off every row; redo brings it back", async () => {
    await runUndoStep(deps(), "c1", applyUndo);
    expect(state.principalNames ?? []).toEqual([]);
    expect(text("az1")).toBe(RAW);
    expect(text("later")).toBe(RAW);
    expect(state.forensicTimeline.every((e) => e.callerName === undefined)).toBe(true);

    await runUndoStep(deps(), "c1", applyRedo);
    expect(state.principalNames).toEqual([{ id: SP, names: ["backup-automation"] }]);
    expect(text("az1")).toBe(NAMED);
    expect(text("later")).toBe(NAMED);
  });
});
