import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import {
  ImportUndoStore,
  emptyUndoStack,
  pushCheckpoint,
  applyUndo,
  applyRedo,
  summarizeUndoStack,
  normalizeStack,
  type ImportUndoStack,
} from "../../src/analysis/importUndo.js";

// Build a full investigation state with `n` events, `m` IOCs, `k` findings — tagged so we can
// assert which snapshot was restored.
function mkState(tag: string, n: number, m: number, k = 0): InvestigationState {
  return {
    ...emptyState("c1"),
    forensicTimeline: Array.from({ length: n }, (_, i) => ({
      id: `${tag}-e${i}`, timestamp: "2026-01-01T00:00:00Z", description: `${tag} event ${i}`,
      severity: "Info" as const, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    })),
    iocs: Array.from({ length: m }, (_, i) => ({
      id: `${tag}-i${i}`, type: "ip" as const, value: `10.0.${tag.length}.${i}`, firstSeen: "2026-01-01T00:00:00Z",
    })),
    findings: Array.from({ length: k }, (_, i) => ({
      id: `${tag}-f${i}`, severity: "High" as const, title: `${tag} finding ${i}`, description: "d",
      relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "2026-01-01T00:00:00Z",
      lastUpdated: "2026-01-01T00:00:00Z", status: "open" as const,
    })),
  };
}

const cp = (tag: string, n: number, m: number, k: number, label: string, at = "2026-06-13T00:00:00Z") => ({
  label, at, state: mkState(tag, n, m, k),
});

describe("importUndo pure operations", () => {
  it("pushCheckpoint appends to undo, clears redo, and caps depth (oldest dropped)", () => {
    let stack: ImportUndoStack = { undo: [], redo: [cp("r", 1, 0, 0, "stale-redo")] };
    stack = pushCheckpoint(stack, cp("a", 1, 1, 1, "a"), 3);
    expect(stack.redo).toEqual([]); // a new import invalidates redo history
    stack = pushCheckpoint(stack, cp("b", 2, 2, 1, "b"), 3);
    stack = pushCheckpoint(stack, cp("c", 3, 3, 1, "c"), 3);
    stack = pushCheckpoint(stack, cp("d", 4, 4, 1, "d"), 3); // exceeds depth 3 -> "a" drops
    expect(stack.undo.map((c) => c.label)).toEqual(["b", "c", "d"]);
  });

  it("applyUndo / applyRedo return null when there is nothing to do", () => {
    expect(applyUndo(emptyUndoStack(), mkState("cur", 5, 5, 2))).toBeNull();
    expect(applyRedo(emptyUndoStack(), mkState("cur", 5, 5, 2))).toBeNull();
  });

  it("undo restores the full pre-import state (incl. findings) and pushes the current state to redo", () => {
    // undo top is the snapshot before "thor" ran (2 events, 1 IOC, 1 finding). Current is post-import.
    const stack: ImportUndoStack = { undo: [cp("before-thor", 2, 1, 1, "thor (0003_thor.json)")], redo: [] };
    const current = mkState("post", 9, 4, 5);
    const r = applyUndo(stack, current, "2026-06-13T10:00:00Z")!;
    expect(r.restore.forensicTimeline).toHaveLength(2);
    expect(r.restore.iocs).toHaveLength(1);
    expect(r.restore.findings).toHaveLength(1);     // findings come back too
    expect(r.stack.undo).toHaveLength(0);
    expect(r.stack.redo).toHaveLength(1);
    expect(r.stack.redo[0].state.findings).toHaveLength(5); // current state preserved for redo
    expect(r.stack.redo[0].label).toBe("thor (0003_thor.json)"); // redo re-applies the same import
    expect(r.stack.redo[0].at).toBe("2026-06-13T10:00:00Z");
  });

  it("round-trips a full S0 -> S1 -> S2 import/undo/redo sequence", () => {
    let stack: ImportUndoStack = emptyUndoStack();
    stack = pushCheckpoint(stack, cp("S0", 1, 0, 0, "import A"));
    stack = pushCheckpoint(stack, cp("S1", 3, 1, 1, "import B"));
    const S2 = mkState("S2", 7, 2, 4);

    const u1 = applyUndo(stack, S2)!;
    expect(u1.restore.forensicTimeline).toHaveLength(3); // S1
    stack = u1.stack;

    const u2 = applyUndo(stack, u1.restore)!;
    expect(u2.restore.forensicTimeline).toHaveLength(1); // S0
    expect(u2.stack.undo).toHaveLength(0);
    expect(u2.stack.redo.map((c) => c.label)).toEqual(["import B", "import A"]);
    stack = u2.stack;

    const r1 = applyRedo(stack, u2.restore)!;
    expect(r1.restore.forensicTimeline).toHaveLength(3); // S1
    stack = r1.stack;

    const r2 = applyRedo(stack, r1.restore)!;
    expect(r2.restore.forensicTimeline).toHaveLength(7); // S2
    expect(r2.restore.findings).toHaveLength(4);
    expect(r2.stack.redo).toHaveLength(0);
    expect(r2.stack.undo.map((c) => c.label)).toEqual(["import A", "import B"]);
  });

  it("summarizeUndoStack reports availability, counts (events/IOCs/findings), and the next undo/redo", () => {
    const empty = summarizeUndoStack(emptyUndoStack(), 5);
    expect(empty.canUndo).toBe(false);
    expect(empty.canRedo).toBe(false);
    expect(empty.maxDepth).toBe(5);
    expect(empty.nextUndo).toBeNull();

    const stack: ImportUndoStack = { undo: [cp("a", 2, 1, 0, "a"), cp("b", 4, 3, 2, "thor")], redo: [cp("c", 9, 5, 6, "siem")] };
    const s = summarizeUndoStack(stack, 5);
    expect(s.canUndo).toBe(true);
    expect(s.canRedo).toBe(true);
    expect(s.nextUndo).toEqual({ label: "thor", at: "2026-06-13T00:00:00Z", events: 4, iocs: 3, findings: 2 });
    expect(s.nextRedo).toEqual({ label: "siem", at: "2026-06-13T00:00:00Z", events: 9, iocs: 5, findings: 6 });
    expect(s.undo).toHaveLength(2);
  });

  it("normalizeStack coerces garbage / partial input and drops checkpoints with no state", () => {
    expect(normalizeStack(null)).toEqual(emptyUndoStack());
    expect(normalizeStack("nope")).toEqual(emptyUndoStack());
    expect(normalizeStack({ undo: "x" })).toEqual(emptyUndoStack());
    const out = normalizeStack({
      undo: [
        { label: "a", at: "t", state: { forensicTimeline: [{ id: "x" }], iocs: [], findings: [] } },
        { label: "no-state" }, // dropped — unrestorable
        42, null,
      ],
      redo: [{ state: {} }],
    });
    expect(out.undo).toHaveLength(1);
    expect(out.undo[0].label).toBe("a");
    expect(out.redo).toHaveLength(1);
    expect(out.redo[0]).toEqual({ label: "", at: "", state: {} });
  });
});

describe("ImportUndoStore", () => {
  let store: ImportUndoStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-importundo-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ImportUndoStore(cases, 5);
  });

  it("returns an empty stack when none exists", async () => {
    expect(await store.load("c1")).toEqual({ undo: [], redo: [] });
  });

  it("persists and loads a stack round-trip (full state intact)", async () => {
    const stack = pushCheckpoint(emptyUndoStack(), cp("before", 3, 2, 1, "thor (0003_thor.json)"), store.depth());
    await store.save("c1", stack);
    const loaded = await store.load("c1");
    expect(loaded.undo).toHaveLength(1);
    expect(loaded.undo[0].label).toBe("thor (0003_thor.json)");
    expect(loaded.undo[0].state.forensicTimeline).toHaveLength(3);
    expect(loaded.undo[0].state.iocs).toHaveLength(2);
    expect(loaded.undo[0].state.findings).toHaveLength(1);
    expect(loaded.redo).toEqual([]);
  });

  it("exposes its configured depth", () => {
    expect(store.depth()).toBe(5);
  });
});
