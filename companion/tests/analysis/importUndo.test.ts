import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";
import {
  ImportUndoStore,
  emptyUndoStack,
  pushCheckpoint,
  applyUndo,
  applyRedo,
  summarizeUndoStack,
  normalizeStack,
  type ImportUndoStack,
  type ImportSnapshot,
} from "../../src/analysis/importUndo.js";

// Build a snapshot with `n` events + `m` IOCs, tagged so we can assert which snapshot was restored.
function snap(tag: string, n: number, m: number): ImportSnapshot {
  const events: ForensicEvent[] = Array.from({ length: n }, (_, i) => ({
    id: `${tag}-e${i}`,
    timestamp: `2026-01-0${(i % 9) + 1}T00:00:00Z`,
    description: `${tag} event ${i}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
  const iocs: IOC[] = Array.from({ length: m }, (_, i) => ({
    id: `${tag}-i${i}`,
    type: "ip",
    value: `10.0.${tag.length}.${i}`,
    firstSeen: "2026-01-01T00:00:00Z",
  }));
  return { forensicTimeline: events, iocs };
}

const cp = (tag: string, n: number, m: number, label: string, at = "2026-06-13T00:00:00Z") => ({
  ...snap(tag, n, m), label, at,
});

describe("importUndo pure operations", () => {
  it("pushCheckpoint appends to undo, clears redo, and caps depth (oldest dropped)", () => {
    let stack: ImportUndoStack = { undo: [], redo: [cp("r", 1, 0, "stale-redo")] };
    stack = pushCheckpoint(stack, cp("a", 1, 1, "a"), 3);
    expect(stack.redo).toEqual([]); // a new import invalidates redo history
    stack = pushCheckpoint(stack, cp("b", 2, 2, "b"), 3);
    stack = pushCheckpoint(stack, cp("c", 3, 3, "c"), 3);
    stack = pushCheckpoint(stack, cp("d", 4, 4, "d"), 3); // exceeds depth 3 -> "a" drops
    expect(stack.undo.map((c) => c.label)).toEqual(["b", "c", "d"]);
  });

  it("applyUndo returns null when there is nothing to undo", () => {
    expect(applyUndo(emptyUndoStack(), snap("cur", 5, 5))).toBeNull();
  });

  it("applyRedo returns null when there is nothing to redo", () => {
    expect(applyRedo(emptyUndoStack(), snap("cur", 5, 5))).toBeNull();
  });

  it("undo restores the pre-import snapshot and pushes the current state to redo (with label carried)", () => {
    // undo top is the snapshot taken before "thor" ran (2 events). Current state has 9 (post-import).
    const stack: ImportUndoStack = { undo: [cp("before-thor", 2, 1, "thor (0003_thor.json)")], redo: [] };
    const current = snap("post", 9, 4);
    const r = applyUndo(stack, current, "2026-06-13T10:00:00Z")!;
    expect(r.restore.forensicTimeline).toHaveLength(2); // restored the pre-import state
    expect(r.stack.undo).toHaveLength(0);
    expect(r.stack.redo).toHaveLength(1);
    expect(r.stack.redo[0].forensicTimeline).toHaveLength(9); // current state preserved for redo
    expect(r.stack.redo[0].label).toBe("thor (0003_thor.json)"); // redo re-applies the same import
    expect(r.stack.redo[0].at).toBe("2026-06-13T10:00:00Z");
  });

  it("round-trips through a full S0 -> S1 -> S2 import/undo/redo sequence", () => {
    // Two imports stacked: undo holds the pre-import snapshots S0 (before A) and S1 (before B).
    let stack: ImportUndoStack = emptyUndoStack();
    stack = pushCheckpoint(stack, cp("S0", 1, 0, "import A"));
    stack = pushCheckpoint(stack, cp("S1", 3, 1, "import B"));
    const S2 = snap("S2", 7, 2);

    // Undo B: back to S1, S2 on redo.
    const u1 = applyUndo(stack, S2)!;
    expect(u1.restore.forensicTimeline).toHaveLength(3); // S1
    stack = u1.stack;

    // Undo A: back to S0, S1 on redo.
    const u2 = applyUndo(stack, u1.restore)!;
    expect(u2.restore.forensicTimeline).toHaveLength(1); // S0
    expect(u2.stack.undo).toHaveLength(0);
    expect(u2.stack.redo.map((c) => c.label)).toEqual(["import B", "import A"]);
    stack = u2.stack;

    // Redo A: forward to S1.
    const r1 = applyRedo(stack, u2.restore)!;
    expect(r1.restore.forensicTimeline).toHaveLength(3); // S1
    stack = r1.stack;

    // Redo B: forward to S2.
    const r2 = applyRedo(stack, r1.restore)!;
    expect(r2.restore.forensicTimeline).toHaveLength(7); // S2
    expect(r2.stack.redo).toHaveLength(0);
    expect(r2.stack.undo.map((c) => c.label)).toEqual(["import A", "import B"]);
  });

  it("summarizeUndoStack reports availability, counts, and the next undo/redo", () => {
    const empty = summarizeUndoStack(emptyUndoStack(), 5);
    expect(empty.canUndo).toBe(false);
    expect(empty.canRedo).toBe(false);
    expect(empty.maxDepth).toBe(5);
    expect(empty.nextUndo).toBeNull();

    const stack: ImportUndoStack = { undo: [cp("a", 2, 1, "a"), cp("b", 4, 3, "thor")], redo: [cp("c", 9, 5, "siem")] };
    const s = summarizeUndoStack(stack, 5);
    expect(s.canUndo).toBe(true);
    expect(s.canRedo).toBe(true);
    expect(s.nextUndo).toEqual({ label: "thor", at: "2026-06-13T00:00:00Z", events: 4, iocs: 3 });
    expect(s.nextRedo).toEqual({ label: "siem", at: "2026-06-13T00:00:00Z", events: 9, iocs: 5 });
    expect(s.undo).toHaveLength(2);
  });

  it("normalizeStack coerces garbage / partial input into a clean stack", () => {
    expect(normalizeStack(null)).toEqual(emptyUndoStack());
    expect(normalizeStack("nope")).toEqual(emptyUndoStack());
    expect(normalizeStack({ undo: "x" })).toEqual(emptyUndoStack());
    const out = normalizeStack({
      undo: [{ label: "a", at: "t", forensicTimeline: [{ id: "x" }], iocs: [] }, 42, null],
      redo: [{}],
    });
    expect(out.undo).toHaveLength(1);
    expect(out.undo[0].forensicTimeline).toHaveLength(1);
    expect(out.redo).toHaveLength(1);
    expect(out.redo[0]).toEqual({ label: "", at: "", forensicTimeline: [], iocs: [] });
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

  it("persists and loads a stack round-trip (full snapshots intact)", async () => {
    const stack = pushCheckpoint(emptyUndoStack(), cp("before", 3, 2, "thor (0003_thor.json)"), store.depth());
    await store.save("c1", stack);
    const loaded = await store.load("c1");
    expect(loaded.undo).toHaveLength(1);
    expect(loaded.undo[0].label).toBe("thor (0003_thor.json)");
    expect(loaded.undo[0].forensicTimeline).toHaveLength(3);
    expect(loaded.undo[0].iocs).toHaveLength(2);
    expect(loaded.redo).toEqual([]);
  });

  it("exposes its configured depth", () => {
    expect(store.depth()).toBe(5);
  });
});
