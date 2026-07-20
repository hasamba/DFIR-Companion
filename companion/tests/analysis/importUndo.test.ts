import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
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
  undoMaxBytesFromEnv,
  DEFAULT_UNDO_MAX_BYTES,
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

  it("pushCheckpoint also evicts oldest checkpoints once the stack exceeds a byte budget, even under the depth cap", () => {
    // Each state carries ~2000 events; a byte budget sized for ~2.5 of them forces eviction well
    // before the depth cap (10) would ever kick in — this is the unbounded-growth regression (#?):
    // 10 full-state snapshots of a large case is tens-to-hundreds of MB by design.
    let stack: ImportUndoStack = emptyUndoStack();
    const big = (tag: string, label: string) => cp(tag, 2000, 0, 0, label);
    const oneSize = Buffer.byteLength(JSON.stringify(big("x", "x").state));
    const budget = Math.floor(oneSize * 2.5);

    stack = pushCheckpoint(stack, big("a", "a"), 10, budget);
    stack = pushCheckpoint(stack, big("b", "b"), 10, budget);
    stack = pushCheckpoint(stack, big("c", "c"), 10, budget);
    stack = pushCheckpoint(stack, big("d", "d"), 10, budget);

    const totalBytes = stack.undo.reduce((sum, c) => sum + Buffer.byteLength(JSON.stringify(c.state)), 0);
    expect(totalBytes).toBeLessThanOrEqual(budget);
    expect(stack.undo.length).toBeLessThan(4); // count cap (10) never triggered — size cap did
    expect(stack.undo[stack.undo.length - 1].label).toBe("d"); // newest always survives
  });

  it("pushCheckpoint keeps at least the newest checkpoint even if it alone exceeds the byte budget", () => {
    const huge = cp("huge", 500, 0, 0, "huge");
    const tinyBudget = 10; // smaller than any real checkpoint
    const stack = pushCheckpoint(emptyUndoStack(), huge, 10, tinyBudget);
    expect(stack.undo).toHaveLength(1);
    expect(stack.undo[0].label).toBe("huge");
  });

  it("a non-positive maxBytes disables the size cap (count cap still applies)", () => {
    let stack: ImportUndoStack = emptyUndoStack();
    stack = pushCheckpoint(stack, cp("a", 500, 0, 0, "a"), 2, 0);
    stack = pushCheckpoint(stack, cp("b", 500, 0, 0, "b"), 2, 0);
    expect(stack.undo.map((c) => c.label)).toEqual(["a", "b"]);
  });

  it("undoMaxBytesFromEnv reads DFIR_UNDO_MAX_MB (in MB) and falls back to the default", () => {
    const prev = process.env.DFIR_UNDO_MAX_MB;
    try {
      delete process.env.DFIR_UNDO_MAX_MB;
      expect(undoMaxBytesFromEnv()).toBe(DEFAULT_UNDO_MAX_BYTES);
      process.env.DFIR_UNDO_MAX_MB = "50";
      expect(undoMaxBytesFromEnv()).toBe(50 * 1024 * 1024);
      process.env.DFIR_UNDO_MAX_MB = "not-a-number";
      expect(undoMaxBytesFromEnv()).toBe(DEFAULT_UNDO_MAX_BYTES);
    } finally {
      if (prev === undefined) delete process.env.DFIR_UNDO_MAX_MB; else process.env.DFIR_UNDO_MAX_MB = prev;
    }
  });

  it("applyUndo caps the growing redo stack by depth+size so repeated undos don't grow it unboundedly", () => {
    let stack: ImportUndoStack = emptyUndoStack();
    stack = pushCheckpoint(stack, cp("a", 1, 0, 0, "a"));
    stack = pushCheckpoint(stack, cp("b", 1, 0, 0, "b"));
    stack = pushCheckpoint(stack, cp("c", 1, 0, 0, "c"));
    let current = mkState("cur", 1, 0, 0);
    for (let i = 0; i < 3; i++) {
      const r = applyUndo(stack, current, "2026-06-13T00:00:00Z", 2)!;
      stack = r.stack;
      current = r.restore;
    }
    expect(stack.redo.length).toBeLessThanOrEqual(2); // depth cap applied to redo too
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
  let cases: CaseStore;
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-importundo-"));
    cases = new CaseStore(root);
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

  it("the persisted stack file stays under the configured byte budget after growing far past DEFAULT_UNDO_DEPTH imports (#unbounded-undo-growth)", async () => {
    // Regression for the reported bug: a bulk import of many files against a case whose state
    // keeps growing (mirrors 50 files ballooning a case from ~0 to 41,660 events) must not let
    // the undo-stack file balloon into the hundreds of MB. Depth alone (5 here) is not enough to
    // bound it — the byte budget must actually cap the file on disk.
    const budgetBytes = 1_000_000; // 1MB — small so the test runs fast but still exercises real disk I/O
    const bounded = new ImportUndoStore(cases, 5, budgetBytes);
    let growingEvents = 200;
    for (let i = 0; i < 15; i++) { // well past the depth cap of 5
      growingEvents += 200; // each successive pre-import state is bigger, like a real bulk import
      await bounded.mutate("c1", (stack) => ({
        stack: pushCheckpoint(stack, cp(`s${i}`, growingEvents, 0, 0, `import ${i}`), bounded.depth(), bounded.byteBudget()),
        result: undefined,
      }));
    }
    const raw = await readFile(join(cases.stateDir("c1"), "import-undo-stack.json"), "utf8");
    expect(Buffer.byteLength(raw)).toBeLessThan(budgetBytes * 1.5); // headroom for JSON formatting/metadata, not unbounded
  });

  it("mutate() serializes concurrent load-modify-save calls so no checkpoint is lost to a race", async () => {
    // Regression: pushImportCheckpoint used to load(), pushCheckpoint(), save() with no lock —
    // two overlapping imports (e.g. bulk import 1.5s apart while the previous one's async work is
    // still in flight) race on the same file: the second save clobbers the first (lost update),
    // and both writers spawn simultaneous multi-MB atomic-write temp files for the same case.
    const labels = Array.from({ length: 8 }, (_, i) => `import-${i}`);
    await Promise.all(labels.map((label) =>
      store.mutate("c1", (stack) => ({
        stack: pushCheckpoint(stack, cp(label, 1, 0, 0, label), 20),
        result: undefined,
      })),
    ));
    const loaded = await store.load("c1");
    expect(loaded.undo.map((c) => c.label).sort()).toEqual([...labels].sort());
  });
});
