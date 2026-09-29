import { describe, it, expect } from "vitest";
import {
  emptyState,
  type ForensicEvent,
  type IOC,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import { computeUndoDelta, applyUndoDelta, isStateDelta } from "../../src/analysis/importUndoDelta.js";

// #1874 item 3: an undo checkpoint is the inverse delta between the pre-import state and the state
// the import left, not a full copy of the case.

const ev = (id: string, extra: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: id,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...extra,
});
const ioc = (id: string, extra: Partial<IOC> = {}): IOC => ({
  id,
  type: "ip",
  value: id,
  firstSeen: "2026-01-01T00:00:00Z",
  ...extra,
});
const st = (events: ForensicEvent[], iocs: IOC[] = [], extra: Partial<InvestigationState> = {}) => ({
  ...emptyState("c1"),
  forensicTimeline: events,
  iocs,
  ...extra,
});
const ids = (a: { id: string }[]) => a.map((x) => x.id);
// Stored checkpoints are JSON — every round trip below goes through it.
const viaJson = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const undo = (before: InvestigationState, after: InvestigationState, current = after) =>
  applyUndoDelta(current, viaJson(computeUndoDelta(before, after)));

describe("computeUndoDelta / applyUndoDelta", () => {
  it("undo of an append-only import returns the exact pre-import state", () => {
    const before = st([ev("a"), ev("b")], [ioc("i1")]);
    const after = st([ev("a"), ev("b"), ev("c"), ev("d")], [ioc("i1"), ioc("i2")], {
      lastSummary: "after",
      updatedAt: "2026-02-01T00:00:00Z",
    });
    expect(undo(before, after)).toEqual(before);
  });

  it("stores only the rows the import touched, not the whole timeline", () => {
    const base = Array.from({ length: 500 }, (_, i) => ev(`e${i}`, { description: "x".repeat(200) }));
    const before = st(base);
    const after = st([...base, ev("new")]);
    const delta = computeUndoDelta(before, after);
    expect(JSON.stringify(delta).length).toBeLessThan(2_000);
    expect(isStateDelta(viaJson(delta))).toBe(true);
  });

  it("restores changed and removed rows at their original positions", () => {
    const before = st([ev("a"), ev("b"), ev("c"), ev("d"), ev("e")], [ioc("i1"), ioc("i2")]);
    const after = st(
      // b changed (evidence accumulated), d removed (demoted / folded), x and y added
      [ev("x"), ev("a"), ev("b", { description: "b+evidence" }), ev("c"), ev("e"), ev("y")],
      [ioc("i1", { extractedFrom: ["x"] }), ioc("i3")],
    );
    expect(undo(before, after)).toEqual(before);
  });

  it("restores the exact order when the import reordered untouched rows", () => {
    const before = st([ev("a"), ev("b"), ev("c")]);
    const after = st([ev("c"), ev("new"), ev("a"), ev("b")]);
    const delta = computeUndoDelta(before, after);
    expect(delta.keyed.forensicTimeline.order).toEqual(["a", "b", "c"]);
    expect(undo(before, after)).toEqual(before);
  });

  it("stores every non-keyed field as its before-value, even when the import left it unchanged", () => {
    // The synthesis that runs AFTER the checkpoint rewrites findings / narrative; undo reverts it.
    const before = st([ev("a")], [], { lastSummary: "pre", attackerPath: "pre-path" });
    const after = st([ev("a"), ev("b")], [], { lastSummary: "pre", attackerPath: "pre-path" });
    const later = { ...after, lastSummary: "synthesized", attackerPath: "new path", findings: [] };
    const restored = undo(before, after, later);
    expect(restored.lastSummary).toBe("pre");
    expect(restored.attackerPath).toBe("pre-path");
  });

  it("removes a top-level field the pre-import state did not have", () => {
    const before = st([ev("a")]);
    delete (before as Partial<InvestigationState>).intelRetirementDecisions;
    const after = st([ev("a")], [], {
      hostRenames: [{ from: "OLD", to: "NEW" } as never],
      collectorHostnames: ["NEW"],
    });
    const restored = undo(before, after);
    expect(restored).toEqual(before);
    expect("hostRenames" in restored).toBe(false);
    expect("collectorHostnames" in restored).toBe(false);
  });

  it("falls back to a whole-array before-value when ids are missing or duplicated", () => {
    const before = st([ev("a"), ev("a")]);
    const after = st([ev("a"), ev("a"), ev("b")]);
    const delta = computeUndoDelta(before, after);
    expect(delta.keyed.forensicTimeline).toBeUndefined();
    expect(delta.fields.forensicTimeline).toEqual(before.forensicTimeline);
    expect(undo(before, after)).toEqual(before);
  });

  it("redo is the same function in the other direction", () => {
    const before = st([ev("a"), ev("b"), ev("c")], [ioc("i1")]);
    const after = st([ev("b", { severity: "Critical" }), ev("c"), ev("d")], [ioc("i2")], {
      lastSummary: "s",
    });
    const restored = undo(before, after);
    const redone = applyUndoDelta(restored, viaJson(computeUndoDelta(after, restored)));
    expect(redone).toEqual(after);
  });

  it("does not mutate its inputs", () => {
    const before = st([ev("a"), ev("b")], [ioc("i1")]);
    const after = st([ev("b"), ev("c")], [ioc("i1"), ioc("i2")]);
    const snapBefore = structuredClone(before);
    const snapAfter = structuredClone(after);
    const delta = computeUndoDelta(before, after);
    applyUndoDelta(after, delta);
    expect(before).toEqual(snapBefore);
    expect(after).toEqual(snapAfter);
  });

  describe("a later non-import write (the documented rule)", () => {
    const before = st([ev("a"), ev("b"), ev("c")], [ioc("i1")]);
    const after = st(
      [ev("a"), ev("b", { description: "b+import" }), ev("c"), ev("n1"), ev("n2")],
      [ioc("i1"), ioc("i2")],
    );

    it("keeps a row or IOC another writer added after the import, next to its neighbour", () => {
      const later = st(
        [ev("a"), ev("m1"), ev("b", { description: "b+import" }), ev("c"), ev("n1"), ev("n2"), ev("m2")],
        [ioc("i1"), ioc("i2"), ioc("i9")],
      );
      const restored = undo(before, after, later);
      // b goes back right after its pre-import neighbour a; m1 still follows a, then b.
      expect(ids(restored.forensicTimeline)).toEqual(["a", "b", "m1", "c", "m2"]);
      expect(restored.forensicTimeline[1].description).toBe("b");
      expect(ids(restored.iocs)).toEqual(["i1", "i9"]);
    });

    it("keeps a later edit to a row the import did not touch", () => {
      const later = {
        ...after,
        forensicTimeline: after.forensicTimeline.map((e) =>
          e.id === "c" ? { ...e, severity: "Critical" as const } : e,
        ),
      };
      const restored = undo(before, after, later);
      expect(restored.forensicTimeline.find((e) => e.id === "c")?.severity).toBe("Critical");
    });

    it("puts back the pre-import image of a row the import changed, over a later edit", () => {
      const later = {
        ...after,
        forensicTimeline: after.forensicTimeline.map((e) =>
          e.id === "b" ? { ...e, severity: "Critical" as const } : e,
        ),
      };
      const restored = undo(before, after, later);
      expect(restored.forensicTimeline.find((e) => e.id === "b")).toEqual(ev("b"));
    });

    it("removes a row the import added even after a later edit to it", () => {
      const later = {
        ...after,
        forensicTimeline: after.forensicTimeline.map((e) =>
          e.id === "n1" ? { ...e, severity: "Critical" as const } : e,
        ),
      };
      expect(ids(undo(before, after, later).forensicTimeline)).toEqual(["a", "b", "c"]);
    });

    it("restores a row whose anchor another writer deleted, at its old index", () => {
      const imp = st([ev("a"), ev("c")]); // the import removed b
      const later = st([ev("c")]); // someone then removed a
      const restored = undo(st([ev("a"), ev("b"), ev("c")]), imp, later);
      // b's anchor (a) is gone, so b goes back at its old index (1), clamped to the list.
      expect(ids(restored.forensicTimeline)).toEqual(["c", "b"]);
    });

    it("keeps later-added rows when the delta carries a full order", () => {
      const b2 = st([ev("a"), ev("b"), ev("c")]);
      const a2 = st([ev("c"), ev("a"), ev("b")]);
      const later = st([ev("c"), ev("z"), ev("a"), ev("b")]);
      const restored = undo(b2, a2, later);
      expect(ids(restored.forensicTimeline)).toEqual(["a", "b", "c", "z"]);
    });
  });
});

describe("isStateDelta", () => {
  it("rejects anything that is not a delta", () => {
    expect(isStateDelta(null)).toBe(false);
    expect(isStateDelta({})).toBe(false);
    expect(isStateDelta({ v: 1, fields: {}, absent: [], keyed: { forensicTimeline: { added: "x" } } })).toBe(
      false,
    );
    expect(isStateDelta({ v: 1, fields: {}, absent: [], keyed: {} })).toBe(true);
  });
});
