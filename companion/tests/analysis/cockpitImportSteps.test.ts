import { describe, expect, it } from "vitest";
import { importStepsOf } from "../../src/analysis/cockpitImportSteps.js";
import {
  applyRedo,
  applyUndo,
  deltaCheckpoint,
  emptyUndoStack,
  encodeStack,
  normalizeStack,
  pushCheckpoint,
} from "../../src/analysis/importUndo.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #2466 — which Undo / Redo step the "Since your last review" digest reports, read from the undo
// stack. A fresh import also pushes an undo entry, so an entry is a redo only when Redo marked it.

const withEvents = (n: number): InvestigationState => ({
  ...emptyState("c1"),
  forensicTimeline: Array.from({ length: n }, (_, i) => ({
    id: `e${i}`,
    timestamp: "2026-01-01T00:00:00Z",
    description: `e${i}`,
    severity: "Info" as const,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  })),
});

const BEFORE = withEvents(1);
const AFTER = withEvents(3);
const IMPORTED = pushCheckpoint(
  emptyUndoStack(),
  deltaCheckpoint("thor (0003_thor.json)", "2026-07-30T11:00:00.000Z", BEFORE, AFTER),
);

describe("importStepsOf (#2466)", () => {
  it("reports nothing for a plain import — the import card covers it", () => {
    expect(importStepsOf(IMPORTED)).toEqual({});
    expect(importStepsOf(emptyUndoStack())).toEqual({});
  });

  it("reports the undone import, at the time of the undo", () => {
    const undone = applyUndo(IMPORTED, AFTER, "2026-07-30T11:50:00.000Z")!;
    expect(importStepsOf(undone.stack)).toEqual({
      undone: { label: "thor (0003_thor.json)", at: "2026-07-30T11:50:00.000Z" },
    });
  });

  it("reports the redone import, at the time of the redo, and survives a save and load", () => {
    const undone = applyUndo(IMPORTED, AFTER, "2026-07-30T11:50:00.000Z")!;
    const redone = applyRedo(undone.stack, undone.restore, "2026-07-30T11:55:00.000Z")!;
    const expected = { redone: { label: "thor (0003_thor.json)", at: "2026-07-30T11:55:00.000Z" } };
    expect(importStepsOf(redone.stack)).toEqual(expected);
    const reloaded = normalizeStack(JSON.parse(encodeStack(redone.stack).toString("utf8")));
    expect(importStepsOf(reloaded)).toEqual(expected);
  });

  it("forgets a redo once a new import lands on top of it", () => {
    const undone = applyUndo(IMPORTED, AFTER, "2026-07-30T11:50:00.000Z")!;
    const redone = applyRedo(undone.stack, undone.restore, "2026-07-30T11:55:00.000Z")!;
    const next = pushCheckpoint(
      redone.stack,
      deltaCheckpoint("evtx (Security.evtx)", "2026-07-30T11:58:00.000Z", AFTER, withEvents(4)),
    );
    expect(importStepsOf(next)).toEqual({});
  });
});
