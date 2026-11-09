import type { CockpitCard } from "./cockpit.js";
import type { ImportUndoStack } from "./importUndo.js";

// Undo / Redo of an import on the "Since your last review" digest (#2466).
//
// The undo route clears the "last import" record (so the banner stops describing a rolled-back
// import) and runs no re-synthesis, which left the digest nothing to show — it read "Nothing new"
// right after the case changed. The undo stack still knows: Undo pushes a redo entry stamped with
// the time of the undo, and Redo pushes an undo entry stamped and marked `redone`. A fresh import
// also pushes an undo entry, but unmarked, and it clears the redo stack — so neither card shows for
// it, and the ordinary import card covers it.

export interface ImportStep {
  label: string;
  at: string;
}

export interface ImportSteps {
  undone?: ImportStep;
  redone?: ImportStep;
}

/** The latest undo still standing and the latest redo, read from the stack. */
export function importStepsOf(stack: ImportUndoStack): ImportSteps {
  const undoTop = stack.undo[stack.undo.length - 1];
  const redoTop = stack.redo[stack.redo.length - 1];
  return {
    ...(redoTop ? { undone: { label: redoTop.label, at: redoTop.at } } : {}),
    ...(undoTop?.redone ? { redone: { label: undoTop.label, at: undoTop.at } } : {}),
  };
}

function stepCard(kind: "undo" | "redo", step: ImportStep): CockpitCard {
  const verb = kind === "undo" ? "undone" : "redone";
  return {
    id: `change:import-${kind}:${step.at}`,
    kind: "change",
    title: `Import ${verb}: ${step.label}`,
    summary:
      kind === "undo"
        ? "Its events, IOCs and findings were taken back out of the case"
        : "Its events, IOCs and findings were put back into the case",
    severity: "Low",
    occurredAt: step.at,
    evidenceIds: [],
    target: { panel: "timeline" },
  };
}

/** One change card per step made after the investigator's last review. */
export function importStepCards(
  steps: ImportSteps | undefined,
  isNew: (at: string) => boolean,
): CockpitCard[] {
  if (!steps) return [];
  return [
    ...(steps.undone && isNew(steps.undone.at) ? [stepCard("undo", steps.undone)] : []),
    ...(steps.redone && isNew(steps.redone.at) ? [stepCard("redo", steps.redone)] : []),
  ];
}
