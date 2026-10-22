// #76 Import undo/redo. Imports can flood the dashboard; these let the analyst roll the forensic
// timeline + IOCs back to the pre-import snapshot (and redo). The synthesis-derived conclusions are
// re-derived from the restored timeline by resynthesizeInBackground, exactly as on import.
//
// Moved out of routes/import.ts (at its file-size ledger) for #2220 and registered at the same
// position: a step whose checkpoint carries super-timeline rows (a Sigma re-grade) writes them back
// through the super-timeline store and announces the change.

import type { Express, Request, Response } from "express";
import {
  summarizeUndoStack,
  applyUndo,
  applyRedo,
  runUndoStep,
  type UndoStepDeps,
} from "../analysis/importUndo.js";
import type { RenameLedger } from "../analysis/hostRenameCarry.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { sendPipelineError } from "./presidioApproval.js";
import { rehomeSuperTimeline, type SuperRehomeStore } from "./importSettleRehomeSuper.js";
import type { RouteContext } from "./context.js";

export function registerImportUndoRoutes(app: Express, ctx: RouteContext): void {
  const { options, importLock } = ctx;

  // Current undo/redo state (button enable + labels). Lightweight summary, not the raw snapshots.
  app.get("/cases/:id/import/undo-stack", async (req: Request, res: Response) => {
    if (!options.importUndoStore) return res.status(501).json({ error: "import undo not configured" });
    try {
      const stack = await options.importUndoStore.load(req.params.id);
      return res.status(200).json(summarizeUndoStack(stack, options.importUndoStore.depth()));
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });

  /** Undo (restore the full pre-import state, push the current one to redo) or its mirror, Redo. */
  const stepRoute = (step: typeof applyUndo, nothing: string) => async (req: Request, res: Response) => {
    const undoStore = options.importUndoStore;
    if (!undoStore || !options.stateStore)
      return res.status(501).json({ error: "import undo not configured" });
    const caseId = req.params.id;
    try {
      const deps: UndoStepDeps = {
        undoStore,
        stateStore: options.stateStore,
        importLock,
        runStateExclusive: ctx.runStateExclusive,
        superTimeline: options.superTimelineStore,
        rehomeSuper: superRehomer(options.superTimelineStore),
      };
      const { summary, next, superChanged } = await runUndoStep(deps, caseId, step);
      if (!summary) return res.status(400).json({ error: nothing });
      // The "last import" banner / NEW row highlights describe a change that has now been rolled back.
      if (options.importMetaStore) {
        try {
          await options.importMetaStore.clear(caseId);
          options.onImportMeta?.(caseId);
        } catch {
          /* non-fatal */
        }
      }
      options.onImportUndo?.(caseId);
      if (superChanged) options.onSuperTimeline?.(caseId);
      if (next) options.onState?.(next);
      return res.status(200).json(summary);
    } catch (err) {
      return sendPipelineError(res, err);
    }
  };

  // No AI re-synthesis — the snapshot is the exact prior state.
  app.post("/cases/:id/import/undo", stepRoute(applyUndo, "nothing to undo"));
  // Redo the most-recently-undone import: re-apply its full state.
  app.post("/cases/:id/import/redo", stepRoute(applyRedo, "nothing to redo"));
}

// A step that changes the host-rename ledger re-homes the super-timeline against the ledger it
// restored (#2221) — the same pass settle runs (#1508), and on an EMPTY ledger too, because Undo of the
// import that taught the first rename restores none. A store without the scan (a test fake) is skipped.
function superRehomer(
  store: Partial<SuperRehomeStore> | undefined,
): ((caseId: string, ledger: RenameLedger) => Promise<number>) | undefined {
  if (!store?.rehome || !store.eventBatches) return undefined;
  const scan = store as SuperRehomeStore;
  return async (caseId, ledger) => {
    try {
      return await rehomeSuperTimeline(scan, caseId, ledger, { evenWithoutLedger: true });
    } catch (error) {
      getServerLogger().warn(
        `[import] ${caseId}: super-timeline rename re-home after undo/redo failed — ${error instanceof Error ? error.message : String(error)}`,
        { caseId },
      );
      throw error;
    }
  };
}
