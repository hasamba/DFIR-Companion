// The import stage's reach into the case (#2311), from the route context: the case's import section
// per page (imports stay serialized), the #2303 streaming importer through the same logged runner
// the import routes use, and the ordinary settle seam (dual-write → tag → demote) after each page.
//
// The replay logic itself — "did this page land?", "forget a dead attempt" — is the engine's
// (integrations/cloudCollect/collectImport.ts); this file only supplies the case operations.
//
// A page of a kind that summarizes per collection skips its own whole-export summaries; the
// collection summary (#2482) is landed and settled here like a page, under its fixed label.

import {
  captureImportBaseline,
  releaseImportBaseline,
  type ImportBaseline,
} from "../analysis/importBaseline.js";
import { summarizesPerCollection } from "../analysis/ingest/cloudStreamProviders.js";
import { collectionCoverageGroup } from "../analysis/cloudCoverageFold.js";
import {
  ledgerForget,
  timelineLanded,
  type CollectPageImporter,
} from "../integrations/cloudCollect/collectImport.js";
import type { CollectionSummaryRequest } from "../integrations/cloudCollect/collectSummary.js";
import type { RouteContext } from "./context.js";
import { runDiskImport } from "./importCloudStream.js";
import {
  gradeStampedRows,
  recoveryDepsFromSettle,
  settleImportOrRecoverThenThrow,
} from "./importRowRecovery.js";
import { dualWriteAndTagPaged } from "./importSettlePaged.js";
import { runUnlocked } from "./importSettleRows.js";
import { routeSettleDeps } from "./routeSettleDeps.js";
import { gradeArmOf } from "./importSettle.js";

/**
 * The settle of a page or summary. A failure still fails the collection, but only after the rows the
 * import merged are stamped, dual-written and tagged (#2891): the next demote is case-wide, and a
 * Resume that would settle them may never come. Called inside the engine's import section.
 */
function settleCollected(
  ctx: RouteContext,
  caseId: string,
  baseline: ImportBaseline,
  label: string,
  preGraded?: readonly string[],
) {
  const settle = routeSettleDeps(ctx);
  if (!settle) return Promise.resolve(null);
  const target = { caseId, storedNames: [label], tag: "cloud-collect" };
  return settleImportOrRecoverThenThrow(settle, target, baseline, label, preGraded ? { preGraded } : {});
}

function stateStoreOf(ctx: RouteContext) {
  const store = ctx.options.stateStore;
  if (!store) throw new Error("cloud collection cannot reach the case state store");
  return store;
}

/**
 * Settle the rows of a page whose import committed before a crash. Every step is idempotent: the
 * super-timeline copy dedups by id (and never carries the grade mark), the tagger runs by mark, the
 * demote moves only rows the tagger finished on among marked ones, and those lose their mark (#2909).
 */
async function settleLanded(ctx: RouteContext, caseId: string, label: string): Promise<void> {
  const settle = routeSettleDeps(ctx);
  if (!settle) return;
  const state = await stateStoreOf(ctx).load(caseId);
  const ids = state.forensicTimeline.filter((e) => e.sourceScreenshots.includes(label)).map((e) => e.id);
  await gradeStampedRows(recoveryDepsFromSettle(settle), caseId, ids);
}

/**
 * Land one collection summary and settle it, as an undoable import with its own baseline.
 *
 * A rebuild (Resume, or a replay after a crash between the summary's commit and its settle) upserts
 * rows the baseline already holds, and the settle only dual-writes and tags rows NEW to the case —
 * so a Low summary a tagger rule would raise could be demoted untagged. Every kept row the baseline
 * already held is therefore dual-written (by id: a copy the store holds is skipped) and offered to
 * the tagger first, as page recovery does (settleLanded); the settle then handles the new ones and
 * demotes.
 */
async function importSummary(
  ctx: RouteContext,
  caseId: string,
  req: CollectionSummaryRequest,
  signal?: AbortSignal,
): Promise<void> {
  const store = stateStoreOf(ctx);
  const pipeline = ctx.options.pipeline;
  if (!pipeline) throw new Error("pipeline is not configured");
  const baseline = await captureImportBaseline(store, caseId, {
    markGrade: gradeArmOf(routeSettleDeps(ctx)),
  });
  try {
    const built = await pipeline.importCloudCollectionSummary(caseId, req.kind, req.pages, {
      collectionId: req.collectionId,
      label: req.label,
      idPrefix: req.idPrefix,
      importedAt: req.importedAt,
      ...(signal ? { signal } : {}),
    });
    const settle = routeSettleDeps(ctx);
    if (!settle) return;
    const held = new Set(baseline.outline.ids);
    const kept = new Set(built.ids);
    const rebuilt = built.state.forensicTimeline.filter((e) => kept.has(e.id) && held.has(e.id));
    // #2909: dual-written without the grade mark, tagged by mark; the rows the tagger finished on are
    // handed to the settle, whose demote may move them and which removes their mark.
    const preGraded = rebuilt.length
      ? (
          await dualWriteAndTagPaged(
            { ...settle, runStateExclusive: settle.runStateExclusive ?? runUnlocked },
            caseId,
            rebuilt.map((e) => e.id),
          )
        ).gradedIds
      : [];
    await settleCollected(ctx, caseId, baseline, req.label, preGraded);
  } finally {
    await releaseImportBaseline(store, baseline);
  }
}

export function caseCollectImporter(ctx: RouteContext): CollectPageImporter {
  const store = stateStoreOf(ctx);
  return {
    withImportSection: (caseId, fn) => ctx.importLock.runExclusive(caseId, fn),
    landed: timelineLanded(store),
    forgetAttempt: ledgerForget(ctx.options.cloudRecordStore),
    settleLanded: (caseId, label) => settleLanded(ctx, caseId, label),
    summarizesPerCollection,
    importSummary: (caseId, req, signal) => importSummary(ctx, caseId, req, signal),
    importPage: async (caseId, page, signal) => {
      // Inside the section the engine holds: the baseline is only honest while it is held.
      const baseline = await captureImportBaseline(store, caseId, {
        markGrade: gradeArmOf(routeSettleDeps(ctx)),
      });
      try {
        await runDiskImport(ctx, page.kind, caseId, page.path, page.label, {
          label: page.label,
          idPrefix: page.idPrefix,
          importedAt: page.importedAt,
          skipSummaries: summarizesPerCollection(page.kind),
          coverageGroup: collectionCoverageGroup(page.collectionId),
          ...(signal ? { signal } : {}),
        });
        await settleCollected(ctx, caseId, baseline, page.label);
      } finally {
        await releaseImportBaseline(store, baseline);
      }
    },
  };
}
