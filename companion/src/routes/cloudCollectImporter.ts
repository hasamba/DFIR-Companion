// The import stage's reach into the case (#2311), from the route context: the case's import section
// per page (imports stay serialized), the #2303 streaming importer through the same logged runner
// the import routes use, and the ordinary settle seam (dual-write → tag → demote) after each page.
//
// The replay logic itself — "did this page land?", "forget a dead attempt" — is the engine's
// (integrations/cloudCollect/collectImport.ts); this file only supplies the case operations.
//
// A page of a kind that summarizes per collection skips its own whole-export summaries; the
// collection summary (#2482) is landed and settled here like a page, under its fixed label.

import { captureImportBaseline, releaseImportBaseline } from "../analysis/importBaseline.js";
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
import { settleForensicImport } from "./importSettle.js";
import { routeSettleDeps } from "./routeSettleDeps.js";

function stateStoreOf(ctx: RouteContext) {
  const store = ctx.options.stateStore;
  if (!store) throw new Error("cloud collection cannot reach the case state store");
  return store;
}

/** Settle the rows of a page whose import committed before a crash. Every step is idempotent. */
async function settleLanded(ctx: RouteContext, caseId: string, label: string): Promise<void> {
  const settle = routeSettleDeps(ctx);
  if (!settle) return;
  const state = await stateStoreOf(ctx).load(caseId);
  const rows = state.forensicTimeline.filter((e) => e.sourceScreenshots.includes(label));
  if (rows.length) {
    await ctx.options.superTimelineStore?.appendReporting(caseId, rows); // dedups by id
    await settle.autoTagImported(caseId, rows);
  }
  await ctx.demoteForensic(caseId);
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
  const baseline = await captureImportBaseline(store, caseId);
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
    if (rebuilt.length) {
      await ctx.options.superTimelineStore?.appendReporting(caseId, rebuilt); // dedups by id
      await settle.autoTagImported(caseId, rebuilt);
    }
    await settleForensicImport(settle, caseId, baseline, req.label);
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
      const baseline = await captureImportBaseline(store, caseId);
      try {
        await runDiskImport(ctx, page.kind, caseId, page.path, page.label, {
          label: page.label,
          idPrefix: page.idPrefix,
          importedAt: page.importedAt,
          skipSummaries: summarizesPerCollection(page.kind),
          coverageGroup: collectionCoverageGroup(page.collectionId),
          ...(signal ? { signal } : {}),
        });
        const settle = routeSettleDeps(ctx);
        if (settle) await settleForensicImport(settle, caseId, baseline, page.label);
      } finally {
        await releaseImportBaseline(store, baseline);
      }
    },
  };
}
