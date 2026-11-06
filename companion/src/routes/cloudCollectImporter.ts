// The import stage's reach into the case (#2311), from the route context: the case's import section
// per page (imports stay serialized), the #2303 streaming importer through the same logged runner
// the import routes use, and the ordinary settle seam (dual-write → tag → demote) after each page.
//
// The replay logic itself — "did this page land?", "forget a dead attempt" — is the engine's
// (integrations/cloudCollect/collectImport.ts); this file only supplies the case operations.

import { captureImportBaseline, releaseImportBaseline } from "../analysis/importBaseline.js";
import {
  ledgerForget,
  timelineLanded,
  type CollectPageImporter,
} from "../integrations/cloudCollect/collectImport.js";
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

export function caseCollectImporter(ctx: RouteContext): CollectPageImporter {
  const store = stateStoreOf(ctx);
  return {
    withImportSection: (caseId, fn) => ctx.importLock.runExclusive(caseId, fn),
    landed: timelineLanded(store),
    forgetAttempt: ledgerForget(ctx.options.cloudRecordStore),
    settleLanded: (caseId, label) => settleLanded(ctx, caseId, label),
    importPage: async (caseId, page, signal) => {
      // Inside the section the engine holds: the baseline is only honest while it is held.
      const baseline = await captureImportBaseline(store, caseId);
      try {
        await runDiskImport(ctx, page.kind, caseId, page.path, page.label, {
          label: page.label,
          idPrefix: page.idPrefix,
          importedAt: page.importedAt,
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
