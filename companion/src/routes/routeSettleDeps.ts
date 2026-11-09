import { autoTagNewEvents } from "../analysis/taggerAuto.js";
import { tagCollectorFootprint } from "../analysis/cloudCollectorFootprint.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { nodeCollectFs } from "../integrations/cloudCollect/collectFs.js";
import { createCollectorRunReader } from "../integrations/cloudCollect/collectRuns.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { SettleDeps } from "./importSettle.js";
import type { RouteContext } from "./context.js";

/**
 * The SettleDeps a route hands settleForensicImport, from the route context: the import routes and
 * the import replay (routes/analysisRuns.ts, #1891) settle through ONE wiring, so a replay crosses
 * the same super-timeline write → auto-tagger → demote as a live import of the same file.
 * (composition/importIngestSettle.ts builds the streamed-ingest twin from AppOptions; routes may
 * not import composition.) Null when no state store is wired: there is nothing to settle.
 */
/** What routeSettleDeps reads from the context: the drop folder's streamed import builds this too (#2336). */
export type SettleContext = Pick<
  RouteContext,
  "options" | "store" | "runStateExclusive" | "serverLogger" | "demoteForensic"
>;

// One reader for the process: its per-collection cache outlives a single import (#2487).
const collectorRuns = createCollectorRunReader(nodeCollectFs);

export interface ImportTaggerDeps {
  options: RouteContext["options"];
  store: Pick<CaseStore, "caseDir">;
  runStateExclusive: RouteContext["runStateExclusive"];
  logLine: (message: string) => void;
}

/**
 * The tagging every import's new rows get (server.ts binds the same one): the content tagger
 * (best effort, TAGGER_AUTO-gated, analysis/taggerAuto.ts), then the collector-footprint tag (#2487:
 * a cloud collection's own API calls; tag only, never a grade; not TAGGER_AUTO-gated).
 */
export function importTagger(d: ImportTaggerDeps): (caseId: string, added: ForensicEvent[]) => Promise<void> {
  const { options } = d;
  return async (caseId, added) => {
    await autoTagNewEvents(
      {
        taggerStore: options.taggerStore,
        tagsStore: options.tagsStore,
        stateStore: options.stateStore,
        analysisRunStore: options.analysisRunStore,
        operationalMetrics: options.operationalMetrics,
        onTags: options.onTags,
        runStateExclusive: d.runStateExclusive,
        logLine: d.logLine,
      },
      caseId,
      added,
    );
    const tags = options.tagsStore;
    if (!tags) return;
    await tagCollectorFootprint(
      {
        tags,
        runsFor: (id) => collectorRuns(d.store.caseDir(id)),
        ...(options.onTags ? { onTags: options.onTags } : {}),
        logLine: d.logLine,
      },
      caseId,
      added,
    );
  };
}

export function routeSettleDeps(ctx: SettleContext): SettleDeps | null {
  const { options } = ctx;
  if (!options.stateStore) return null;
  const autoTagImported = importTagger({
    options,
    store: ctx.store,
    runStateExclusive: ctx.runStateExclusive,
    logLine: (m) => ctx.serverLogger.info(m),
  });
  return {
    stateStore: options.stateStore,
    runStateExclusive: ctx.runStateExclusive,
    superTimelineStore: options.superTimelineStore,
    onSuperTimeline: options.onSuperTimeline,
    onStateChanged: options.onStateChanged,
    onState: options.onState,
    autoTagImported,
    demoteForensic: ctx.demoteForensic,
  };
}
