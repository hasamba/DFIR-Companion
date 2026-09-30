import { autoTagNewEvents } from "../analysis/taggerAuto.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { SettleDeps } from "./importSettle.js";
import type { RouteContext } from "./context.js";

/**
 * The SettleDeps a route hands settleForensicImport, from the route context: the import routes and
 * the import replay (routes/analysisRuns.ts, #1891) settle through ONE wiring, so a replay crosses
 * the same super-timeline write → auto-tagger → demote as a live import of the same file.
 * (composition/importIngestSettle.ts builds the streamed-ingest twin from AppOptions; routes may
 * not import composition.) Null when no state store is wired: there is nothing to settle.
 */
export function routeSettleDeps(ctx: RouteContext): SettleDeps | null {
  const { options } = ctx;
  if (!options.stateStore) return null;
  // Auto-tag only newly imported super-timeline events; best-effort and TAGGER_AUTO-gated.
  const autoTagImported = (caseId: string, added: ForensicEvent[]): Promise<void> =>
    autoTagNewEvents(
      {
        taggerStore: options.taggerStore,
        tagsStore: options.tagsStore,
        stateStore: options.stateStore,
        analysisRunStore: options.analysisRunStore,
        operationalMetrics: options.operationalMetrics,
        onTags: options.onTags,
        runStateExclusive: ctx.runStateExclusive,
        logLine: (m) => ctx.serverLogger.info(m),
      },
      caseId,
      added,
    );
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
