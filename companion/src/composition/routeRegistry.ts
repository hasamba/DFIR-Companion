/**
 * The route-registration sequence: every `registerXRoutes(app, ctx)` call, in order, plus the two
 * non-route mounts that are interleaved with them. Lifted out of createApp by #416.
 *
 * THE ORDER IS THE CONTRACT, for three separate reasons, and each is called out at its line below:
 *   a GATE only covers what is registered after it (mountAiRateLimit),
 *   a GREEDY route makes a later one unreachable (interactive report before reports-export),
 *   a HOOK must exist before the first write it is meant to observe (custody on store).
 * tests/architecture/routeInventory.test.ts records the whole interleaved layer list, so a
 * reordering here shows up as a diff in review rather than as a silently unreachable route.
 *
 * This file has one job and takes no decisions: everything it needs is already on `ctx`.
 */
import type { Express } from "express";
import type { RouteContext } from "../routes/context.js";
import { createCaseExistsGate } from "../analysis/caseExistsGate.js";
import { mountAiRateLimit } from "./aiRateLimit.js";
import { mountCaseWriteGuard } from "./caseWriteGuard.js";
import { registerSystemRoutes } from "../routes/system.js";
import { registerGeoTileRoutes } from "../routes/geoTiles.js";
import { registerAiModelRoutes } from "../routes/aiModels.js";
import { registerCaptureRoutes } from "../routes/captures.js";
import { registerPushNotifyRoutes } from "../routes/pushNotify.js";
import { registerTemplatesViewsRoutes } from "../routes/templatesViews.js";
import { registerToolsRoutes } from "../routes/tools.js";
import { registerImportRoutes } from "../routes/import.js";
import { registerVelociraptorRoutes } from "../routes/velociraptor.js";
import { registerThreatIntelRoutes } from "../routes/threatIntel.js";
import { registerEnrichmentTestRoutes } from "../routes/enrichmentTest.js";
import { registerAnonymizationRoutes } from "../routes/anonymization.js";
import { registerTimelineRoutes } from "../routes/timeline.js";
import { registerAnalysisGraphRoutes } from "../routes/analysisGraph.js";
import { registerSessionSegmentationRoutes } from "../routes/sessionSegmentation.js";
import { registerFindingsRoutes } from "../routes/findings.js";
import { registerTaggerRoutes } from "../routes/tagger.js";
import { registerCustodyRoutes } from "../routes/custody.js";
import { registerMcpRoutes } from "../routes/mcp.js";
import { registerPlaybookHuntsRoutes } from "../routes/playbookHunts.js";
import { registerPlaybookMatchRoutes } from "../routes/playbookMatch.js";
import { registerAiSynthesisRoutes } from "../routes/aiSynthesis.js";
import { registerFindingsDisplayRoutes } from "../routes/findingsDisplay.js";
import { registerReportsExportRoutes } from "../routes/reportsExport.js";
import { registerInteractiveReportRoutes } from "../routes/interactiveReport.js";
import { registerReportVersionsRoutes } from "../routes/reportVersions.js";
import { registerAnalysisRunRoutes } from "../routes/analysisRuns.js";
import { registerCasePasswordRoutes } from "../routes/casePassword.js";
import { registerCaseLifecycleRoutes } from "../routes/caseLifecycle.js";
import { registerJobRoutes } from "../routes/jobs.js";
import { registerDeepPassRoutes } from "../routes/deepPass.js";
import { registerIncidentTypeRoutes } from "../routes/incidentTypes.js";
import { registerCollectionPlanRoutes } from "../routes/collectionPlan.js";
import { registerHostScopeRoutes } from "../routes/hostScope.js";
import { registerHostDuplicateRoutes } from "../routes/hostDuplicates.js";
import { registerAiStateRoutes } from "../routes/aiState.js";
import { registerClockSkewRoutes } from "../routes/clockSkew.js";
import {
  registerSlashCommandRoutes,
  startTelegramPolling,
  startSlackSocketMode,
} from "../routes/slashCommand.js";
import { registerComplianceRoutes } from "../routes/compliance.js";
import { registerCoachRoutes } from "../routes/coach.js";
import { registerCockpitRoutes } from "../routes/cockpit.js";

/**
 * Handles for the opt-in outbound command transports (#235). Returned rather than written onto
 * `app.locals` here, because they are not routes and the host is what owns shutdown.
 */
export interface OutboundTransports {
  telegramPoller?: ReturnType<typeof startTelegramPolling>;
  slackSocketMode?: ReturnType<typeof startSlackSocketMode>;
}

export function registerAllRoutes(app: Express, ctx: RouteContext): OutboundTransports {
  const { store, options } = ctx;
  const transports: OutboundTransports = {};
  registerSystemRoutes(app, ctx);
  // The basemap under the Geographic Map panel, proxied so the dashboard keeps `img-src 'self'`
  // (see routes/geoTiles.ts). Mounted with the other unauthenticated-cost reads and BEFORE
  // mountAiRateLimit: one map view fetches dozens of tiles, and a limiter sized for AI routes
  // would blank the map it is meant to protect.
  registerGeoTileRoutes(app, ctx);
  registerAiModelRoutes(app, ctx);
  registerCaptureRoutes(app, ctx);
  registerPushNotifyRoutes(app, ctx);
  registerTemplatesViewsRoutes(app, ctx);
  registerToolsRoutes(app, ctx);
  registerMcpRoutes(app, ctx);

  // Rate-limit the AI-cost-bearing case routes so an attacker who knows a caseId cannot burn the
  // operator's AI budget. Mounted HERE — after the route families that need no limit, before
  // registerImportRoutes — because the gate only covers layers registered after it, and
  // tests/architecture/routeInventory.test.ts records that interleaving. See composition/aiRateLimit.ts.
  mountAiRateLimit(app);

  // Freeze the MANUAL evidence routes on a closed or archived case, the way every automated
  // ingest path already freezes itself. Same placement reasoning as the gate above — it only
  // covers what follows it, and both routes it guards are registered below. See
  // composition/caseWriteGuard.ts.
  mountCaseWriteGuard(app, store);

  registerImportRoutes(app, ctx);
  // The third case gate, and the narrowest: /cases/:id/velociraptor/* additionally requires a case
  // that EXISTS. The two mounted in httpStack.ts do not — caseIdGate validates the SHAPE of :id and
  // caseLockGate lets a case with no meta through — and routes/velociraptor.ts checked caseExists in
  // no handler at all, so run-bundle LAUNCHED A HUNT ON LIVE ENDPOINTS for a case id that was merely
  // sitting in the dashboard's picker. See analysis/caseExistsGate.ts for the full account.
  //
  // Placement, for the same reason as the two gates above: it covers only what follows it, so it sits
  // directly above the routes it guards — and BELOW mountAiRateLimit, whose coverage contract is that
  // the limiter answers first even for a case that does not exist.
  app.use("/cases/:id/velociraptor", createCaseExistsGate(store));
  registerVelociraptorRoutes(app, ctx);
  registerThreatIntelRoutes(app, ctx);
  registerEnrichmentTestRoutes(app, ctx);
  registerAnonymizationRoutes(app, ctx);
  registerTimelineRoutes(app, ctx);
  registerAnalysisGraphRoutes(app, ctx);
  registerSessionSegmentationRoutes(app, ctx);
  registerFindingsRoutes(app, ctx);
  registerTaggerRoutes(app, ctx);
  // Auto-record chain of custody for every artifact the companion stores (#231). Hooked onto the
  // store rather than onto the ~25 saveImport call sites, so no import route — including ones added
  // later — can quietly land evidence without a custody entry. POST /cases/:id/custody remains for
  // evidence the companion never wrote itself (mounted images, external tool output).
  if (options.custodyStore) {
    const custody = options.custodyStore;
    store.onArtifactStored(async (artifact) => {
      await custody.record(artifact.caseId, {
        artifactPath: artifact.path,
        sha256: artifact.sha256,
        // Only the capture path knows its collector and origin URL; an import is attributed to the
        // companion itself, with the analyst's action already in the activity log.
        collectedBy: artifact.provenance?.collectedBy ?? "companion",
        collectedAt: new Date().toISOString(),
        source: artifact.provenance?.source ?? "",
        trigger: artifact.provenance?.trigger ?? artifact.kind,
        caseId: artifact.caseId,
      });
    });
  }
  registerCustodyRoutes(app, ctx);
  registerPlaybookHuntsRoutes(app, ctx);
  registerPlaybookMatchRoutes(app, ctx);
  registerAiSynthesisRoutes(app, ctx);
  registerFindingsDisplayRoutes(app, ctx);
  registerDeepPassRoutes(app, ctx);
  // MUST precede registerReportsExportRoutes: that file's `GET /cases/:id/report/:file` matches
  // `/report/interactive` too, and answers unknown names with 400 rather than calling next(), so
  // registering the interactive report after it makes the route permanently unreachable.
  registerInteractiveReportRoutes(app, ctx);
  registerReportsExportRoutes(app, ctx);
  registerReportVersionsRoutes(app, ctx);
  registerAnalysisRunRoutes(app, ctx);
  registerCasePasswordRoutes(app, ctx);
  registerCaseLifecycleRoutes(app, ctx);
  registerJobRoutes(app, ctx);
  registerIncidentTypeRoutes(app, ctx);
  registerCollectionPlanRoutes(app, ctx);
  registerHostScopeRoutes(app, ctx);
  registerHostDuplicateRoutes(app, ctx);
  registerAiStateRoutes(app, ctx);
  registerClockSkewRoutes(app, ctx);
  registerCoachRoutes(app, ctx);
  registerCockpitRoutes(app, ctx);
  registerComplianceRoutes(app, ctx);
  registerSlashCommandRoutes(app, ctx);
  // Outbound command transports (#235) are opt-in. Started here, after the slash-command routes they
  // serve, but handed back so the caller can park them on app.locals for shutdown.
  if (options.telegramPolling) transports.telegramPoller = startTelegramPolling(ctx);
  if (options.slackSocketMode) transports.slackSocketMode = startSlackSocketMode(ctx);
  return transports;
}
