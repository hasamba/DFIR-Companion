import type { Express, Request, Response } from "express";
import { projectAlignment } from "../analysis/clockSkew.js";
import { techniqueNamesFor } from "../analysis/attackTechniqueNames.js";
import { withoutEventAliases } from "../analysis/eventAliases.js";
import { withoutRejectedEventTags, withoutRejectedTechniques } from "../analysis/rejectedTechniques.js";
import { withFindingTextTechniques } from "../analysis/findingTextTechniques.js";
import { searchForensicTimeline } from "../analysis/forensicSearch.js";
import { eventAliasSource } from "../analysis/eventAliasRead.js";
import { taggerTagsForRows } from "../analysis/taggerRowTags.js";
import type { RouteContext } from "./context.js";

/**
 * GET /cases/:id/state — the whole case as the dashboard reads it.
 *
 * Split out of routes/caseLifecycle.ts rather than added to it, for the same reason
 * routes/caseIdentity.ts was: that file is at its recorded size under scripts/check-file-size.mjs,
 * and one route that assembles a view over the stored case is a coherent seam rather than more
 * catch-all. It is registered from caseLifecycle at the position the route occupied, because
 * Express matches layers in registration order and tests/architecture/routeInventory.test.ts pins
 * that order as a contract.
 *
 * EVERYTHING THIS HANDLER ADDS IS A VIEW. state/state.json keeps the evidence exactly as imported;
 * the corrections and the reference data below are applied on the way out and never written back,
 * so an analyst who changes clock skew or a build that learns a new technique name sees the
 * difference on the next fetch with nothing to migrate and nothing to heal.
 */
export function registerCaseStateRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  app.get("/cases/:id/state", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const rawCursor = Number(req.query.timelineCursor);
      const rawLimit = Number(req.query.timelineLimit);
      // `q` full-text searches the WHOLE stored timeline (#928). The dashboard used to filter the
      // page it had fetched, which quietly meant "search the first 10,000 events" — on a bigger
      // case the analyst was shown no results for evidence that had never been sent to the browser.
      const search = typeof req.query.q === "string" && req.query.q.trim() ? req.query.q.trim() : undefined;
      const timelineQuery = {
        cursor: Number.isFinite(rawCursor) && rawCursor >= 0 ? Math.floor(rawCursor) : undefined,
        limit: Number.isFinite(rawLimit) && rawLimit >= 0 ? Math.min(10_000, Math.floor(rawLimit)) : 10_000,
      };
      const timeline = search
        ? await searchForensicTimeline(options.stateStore, req.params.id, search, timelineQuery)
        : await options.stateStore.queryForensicTimeline(req.params.id, timelineQuery);
      // The analyst's technique removals (#1742) are hidden from the state and its events alike —
      // after the techniques each finding's own text names are added (#1873), so a removal still wins.
      const state = withoutRejectedTechniques(
        withFindingTextTechniques(await options.stateStore.loadOverview(req.params.id)),
      );
      // Clock-skew alignment (#228) is a VIEW over the stored case, applied here on the way out: the
      // dashboard renders corrected times (each event keeping its recorded one in originalTimestamp)
      // while state/state.json keeps the evidence exactly as imported.
      const skew = options.clockSkewStore ? await options.clockSkewStore.load(req.params.id) : undefined;
      const forensicTimeline = withoutRejectedEventTags(
        projectAlignment(skew, timeline.entities),
        state.rejectedTechniques,
      );
      // The automatic tagger's labels for THIS page's rows (#2059) — the tag list no longer carries them.
      const eventTaggerTags = await taggerTagsForRows(
        options.tagsStore,
        eventAliasSource(options.stateStore),
        req.params.id,
        forensicTimeline.map((e) => e.id),
      );
      return res.status(200).json({
        ...withoutEventAliases(state), // #1715: lineage is server bookkeeping
        forensicTimeline,
        forensicTimelineTotal: timeline.total,
        // Set only when the match count gave up at its ceiling (#928) — the total is then a floor,
        // and the client must not print it as if it were the number of matches.
        ...(timeline.totalIsLowerBound ? { forensicTimelineTotalIsLowerBound: true } : {}),
        forensicTimelineNextCursor: timeline.nextCursor,
        eventTaggerTags,
        // ATT&CK names for every technique this payload mentions. The dashboard's MITRE
        // panel completes the stored table from the techniques the events carry, exactly as
        // analysis/eventTechniques.ts does server-side, and until now it had no way to name a row
        // it appended: the panel showed "T1490" where the report showed "Inhibit System Recovery".
        //
        // Derived from THIS response's two inputs, so the map covers every id the client can
        // append and nothing it cannot. Paginating the timeline narrows both together.
        techniqueNames: techniqueNamesFor(state.mitreTechniques, forensicTimeline),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
