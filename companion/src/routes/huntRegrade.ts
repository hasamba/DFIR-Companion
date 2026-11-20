import type { Express, Request, Response } from "express";
import { isHuntType } from "../analysis/incidentTypes.js";
import { regradeHuntCase } from "../analysis/huntRegrade.js";
import { logActivity } from "../analysis/activityLog.js";
import type { RouteContext } from "./context.js";

/**
 * POST /cases/:id/hunt/regrade (#2670) — "Re-grade with current baseline". Analyst-pressed and
 * audit-logged, like the Sigma re-grade (#2206): it re-reads this case's rows from the forensic
 * timeline AND the raw record (demoted rows included), re-pins the case to the client's current
 * baseline version and rewrites the grouped hunt entries. It feeds no AI. The answer says how many
 * host observations the raw record has already evicted. Earlier cases are only ever re-graded by
 * this explicit action, so a delivered report never changes silently.
 */
export function registerHuntRegradeRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.post("/cases/:id/hunt/regrade", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const deps = options.huntGradingDeps;
    const rows = options.stateStore;
    if (!deps || !rows || !options.incidentTypeStore)
      return res.status(501).json({ error: "hunt grading not configured" });
    try {
      if (!isHuntType(await options.incidentTypeStore.loadType(caseId)))
        return res.status(409).json({ error: "this case is not a threat hunt" });
      const result = await ctx.runStateExclusive(caseId, () =>
        regradeHuntCase(
          {
            ...deps,
            rows: { forensicTimelineBatches: (id) => rows.forensicTimelineBatches(id) },
            ...(options.superTimelineStore
              ? { raw: { eventBatches: (id: string) => options.superTimelineStore!.eventBatches(id) } }
              : {}),
          },
          caseId,
        ),
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "hunt",
        action: "hunt-regrade",
        detail:
          `Re-graded with baseline version ${result.baselineVersion ?? "(no client linked)"}: ${result.rowsRead} row(s) read, ` +
          `${result.changed} entry change(s), ${result.entries} hunt item(s); ${result.evicted} host observation(s) no longer in the raw record`,
      });
      if (result.changed) options.onStateChanged?.(caseId);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
