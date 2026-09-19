import type { Express, Request, Response } from "express";
import { attributionGapLeads } from "../analysis/attributionGapLeads.js";
import { loadAdversaryGroupsDataset } from "../analysis/adversaryGroupsData.js";
import type { RouteContext } from "./context.js";

/**
 * Gap leads from the analyst's own attribution assertions (#1405):
 *   - GET /cases/:id/attribution-gap-leads
 * For every active assertion whose label matches a known ATT&CK group, the techniques that group is
 * documented to use that this case's graded evidence has not shown — read-time only, never stored,
 * never a source of attribution. Kept off /attribution-assertions so that audit-trail read stays as
 * it is. A dataset that fails to load yields no leads and says so, never a 500.
 */
export function registerAttributionGapLeadsRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  app.get("/cases/:id/attribution-gap-leads", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    if (!options.attributionAssertionStore)
      return res.status(501).json({ error: "attribution-assertion store not configured" });
    try {
      const caseId = req.params.id;
      const [state, assertions] = await Promise.all([
        options.stateStore.load(caseId),
        options.attributionAssertionStore.load(caseId),
      ]);
      let dataset: ReturnType<typeof loadAdversaryGroupsDataset> | null = null;
      try {
        dataset = loadAdversaryGroupsDataset();
      } catch {
        dataset = null;
      }
      if (!dataset || !dataset.groups.length)
        return res.status(200).json({ leads: [], unmatchedAssertions: 0, datasetUnavailable: true });
      const result = attributionGapLeads(state, assertions, dataset);
      return res.status(200).json({ ...result, attackVersion: dataset.attackVersion });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
