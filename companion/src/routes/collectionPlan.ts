import type { Express, Request, Response } from "express";
import { buildCollectionPlan, getCollectionStep, type CollectionPlan } from "../analysis/collectionPlan.js";
import type { RouteContext } from "./context.js";

/**
 * Collection-plan domain (#347): the case's incident type expressed as an ordered evidence
 * checklist, each step derived from the evidence already in the case, with analyst overrides.
 *   - GET    /cases/:id/collection-plan           — the built plan (null with no incident type).
 *   - PUT    /cases/:id/collection-plan/:stepId   — assert collected / not-applicable.
 *   - DELETE /cases/:id/collection-plan/:stepId   — return the step to automatic.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
export function registerCollectionPlanRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // Build the response shared by all three routes: the chosen type id plus its plan. Recomputed
  // every time from the timeline — no derived state is ever persisted, so nothing can go stale.
  async function plan(caseId: string): Promise<{ typeId: string; plan: CollectionPlan | null }> {
    const type = options.incidentTypeStore ? await options.incidentTypeStore.loadType(caseId) : null;
    if (!type) return { typeId: "", plan: null };
    const state = await options.stateStore!.load(caseId);
    const overrides = options.collectionPlanStore ? await options.collectionPlanStore.load(caseId) : {};
    return { typeId: type.id, plan: buildCollectionPlan(type.recommendedImportOrder, state.forensicTimeline, overrides) };
  }

  function configured(res: Response): boolean {
    if (!options.collectionPlanStore || !options.stateStore) {
      res.status(501).json({ error: "collection-plan store not configured" });
      return false;
    }
    return true;
  }

  app.get("/cases/:id/collection-plan", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      return res.status(200).json(await plan(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/collection-plan/:stepId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const { stepId } = req.params;
    if (!getCollectionStep(stepId)) return res.status(404).json({ error: `unknown collection step "${stepId}"` });
    const state = req.body?.state;
    if (state !== "collected" && state !== "na") {
      return res.status(400).json({ error: 'state must be "collected" or "na"' });
    }
    const reason = typeof req.body?.reason === "string" ? req.body.reason.slice(0, 500) : "";
    try {
      await options.collectionPlanStore!.set(req.params.id, stepId, { state, reason });
      return res.status(200).json(await plan(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/collection-plan/:stepId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const { stepId } = req.params;
    if (!getCollectionStep(stepId)) return res.status(404).json({ error: `unknown collection step "${stepId}"` });
    try {
      await options.collectionPlanStore!.clear(req.params.id, stepId);
      return res.status(200).json(await plan(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
