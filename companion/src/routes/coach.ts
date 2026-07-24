import type { Express, Request, Response } from "express";
import { recommendNextActions, type CoachRecommendation } from "../analysis/coach.js";
import type { RouteContext } from "./context.js";

/**
 * Next-action coach routes (issue #271): a deterministic, AI-free endpoint that recommends the
 * highest-value next investigation action based on the current case state.
 */
export function registerCoachRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // Return a ranked list of next-action recommendations for the case. The dashboard sidebar shows
  // the first (highest priority) item and can expand to show the rest.
  app.get("/cases/:id/coach/next-actions", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const recommendations = recommendNextActions(state);
      return res.status(200).json({ caseId, recommendations });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Lightweight alias returning only the top recommendation for the sidebar card.
  app.get("/cases/:id/coach/next-action", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const recommendations = recommendNextActions(state);
      const top = recommendations[0] ?? null;
      return res.status(200).json({ caseId, recommendation: top, total: recommendations.length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}

export type { CoachRecommendation };
