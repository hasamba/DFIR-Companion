import type { Express, Request, Response } from "express";
import { recommendNextActions, type CoachRecommendation } from "../analysis/coach.js";
import type { StateStore } from "../analysis/stateStore.js";
import { countEnrichableWork } from "../enrichment/enrichService.js";
import type { RouteContext } from "./context.js";

/**
 * Next-action coach routes (issue #271): a deterministic, AI-free endpoint that recommends the
 * highest-value next investigation action based on the current case state.
 */
export function registerCoachRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  // Load the case and rank it. Two of the signals can't be read off InvestigationState, and both are
  // taken from the subsystem that OWNS them so the card can't recommend something the app wouldn't
  // actually do:
  //   - pendingEnrichmentIocs — the enrichment engine's own candidate filter, over the providers
  //     ENABLED for this case. An IOC type no provider supports, or a case with enrichment off,
  //     therefore counts as zero work instead of pinning a no-op "Run enrichment" card at the top.
  //   - playbookTasks — where next-step progress lives. syncPlaybook is the same idempotent,
  //     write-only-when-changed derive the playbook routes use, so the count reflects what the
  //     analyst has actually worked through rather than what synthesis once proposed.
  async function rank(stateStore: StateStore, caseId: string): Promise<CoachRecommendation[]> {
    const state = await stateStore.load(caseId);
    const [providers, playbookTasks] = await Promise.all([
      ctx.enabledProvidersFor(caseId),
      ctx.syncPlaybook(caseId),
    ]);
    return recommendNextActions(state, {
      pendingEnrichmentIocs: countEnrichableWork(state.iocs, providers),
      playbookTasks,
    });
  }

  // Return a ranked list of next-action recommendations for the case. The dashboard sidebar shows
  // the first (highest priority) item and can expand to show the rest.
  app.get("/cases/:id/coach/next-actions", async (req: Request, res: Response) => {
    const stateStore = options.stateStore;
    if (!stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      // StateStore.load answers a missing case with emptyState, so without this the route would 200
      // with "Import evidence" for any id at all (every sibling read route 404s instead), and
      // syncPlaybook would go on to derive — and persist — a playbook under the nonexistent case.
      if (!(await store.caseExists(caseId))) {
        return res.status(404).json({ error: `case ${caseId} does not exist` });
      }
      const recommendations = await rank(stateStore, caseId);
      return res.status(200).json({ caseId, recommendations });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Lightweight alias returning only the top recommendation for the sidebar card.
  app.get("/cases/:id/coach/next-action", async (req: Request, res: Response) => {
    const stateStore = options.stateStore;
    if (!stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      if (!(await store.caseExists(caseId))) {
        return res.status(404).json({ error: `case ${caseId} does not exist` });
      }
      const recommendations = await rank(stateStore, caseId);
      const top = recommendations[0] ?? null;
      return res.status(200).json({ caseId, recommendation: top, total: recommendations.length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}

export type { CoachRecommendation };
