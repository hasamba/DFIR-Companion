import type { Express, Request, Response } from "express";
import { intelRetirementReview, recordRetirementDecision } from "../analysis/intelRetirement.js";
import type { RouteContext } from "./context.js";

// The intel retirement review (#933 item 19, second half — #1024): GET lists the findings whose
// intel corroboration rests only on assertions that are no longer actionable, with the assertions
// named and any decision on file; POST records the analyst's decision (`retire` / `keep`) and
// changes nothing else — no severity, no status, no deployed detection. Under the state lock, so
// a decision can never race a merge's read-modify-write.
export function registerIntelRetirementRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/intel-retirement", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      return res.status(200).json(intelRetirementReview(state));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/intel-retirement/:findingId", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const decision = req.body?.decision;
    if (decision !== "retire" && decision !== "keep")
      return res.status(400).json({ error: "decision must be 'retire' or 'keep'" });
    const findingId = String(req.params.findingId ?? "").trim();
    if (!findingId) return res.status(400).json({ error: "findingId is required" });
    const note = typeof req.body?.note === "string" ? req.body.note : undefined;
    const stateStore = options.stateStore;
    try {
      const next = await ctx.runStateExclusive(req.params.id, async () => {
        const state = await stateStore.load(req.params.id);
        if (!state.findings.some((f) => f.id === findingId)) return null;
        const updated = recordRetirementDecision(state, { findingId, decision, ...(note ? { note } : {}) });
        await stateStore.save({ ...updated, updatedAt: new Date().toISOString() });
        return updated;
      });
      if (!next) return res.status(404).json({ error: "finding not found in this case" });
      options.onState?.(next);
      return res.status(200).json(intelRetirementReview(next));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
