import type { Express, Request, Response } from "express";
import { detectClockSkew, alignTimestamps } from "../analysis/clockSkew.js";
import type { RouteContext } from "./context.js";

/**
 * Clock-skew domain (#228): detect per-host clock drift via anchor events and align the
 * cross-host timeline onto a common axis.
 *   - GET  /cases/:id/clock-skew        — detected skew per host (offset, anchors, confidence).
 *   - POST /cases/:id/clock-skew/align   — toggle alignment; when enabling, returns aligned events.
 */
export function registerClockSkewRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/clock-skew", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      const results = detectClockSkew(state.forensicTimeline);
      if (options.clockSkewStore) {
        const current = await options.clockSkewStore.load(req.params.id);
        await options.clockSkewStore.save(req.params.id, {
          alignEnabled: current.alignEnabled,
          results,
          updatedAt: new Date().toISOString(),
        });
      }
      return res.status(200).json({ results });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/clock-skew/align", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const enable = req.body?.enable !== false;
    try {
      const state = await options.stateStore.load(req.params.id);
      let results = options.clockSkewStore
        ? (await options.clockSkewStore.load(req.params.id)).results
        : [];
      if (results.length === 0) results = detectClockSkew(state.forensicTimeline);
      if (options.clockSkewStore) {
        await options.clockSkewStore.setAlign(req.params.id, enable);
      }
      const events = enable ? alignTimestamps(state.forensicTimeline, results) : state.forensicTimeline;
      return res.status(200).json({ alignEnabled: enable, results, events });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
