import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { validateServedLocation } from "../analysis/servedLocation.js";
import { servedExposure } from "../analysis/servedExposure.js";
import type { RouteContext } from "./context.js";

// Served locations and the served-exposure reading (#930 item 4). The analyst declares where a URL
// prefix is served from; the reading says, per resource under it, what the file rows and the
// access-log rows establish — stage by stage, never a transfer, never a disclosure without
// confirmed sensitivity. Nothing is fetched; no server is contacted.
export function registerServedExposureRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/served-locations", async (req: Request, res: Response) => {
    if (!options.servedLocationStore)
      return res.status(501).json({ error: "served locations not configured" });
    try {
      return res.status(200).json({ locations: await options.servedLocationStore.load(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/served-locations", async (req: Request, res: Response) => {
    if (!options.servedLocationStore)
      return res.status(501).json({ error: "served locations not configured" });
    if (!(await ctx.store.caseExists(req.params.id)))
      return res.status(404).json({ error: "case not found" });
    const v = validateServedLocation(req.body ?? {}, new Date().toISOString());
    if (!v.ok) return res.status(400).json({ error: v.error });
    try {
      const out = await options.servedLocationStore.declare(req.params.id, v.location);
      if (out === "full")
        return res
          .status(400)
          .json({ error: "this case already holds the maximum number of served locations" });
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage",
        action: "served-location-declared",
        actor: "",
        detail: `${v.location.host}: ${v.location.urlPrefix || "/"} ← ${v.location.localRoot}${v.location.public ? " (public)" : ""}`,
        targetType: "served-location",
        targetId: v.location.id,
      });
      return res.status(201).json({ location: out });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/served-locations/:lid", async (req: Request, res: Response) => {
    if (!options.servedLocationStore)
      return res.status(501).json({ error: "served locations not configured" });
    try {
      return (await options.servedLocationStore.remove(req.params.id, req.params.lid))
        ? res.status(204).end()
        : res.status(404).json({ error: "served location not found" });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/served-exposure", async (req: Request, res: Response) => {
    if (!options.servedLocationStore || !options.stateStore)
      return res.status(501).json({ error: "served exposure not configured" });
    try {
      const [locations, state] = await Promise.all([
        options.servedLocationStore.load(req.params.id),
        options.stateStore.load(req.params.id),
      ]);
      return res.status(200).json(servedExposure(state, locations));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
