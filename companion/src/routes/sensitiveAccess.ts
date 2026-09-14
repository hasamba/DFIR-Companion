import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { validateSensitiveLocation } from "../analysis/sensitiveLocation.js";
import { sensitiveAccess } from "../analysis/sensitiveAccess.js";
import type { RouteContext } from "./context.js";

// Sensitive locations and the sensitive-access reading (#930 item 7). The analyst declares what
// matters; the reading says, per object under it, what the object-access rows establish —
// a read only on an evidenced file, an instance and a session as candidates, "suspicious" only
// from the candidate's own rows. Nothing is fetched; no host is contacted.
export function registerSensitiveAccessRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/sensitive-locations", async (req: Request, res: Response) => {
    if (!options.sensitiveLocationStore)
      return res.status(501).json({ error: "sensitive locations not configured" });
    try {
      return res.status(200).json({ locations: await options.sensitiveLocationStore.load(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/sensitive-locations", async (req: Request, res: Response) => {
    if (!options.sensitiveLocationStore)
      return res.status(501).json({ error: "sensitive locations not configured" });
    if (!(await ctx.store.caseExists(req.params.id)))
      return res.status(404).json({ error: "case not found" });
    const v = validateSensitiveLocation(req.body ?? {}, new Date().toISOString());
    if (!v.ok) return res.status(400).json({ error: v.error });
    try {
      const out = await options.sensitiveLocationStore.declare(req.params.id, v.location);
      if (out === "full")
        return res
          .status(400)
          .json({ error: "this case already holds the maximum number of sensitive locations" });
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage",
        action: "sensitive-location-declared",
        actor: "",
        detail: `${v.location.host || "any host"}: ${v.location.path} (${v.location.kind})`,
        targetType: "sensitive-location",
        targetId: v.location.id,
      });
      return res.status(201).json({ location: out });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/sensitive-locations/:lid", async (req: Request, res: Response) => {
    if (!options.sensitiveLocationStore)
      return res.status(501).json({ error: "sensitive locations not configured" });
    try {
      return (await options.sensitiveLocationStore.remove(req.params.id, req.params.lid))
        ? res.status(204).end()
        : res.status(404).json({ error: "sensitive location not found" });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/sensitive-access", async (req: Request, res: Response) => {
    if (!options.sensitiveLocationStore || !options.stateStore)
      return res.status(501).json({ error: "sensitive access not configured" });
    try {
      const [locations, state] = await Promise.all([
        options.sensitiveLocationStore.load(req.params.id),
        options.stateStore.load(req.params.id),
      ]);
      return res.status(200).json(sensitiveAccess(state, locations));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
