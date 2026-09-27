import type { Express, Request, Response } from "express";
import { resolveStoredTargets } from "../analysis/eventAliasLookup.js";
import type { RouteContext } from "./context.js";

// The two annotation LISTS the dashboard indexes by `(targetType, targetId)`: investigator comments and
// analyst tags (stars are `starred` tags). Moved here from routes/findings.ts, which has no line
// headroom, when #1715 made them resolve: correlation can fold the event an analyst marked into
// another, so each event target whose event is gone also carries `resolvedTargetId` — the event it
// lives on today. The stored record is unchanged; the dashboard shows the mark on both ids.
export function registerEntityAnnotationRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      const comments = await options.commentsStore.load(req.params.id);
      return res.status(200).json(await resolveStoredTargets(options.stateStore, req.params.id, comments));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    try {
      const tags = await options.tagsStore.load(req.params.id);
      return res.status(200).json(await resolveStoredTargets(options.stateStore, req.params.id, tags));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
