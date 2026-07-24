import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { buildActionRegistry, allActions, searchActions } from "../analysis/commandPalette.js";

export function registerCommandPaletteRoutes(app: Express, _ctx: RouteContext): void {
  const registry = buildActionRegistry();

  app.get("/command-palette/actions", (_req: Request, res: Response) => {
    res.status(200).json({ actions: allActions(registry) });
  });

  app.get("/command-palette/search", (req: Request, res: Response) => {
    const q = typeof req.query.q === "string" ? req.query.q : "";
    const results = searchActions(q, allActions(registry));
    res.status(200).json({ query: q, results: results.map((r) => ({ id: r.action.id, label: r.action.label, category: r.action.category, score: r.score })) });
  });
}