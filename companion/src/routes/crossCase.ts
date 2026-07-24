import type { Express, Request, Response } from "express";
import type { CrossCaseStore } from "../storage/crossCaseStore.js";
import type { RouteContext } from "./context.js";

/**
 * Cross-case knowledge base routes (issue #227): surface prior-case IOC/technique matches and KB
 * diagnostics so an analyst can see "seen in N prior cases" without searching manually.
 */
export function registerCrossCaseRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const crossCaseStore = options.crossCaseStore;
  if (!crossCaseStore) return;

  // Look up an IOC value across all cases.
  app.get("/crosscase/ioc", async (req: Request, res: Response) => {
    const value = typeof req.query.value === "string" ? req.query.value : "";
    if (!value) return res.status(400).json({ error: "value query param is required" });
    try {
      const entry = await crossCaseStore.lookupIoc(value);
      return res.status(200).json({ value, entry });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Look up a MITRE technique across all cases.
  app.get("/crosscase/technique", async (req: Request, res: Response) => {
    const technique = typeof req.query.id === "string" ? req.query.id : "";
    if (!technique) return res.status(400).json({ error: "id query param is required" });
    try {
      const entry = await crossCaseStore.lookupTechnique(technique);
      return res.status(200).json({ technique, entry });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // KB stats for the diagnostics panel.
  app.get("/crosscase/stats", async (_req: Request, res: Response) => {
    try {
      const stats = await crossCaseStore.stats();
      return res.status(200).json(stats);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Mark an IOC as benign in a given case (cross-case FP propagation).
  app.post("/crosscase/mark-benign", async (req: Request, res: Response) => {
    const caseId = typeof req.body?.caseId === "string" ? req.body.caseId : "";
    const value = typeof req.body?.value === "string" ? req.body.value : "";
    if (!caseId || !value) return res.status(400).json({ error: "caseId and value are required" });
    try {
      await crossCaseStore.markBenign(caseId, value);
      return res.status(200).json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}