import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";

export function registerJobRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/api/jobs", async (req: Request, res: Response) => {
    await options.jobManager?.ready();
    const caseId = typeof req.query.caseId === "string" ? req.query.caseId : undefined;
    return res.status(200).json({ jobs: options.jobManager?.list(caseId) ?? [] });
  });

  app.get("/api/jobs/:id", async (req: Request, res: Response) => {
    await options.jobManager?.ready();
    const job = options.jobManager?.get(req.params.id);
    if (!job) {
      return res.status(404).json({ error: `unknown job: ${req.params.id}` });
    }
    return res.status(200).json(job);
  });

  app.post("/api/jobs/:id/cancel", async (req: Request, res: Response) => {
    if (!options.jobManager) {
      return res.status(501).json({ error: "job manager not configured" });
    }
    const result = await options.jobManager.cancel(req.params.id);
    if (result.ok) return res.status(200).json(result.job);
    if (result.reason === "unknown") {
      return res.status(404).json({ error: `unknown job: ${req.params.id}` });
    }
    if (result.reason === "terminal") {
      return res.status(409).json({ error: "job already finished" });
    }
    return res.status(422).json({ error: "this job cannot be cancelled" });
  });

  app.post("/api/jobs/:id/resume", async (req: Request, res: Response) => {
    if (!options.jobManager) {
      return res.status(501).json({ error: "job manager not configured" });
    }
    const result = await options.jobManager.resume(req.params.id);
    if (result.ok) return res.status(202).json(result.job);
    if (result.reason === "unknown") {
      return res.status(404).json({ error: `unknown job: ${req.params.id}` });
    }
    if (result.reason === "not-interrupted") {
      return res.status(409).json({ error: "job is not interrupted or failed" });
    }
    return res.status(422).json({
      error:
        result.reason === "retry-exhausted"
          ? "job retry budget is exhausted"
          : "this job has no restart-safe resume handler",
    });
  });
}
