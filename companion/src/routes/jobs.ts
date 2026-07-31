import type { Express, Request, Response } from "express";
import type { JobManager } from "../analysis/jobManager.js";
import type { TeamAuth } from "../auth/teamAuth.js";

export interface JobRouteOptions {
  jobManager?: JobManager;
  teamAuth?: TeamAuth;
}

function canRead(options: JobRouteOptions, req: Request, caseId: string): boolean {
  return !options.teamAuth || options.teamAuth.canReadCase(req, caseId);
}

export function registerJobRoutes(app: Express, options: JobRouteOptions): void {
  app.get("/api/jobs", (req: Request, res: Response) => {
    const caseId = typeof req.query.caseId === "string" ? req.query.caseId : undefined;
    const jobs = options.jobManager?.list(caseId) ?? [];
    return res.status(200).json({
      jobs: jobs.filter((job) => canRead(options, req, job.caseId)),
    });
  });

  app.get("/api/jobs/:id", (req: Request, res: Response) => {
    const job = options.jobManager?.get(req.params.id);
    if (!job || !canRead(options, req, job.caseId)) {
      return res.status(404).json({ error: `unknown job: ${req.params.id}` });
    }
    return res.status(200).json(job);
  });

  app.post("/api/jobs/:id/cancel", (req: Request, res: Response) => {
    if (!options.jobManager) return res.status(501).json({ error: "job manager not configured" });
    const job = options.jobManager.get(req.params.id);
    if (!job || !canRead(options, req, job.caseId)) {
      return res.status(404).json({ error: `unknown job: ${req.params.id}` });
    }
    if (options.teamAuth && !options.teamAuth.canWriteCase(req, job.caseId)) {
      return res.status(403).json({ error: "case role does not permit cancelling this job" });
    }
    const result = options.jobManager.cancel(req.params.id);
    if (result.ok) return res.status(200).json(result.job);
    if (result.reason === "terminal") return res.status(409).json({ error: "job already finished" });
    return res.status(422).json({ error: "this job cannot be cancelled" });
  });
}
