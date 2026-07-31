import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";

function canAccessGlobalJob(ctx: RouteContext, req: Request): boolean {
  const teamAuth = ctx.options.teamAuth;
  if (!teamAuth) return true;
  const auth = teamAuth.requireSession(req);
  return auth !== null && teamAuth.isGlobalAdministrator(auth);
}

function canRead(ctx: RouteContext, req: Request, caseId: string | null): boolean {
  if (caseId === null) return canAccessGlobalJob(ctx, req);
  return !ctx.options.teamAuth || ctx.options.teamAuth.canReadCase(req, caseId);
}

function canWrite(ctx: RouteContext, req: Request, caseId: string | null): boolean {
  if (caseId === null) return canAccessGlobalJob(ctx, req);
  return !ctx.options.teamAuth || ctx.options.teamAuth.canWriteCase(req, caseId);
}

async function listJobs(ctx: RouteContext, req: Request, res: Response): Promise<Response> {
  await ctx.options.jobManager?.ready();
  const caseId = typeof req.query.caseId === "string" ? req.query.caseId : undefined;
  const jobs = ctx.options.jobManager?.list(caseId) ?? [];
  return res.status(200).json({ jobs: jobs.filter((job) => canRead(ctx, req, job.caseId)) });
}

async function getJob(ctx: RouteContext, req: Request, res: Response): Promise<Response> {
  await ctx.options.jobManager?.ready();
  const job = ctx.options.jobManager?.get(req.params.id);
  if (!job || !canRead(ctx, req, job.caseId)) {
    return res.status(404).json({ error: `unknown job: ${req.params.id}` });
  }
  return res.status(200).json(job);
}

async function cancelJob(ctx: RouteContext, req: Request, res: Response): Promise<Response> {
  const manager = ctx.options.jobManager;
  if (!manager) return res.status(501).json({ error: "job manager not configured" });
  await manager.ready();
  const job = manager.get(req.params.id);
  if (!job || !canRead(ctx, req, job.caseId)) {
    return res.status(404).json({ error: `unknown job: ${req.params.id}` });
  }
  if (!canWrite(ctx, req, job.caseId)) {
    return res.status(403).json({ error: "case role does not permit cancelling this job" });
  }
  const result = await manager.cancel(req.params.id);
  if (result.ok) return res.status(200).json(result.job);
  if (result.reason === "unknown") return res.status(404).json({ error: `unknown job: ${req.params.id}` });
  if (result.reason === "terminal") return res.status(409).json({ error: "job already finished" });
  return res.status(422).json({ error: "this job cannot be cancelled" });
}

async function resumeJob(ctx: RouteContext, req: Request, res: Response): Promise<Response> {
  const manager = ctx.options.jobManager;
  if (!manager) return res.status(501).json({ error: "job manager not configured" });
  await manager.ready();
  const job = manager.get(req.params.id);
  if (!job || !canRead(ctx, req, job.caseId)) {
    return res.status(404).json({ error: `unknown job: ${req.params.id}` });
  }
  if (!canWrite(ctx, req, job.caseId)) {
    return res.status(403).json({ error: "case role does not permit resuming this job" });
  }
  const result = await manager.resume(req.params.id);
  if (result.ok) return res.status(202).json(result.job);
  if (result.reason === "unknown") return res.status(404).json({ error: `unknown job: ${req.params.id}` });
  if (result.reason === "not-interrupted") {
    return res.status(409).json({ error: "job is not interrupted or failed" });
  }
  const error =
    result.reason === "retry-exhausted"
      ? "job retry budget is exhausted"
      : "this job has no restart-safe resume handler";
  return res.status(422).json({ error });
}

export function registerJobRoutes(app: Express, ctx: RouteContext): void {
  app.get("/api/jobs", (req, res) => listJobs(ctx, req, res));
  app.get("/api/jobs/:id", (req, res) => getJob(ctx, req, res));
  app.post("/api/jobs/:id/cancel", (req, res) => cancelJob(ctx, req, res));
  app.post("/api/jobs/:id/resume", (req, res) => resumeJob(ctx, req, res));
}
