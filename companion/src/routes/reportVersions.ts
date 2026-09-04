import type { Express, Request, Response } from "express";
import { z } from "zod";
import { logActivity } from "../analysis/activityLog.js";
import { attachmentContentDisposition } from "../analysis/caseExportArchive.js";
import { diffFindings } from "../analysis/findingsDiff.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import { diffTimeline } from "../analysis/timelineDiff.js";
import { requestAuthentication } from "../auth/types.js";
import { REPORT_PACK_TYPES } from "../reports/reportReleaseStore.js";
import {
  reportActorSchema,
  reportAnnotationInputSchema,
  type ReportActor,
} from "../reports/reportWorkflowTypes.js";
import type { RouteContext } from "./context.js";

const noteSchema = z.object({ note: z.string().trim().min(1).max(4_000) });
const reasonSchema = z.object({ reason: z.string().trim().min(1).max(4_000) });
const resolveSchema = z.object({ resolution: z.string().trim().min(1).max(4_000) });
const submitSchema = z.object({ reviewerId: z.string().trim().min(1).max(200) });
const releaseSchema = z.object({
  supersedesReleaseId: z.string().trim().min(1).max(200).optional(),
});

function requestActor(req: Request, ctx: RouteContext): ReportActor | null {
  if (!ctx.options.teamAuth) {
    return { id: "solo", displayName: "Solo investigator", kind: "solo" };
  }
  const auth = requestAuthentication(req);
  if (auth?.kind !== "session" || auth.identity.kind === "service") return null;
  return reportActorSchema.parse({
    id: auth.identity.id,
    displayName: auth.identity.displayName,
    kind: auth.identity.kind,
  });
}

function workflowError(res: Response, err: unknown): Response {
  if (err instanceof z.ZodError) return res.status(400).json({ error: "invalid request body" });
  const message = err instanceof Error ? err.message : "report workflow failed";
  if (message.includes("not found")) return res.status(404).json({ error: message });
  if (
    message.includes("current status") ||
    message.includes("blocked") ||
    message.includes("already") ||
    message.includes("supersede")
  ) {
    return res.status(409).json({ error: message });
  }
  return res.status(400).json({ error: message });
}

function auditWorkflow(
  req: Request,
  ctx: RouteContext,
  caseId: string,
  action: string,
  targetId: string,
  detail: string,
): void {
  const auth = requestAuthentication(req);
  if (auth?.kind === "session") {
    ctx.options.teamAuth?.store.addAudit(auth.identity, action, targetId, caseId, detail);
  }
  void logActivity(ctx.options.activityLogStore, ctx.options.onActivity, caseId, {
    category: action === "report-released" ? "export" : "collaboration",
    action,
    detail,
    targetType: "report-version",
    targetId,
  });
}

function reviewerActor(ctx: RouteContext, caseId: string, reviewerId: string): ReportActor | null {
  const auth = ctx.options.teamAuth;
  if (!auth) return null;
  const identity = auth.store.getIdentity(reviewerId);
  if (!identity || identity.disabled || identity.kind === "service") return null;
  const role = auth.store.getCaseRole(identity.id, caseId);
  if (identity.globalRole !== "administrator" && role !== "reviewer" && role !== "administrator") {
    return null;
  }
  return { id: identity.id, displayName: identity.displayName, kind: identity.kind };
}

/**
 * Report versioning (#77): list the version snapshots a case has accumulated (one per report
 * regeneration, deduped when nothing changed — see ReportVersionStore.snapshot), diff two of them
 * (added/removed findings + severity changes, IOC changes, timeline changes — reusing the same
 * *Diff.ts primitives the import pipeline uses), and restore an earlier version's editable
 * report-meta (title page, distribution, BIA, glossary, recommendations…) as the CURRENT report-meta,
 * so the next "Generate Report" click renders with it. Restoring does not touch findings/IOCs/timeline
 * (those come from the live investigation state, not the archived version) and does not regenerate the
 * report itself — the analyst reviews the restored fields, then regenerates from the dashboard as usual.
 */
export function registerReportVersionsRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/report-versions", async (req: Request, res: Response) => {
    if (!options.reportVersionStore)
      return res.status(501).json({ error: "report versioning not configured" });
    try {
      const versions = await options.reportVersionStore.list(req.params.id);
      const withWorkflow = await Promise.all(
        versions.map(async (version) => ({
          ...version,
          workflow: await options.reportVersionStore!.workflow(req.params.id, version.id),
        })),
      );
      return res.status(200).json(withWorkflow);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Diff two stored versions' findings/IOCs/forensic-timeline. `from`/`to` are version ids from the
  // list above; `to` defaults to the most recent version when omitted.
  app.get("/cases/:id/report-versions/diff", async (req: Request, res: Response) => {
    if (!options.reportVersionStore)
      return res.status(501).json({ error: "report versioning not configured" });
    const caseId = req.params.id;
    const fromId = typeof req.query.from === "string" ? req.query.from : "";
    let toId = typeof req.query.to === "string" ? req.query.to : "";
    if (!fromId) return res.status(400).json({ error: "from is required" });
    try {
      if (!toId) {
        const versions = await options.reportVersionStore.list(caseId);
        toId = versions[0]?.id ?? "";
      }
      const [from, to] = await Promise.all([
        options.reportVersionStore.get(caseId, fromId),
        toId ? options.reportVersionStore.get(caseId, toId) : Promise.resolve(null),
      ]);
      if (!from || !to) return res.status(404).json({ error: "version not found" });
      return res.status(200).json({
        from: { id: from.id, createdAt: from.createdAt, version: from.version },
        to: { id: to.id, createdAt: to.createdAt, version: to.version },
        findings: diffFindings(from.state.findings, to.state.findings),
        iocs: diffIocs(from.state.iocs, to.state.iocs),
        timeline: diffTimeline(from.state.forensicTimeline, to.state.forensicTimeline),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Restore a prior version's editable report-meta as the case's CURRENT report-meta. Returns the
  // saved (normalized) meta so the dashboard's report-meta form can refresh in place.
  app.post("/cases/:id/report-versions/:versionId/restore", async (req: Request, res: Response) => {
    if (!options.reportVersionStore)
      return res.status(501).json({ error: "report versioning not configured" });
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    const caseId = req.params.id;
    try {
      const version = await options.reportVersionStore.get(caseId, req.params.versionId);
      if (!version) return res.status(404).json({ error: "version not found" });
      const saved = await options.reportMetaStore.save(caseId, version.meta);
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/report-reviewers", (req: Request, res: Response) => {
    if (!options.teamAuth) return res.status(200).json({ mode: "solo", reviewers: [] });
    const reviewers = options.teamAuth.store
      .listCaseRoles(req.params.id)
      .filter((entry) => entry.role === "reviewer" || entry.role === "administrator")
      .filter((entry) => !entry.identity.disabled && entry.identity.kind !== "service")
      .map((entry) => ({
        id: entry.identity.id,
        displayName: entry.identity.displayName,
        kind: entry.identity.kind,
        role: entry.role,
      }));
    return res.status(200).json({ mode: "team", reviewers });
  });

  app.get("/cases/:id/report-versions/:versionId/workflow", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    try {
      const workflow = await options.reportVersionStore.workflow(req.params.id, req.params.versionId);
      if (!workflow) return res.status(404).json({ error: "report version not found" });
      return res.status(200).json({
        ...workflow,
        reviewMode: options.teamAuth ? "team" : "solo",
      });
    } catch (err) {
      return workflowError(res, err);
    }
  });

  app.post("/cases/:id/report-versions/:versionId/workflow/submit", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    if (!options.teamAuth) {
      return res.status(409).json({ error: "peer review requires team authentication" });
    }
    const actor = requestActor(req, ctx);
    if (!actor) return res.status(403).json({ error: "a signed-in person must submit the report" });
    try {
      const { reviewerId } = submitSchema.parse(req.body as unknown);
      const reviewer = reviewerActor(ctx, req.params.id, reviewerId);
      if (!reviewer) {
        return res.status(400).json({ error: "reviewer is not an eligible case reviewer" });
      }
      const workflow = await options.reportVersionStore.submitForReview(
        req.params.id,
        req.params.versionId,
        actor,
        reviewer,
      );
      auditWorkflow(
        req,
        ctx,
        req.params.id,
        "report-submitted-for-review",
        req.params.versionId,
        `assigned ${reviewer.displayName}`,
      );
      return res.status(200).json(workflow);
    } catch (err) {
      return workflowError(res, err);
    }
  });

  app.post(
    "/cases/:id/report-versions/:versionId/review/annotations",
    async (req: Request, res: Response) => {
      if (!options.reportVersionStore) {
        return res.status(501).json({ error: "report versioning not configured" });
      }
      const actor = requestActor(req, ctx);
      if (!actor) return res.status(403).json({ error: "a signed-in reviewer is required" });
      try {
        const input = reportAnnotationInputSchema.parse(req.body as unknown);
        const workflow = await options.reportVersionStore.addReviewAnnotation(
          req.params.id,
          req.params.versionId,
          actor,
          input,
        );
        auditWorkflow(
          req,
          ctx,
          req.params.id,
          "report-review-annotation-added",
          req.params.versionId,
          `${input.targetType}:${input.targetId}`,
        );
        return res.status(201).json(workflow);
      } catch (err) {
        return workflowError(res, err);
      }
    },
  );

  app.post(
    "/cases/:id/report-versions/:versionId/workflow/annotations/:annotationId/resolve",
    async (req: Request, res: Response) => {
      if (!options.reportVersionStore) {
        return res.status(501).json({ error: "report versioning not configured" });
      }
      const actor = requestActor(req, ctx);
      if (!actor) return res.status(403).json({ error: "a signed-in investigator is required" });
      try {
        const { resolution } = resolveSchema.parse(req.body as unknown);
        const workflow = await options.reportVersionStore.resolveReviewAnnotation(
          req.params.id,
          req.params.versionId,
          req.params.annotationId,
          actor,
          resolution,
        );
        auditWorkflow(
          req,
          ctx,
          req.params.id,
          "report-review-annotation-resolved",
          req.params.versionId,
          req.params.annotationId,
        );
        return res.status(200).json(workflow);
      } catch (err) {
        return workflowError(res, err);
      }
    },
  );

  app.post(
    "/cases/:id/report-versions/:versionId/review/request-changes",
    async (req: Request, res: Response) => {
      if (!options.reportVersionStore) {
        return res.status(501).json({ error: "report versioning not configured" });
      }
      const actor = requestActor(req, ctx);
      if (!actor) return res.status(403).json({ error: "a signed-in reviewer is required" });
      try {
        const { reason } = reasonSchema.parse(req.body as unknown);
        const workflow = await options.reportVersionStore.requestReportChanges(
          req.params.id,
          req.params.versionId,
          actor,
          reason,
        );
        auditWorkflow(req, ctx, req.params.id, "report-changes-requested", req.params.versionId, reason);
        return res.status(200).json(workflow);
      } catch (err) {
        return workflowError(res, err);
      }
    },
  );

  app.post("/cases/:id/report-versions/:versionId/review/approve", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    const actor = requestActor(req, ctx);
    if (!actor) return res.status(403).json({ error: "a signed-in reviewer is required" });
    try {
      const { note } = noteSchema.parse(req.body as unknown);
      const workflow = await options.reportVersionStore.approve(
        req.params.id,
        req.params.versionId,
        actor,
        note,
      );
      auditWorkflow(req, ctx, req.params.id, "report-approved", req.params.versionId, note);
      return res.status(200).json(workflow);
    } catch (err) {
      return workflowError(res, err);
    }
  });

  app.post(
    "/cases/:id/report-versions/:versionId/workflow/self-approve",
    async (req: Request, res: Response) => {
      if (!options.reportVersionStore) {
        return res.status(501).json({ error: "report versioning not configured" });
      }
      if (options.teamAuth) {
        return res.status(409).json({ error: "team mode requires independent peer review" });
      }
      const actor = requestActor(req, ctx)!;
      try {
        const { note } = noteSchema.parse(req.body as unknown);
        const workflow = await options.reportVersionStore.selfApprove(
          req.params.id,
          req.params.versionId,
          actor,
          note,
        );
        auditWorkflow(req, ctx, req.params.id, "report-self-reviewed", req.params.versionId, note);
        return res.status(200).json(workflow);
      } catch (err) {
        return workflowError(res, err);
      }
    },
  );

  app.post("/cases/:id/report-versions/:versionId/workflow/release", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    if (!options.analysisRunStore || !options.custodyStore) {
      return res.status(501).json({ error: "release integrity services are not configured" });
    }
    const actor = requestActor(req, ctx);
    if (!actor) return res.status(403).json({ error: "a signed-in investigator is required" });
    try {
      const body = releaseSchema.parse(req.body as unknown);
      const version = await options.reportVersionStore.get(req.params.id, req.params.versionId);
      if (!version) return res.status(404).json({ error: "report version not found" });
      const runIds = version.analysisRunIds ?? [];
      const runs = (
        await Promise.all(runIds.map((id) => options.analysisRunStore!.get(req.params.id, id)))
      ).filter((run): run is NonNullable<typeof run> => run !== null);
      const [analysisIntegrity, head, chainBreaks, mismatches] = await Promise.all([
        options.analysisRunStore.verify(req.params.id),
        options.custodyStore.chainHead(req.params.id),
        options.custodyStore.verifyChain(req.params.id),
        options.custodyStore.verifyIntegrity(req.params.id),
      ]);
      const release = await options.reportVersionStore.release(req.params.id, req.params.versionId, {
        actor,
        ...body,
        analysisRuns: runs,
        analysisIntegrity,
        custody: { head, chainBreaks, mismatches },
      });
      auditWorkflow(
        req,
        ctx,
        req.params.id,
        "report-released",
        req.params.versionId,
        `${release.id} · ${release.manifestHash}`,
      );
      return res.status(201).json(release);
    } catch (err) {
      return workflowError(res, err);
    }
  });

  app.get("/cases/:id/report-releases", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    try {
      return res.status(200).json(await options.reportVersionStore.listReleases(req.params.id));
    } catch (err) {
      return workflowError(res, err);
    }
  });

  app.get("/cases/:id/report-releases/integrity", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    return res.status(200).json(await options.reportVersionStore.verifyReleases(req.params.id));
  });

  app.get("/cases/:id/report-releases/diff", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    const fromId = typeof req.query.from === "string" ? req.query.from : "";
    const toId = typeof req.query.to === "string" ? req.query.to : "";
    if (!fromId || !toId) return res.status(400).json({ error: "from and to are required" });
    try {
      const [from, to] = await Promise.all([
        options.reportVersionStore.getRelease(req.params.id, fromId),
        options.reportVersionStore.getRelease(req.params.id, toId),
      ]);
      if (!from || !to) return res.status(404).json({ error: "release not found" });
      return res.status(200).json({
        from: { id: from.id, releasedAt: from.releasedAt, version: from.reportVersion },
        to: { id: to.id, releasedAt: to.releasedAt, version: to.reportVersion },
        findings: diffFindings(from.snapshot.state.findings, to.snapshot.state.findings),
        iocs: diffIocs(from.snapshot.state.iocs, to.snapshot.state.iocs),
        timeline: diffTimeline(from.snapshot.state.forensicTimeline, to.snapshot.state.forensicTimeline),
      });
    } catch (err) {
      return workflowError(res, err);
    }
  });

  app.get("/cases/:id/report-releases/:releaseId", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    try {
      const release = await options.reportVersionStore.getRelease(req.params.id, req.params.releaseId);
      return release ? res.status(200).json(release) : res.status(404).json({ error: "release not found" });
    } catch (err) {
      return workflowError(res, err);
    }
  });

  app.get("/cases/:id/report-releases/:releaseId/packs/:pack", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) {
      return res.status(501).json({ error: "report versioning not configured" });
    }
    const pack = req.params.pack;
    if (!(REPORT_PACK_TYPES as readonly string[]).includes(pack)) {
      return res.status(400).json({ error: "unknown release pack" });
    }
    try {
      const release = await options.reportVersionStore.getRelease(req.params.id, req.params.releaseId);
      if (!release) return res.status(404).json({ error: "release not found" });
      const typedPack = pack as (typeof REPORT_PACK_TYPES)[number];
      const extension = typedPack === "ioc" ? "csv" : "md";
      res.type(typedPack === "ioc" ? "text/csv; charset=utf-8" : "text/markdown; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        attachmentContentDisposition(`${typedPack}-${release.id}.${extension}`),
      );
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(release.packs[typedPack]);
    } catch (err) {
      return workflowError(res, err);
    }
  });
}
