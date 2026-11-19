// AI Agent Forensics (#2690): the panel's HTTP surface. Thin — the lifecycle is in
// composition/aiAgentForensics.ts. The run record is served WITHOUT its raw rows (they carry the
// unredacted matched text, which only "Add to case" files back through the evidence-first ingest).
//
//   GET  /ai-agent/rules                                 rule version, scopes, rules not run, problem
//   GET  /ai-agent/sweeps                                the hidden sweep cases and their runs
//   POST /ai-agent/runs                                  start a run (body.caseId → in that case; none → sweep)
//   GET  /cases/:id/ai-agent/runs                        the case's (or sweep's) runs
//   POST /cases/:id/ai-agent/runs/:runId/refresh         read results back, rebuild the report
//   POST /cases/:id/ai-agent/runs/:runId/add-to-case     file a sweep into body.targetCaseId
//   GET  /cases/:id/ai-agent/runs/:runId/report.md|.csv  the run report, escaped

import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { isValidCaseId } from "../storage/caseStore.js";
import { activeAiAgentRuleSet, activeAiAgentRulesProblem } from "../analysis/aiAgentActiveRules.js";
import { groupNotRun } from "../analysis/aiAgentReport.js";
import { AiAgentRunStore, type AiAgentRun } from "../analysis/aiAgentRunStore.js";
import {
  AiAgentRunError,
  addSweepToCase,
  listSweeps,
  refreshAiAgentRun,
  startAiAgentRun,
  type AiAgentForensicsDeps,
} from "../composition/aiAgentForensics.js";
import { AiAgentArtifactError } from "../integrations/velociraptor/aiAgentArtifact.js";
import { AiAgentLaunchError } from "../integrations/velociraptor/aiAgentLaunch.js";
import { aiAgentReportCsv, aiAgentReportMarkdown } from "../reports/aiAgentReportExport.js";

/** The run as the dashboard sees it: no raw rows. */
export function publicRun(run: AiAgentRun): Omit<AiAgentRun, "rows"> & { rowCount: number } {
  const { rows, ...rest } = run;
  return { ...rest, rowCount: rows?.length ?? 0 };
}

function fail(res: Response, err: unknown): Response {
  const e = err as Error;
  if (err instanceof AiAgentRunError) return res.status(err.status).json({ error: e.message });
  if (err instanceof AiAgentArtifactError || err instanceof AiAgentLaunchError)
    return res.status(400).json({ error: e.message });
  return res.status(502).json({ error: e.message });
}

function deps(ctx: RouteContext, runStore: AiAgentRunStore): AiAgentForensicsDeps | null {
  const { options } = ctx;
  if (!options.veloHuntStore) return null;
  const log = (line: string): void => ctx.serverLogger.info(line);
  return {
    store: ctx.store,
    serverClients: ctx.serverClients,
    serverSetStore: options.serverSetStore,
    veloHuntStore: options.veloHuntStore,
    runStore,
    disableAi: (caseId) => ctx.setControl(caseId, { enabled: false }),
    startVeloHuntCollect: (caseId, huntId) => ctx.startVeloHuntCollect(caseId, huntId),
    armCollectTimer: (caseId, huntId, waitMinutes) => {
      const timer = setTimeout(() => ctx.startVeloHuntCollect(caseId, huntId), waitMinutes * 60_000);
      timer.unref?.();
      ctx.veloHuntTimers().set(caseId, timer, huntId);
    },
    scheduleVeloHuntStatusPoll: (caseId, huntId) => ctx.scheduleVeloHuntStatusPoll(caseId, huntId),
    cancelVeloHuntTimersForCase: (caseId) => ctx.cancelVeloHuntTimersForCase(caseId),
    ingestVeloArtifactMap: (caseId, json, o) => ctx.ingestVeloArtifactMap(caseId, json, o),
    onChange: (caseId) => options.onVeloHunt?.(caseId),
    log,
  };
}

const NOT_WIRED = { error: "Velociraptor hunts are not configured on this server" };

export function registerAiAgentForensicsRoutes(app: Express, ctx: RouteContext): void {
  const runStore = new AiAgentRunStore(ctx.store);

  app.get("/ai-agent/rules", (_req: Request, res: Response) => {
    try {
      const set = activeAiAgentRuleSet();
      return res.status(200).json({
        version: set.version,
        upstreamCommit: set.upstreamCommit,
        scopes: set.scopes.map((s) => ({ id: s.id, label: s.label, default: s.default })),
        notRun: groupNotRun(set.notRun),
        provisionalGrades: true,
        problem: activeAiAgentRulesProblem(),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/ai-agent/sweeps", async (_req: Request, res: Response) => {
    const d = deps(ctx, runStore);
    if (!d) return res.status(501).json(NOT_WIRED);
    try {
      const sweeps = await listSweeps(d);
      return res.status(200).json({
        sweeps: sweeps.map((s) => ({ caseId: s.caseId, run: s.run ? publicRun(s.run) : null })),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/ai-agent/runs", async (req: Request, res: Response) => {
    const d = deps(ctx, runStore);
    if (!d) return res.status(501).json(NOT_WIRED);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const caseId = typeof body.caseId === "string" && body.caseId.trim() ? body.caseId.trim() : undefined;
    if (caseId && !isValidCaseId(caseId))
      return res.status(400).json({ error: "caseId must be a valid case id" });
    const visible = ctx.options.teamAuth?.visibleCaseIds(req);
    if (caseId && visible && !visible.has(caseId)) return res.status(404).json({ error: "case not found" });
    try {
      const out = await startAiAgentRun(d, {
        caseId,
        serverSetId: typeof body.serverSetId === "string" ? body.serverSetId : undefined,
        clientIds: Array.isArray(body.clientIds) ? body.clientIds.map(String) : [],
        scopes: Array.isArray(body.scopes) ? body.scopes.map(String) : undefined,
        uploadMaxBytes: Number.isFinite(Number(body.uploadMaxBytes))
          ? Number(body.uploadMaxBytes)
          : undefined,
        waitMinutes: Number.isFinite(Number(body.waitMinutes)) ? Number(body.waitMinutes) : undefined,
      });
      return res.status(202).json({ caseId: out.caseId, sweep: out.sweep, run: publicRun(out.run) });
    } catch (err) {
      ctx.serverLogger.info(`[ai-agent] run ERROR: ${(err as Error).message}`);
      return fail(res, err);
    }
  });

  app.get("/cases/:id/ai-agent/runs", async (req: Request, res: Response) => {
    try {
      const runs = await runStore.list(req.params.id);
      return res.status(200).json({ runs: runs.map(publicRun) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/ai-agent/runs/:runId/refresh", async (req: Request, res: Response) => {
    const d = deps(ctx, runStore);
    if (!d) return res.status(501).json(NOT_WIRED);
    try {
      return res
        .status(200)
        .json({ run: publicRun(await refreshAiAgentRun(d, req.params.id, req.params.runId)) });
    } catch (err) {
      return fail(res, err);
    }
  });

  app.post("/cases/:id/ai-agent/runs/:runId/add-to-case", async (req: Request, res: Response) => {
    const d = deps(ctx, runStore);
    if (!d) return res.status(501).json(NOT_WIRED);
    if (!ctx.options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const target = String(req.body?.targetCaseId ?? "").trim();
    if (!isValidCaseId(target))
      return res.status(400).json({ error: "targetCaseId must be a valid case id" });
    const visible = ctx.options.teamAuth?.visibleCaseIds(req);
    if (visible && !visible.has(target)) return res.status(404).json({ error: "case not found" });
    try {
      return res.status(200).json(await addSweepToCase(d, req.params.id, req.params.runId, target));
    } catch (err) {
      return fail(res, err);
    }
  });

  app.get("/cases/:id/ai-agent/runs/:runId/report.:fmt", async (req: Request, res: Response) => {
    const fmt = req.params.fmt;
    if (fmt !== "md" && fmt !== "csv") return res.status(404).json({ error: "report format: md or csv" });
    try {
      const run = await runStore.get(req.params.id, req.params.runId);
      if (!run) return res.status(404).json({ error: "run not found" });
      const name = `ai-agent-forensics-${run.huntId}.${fmt}`;
      res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
      return fmt === "md"
        ? res.type("text/markdown; charset=utf-8").send(aiAgentReportMarkdown(run))
        : res.type("text/csv; charset=utf-8").send(aiAgentReportCsv(run));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
