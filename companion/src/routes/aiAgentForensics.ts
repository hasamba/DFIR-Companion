// AI Agent Forensics (#2690): the panel's HTTP surface. Thin — the lifecycle is in
// integrations/velociraptor/aiAgentRuns.ts. The run record is served WITHOUT its raw rows (they carry the
// unredacted matched text, which only "Add to case" files back through the evidence-first ingest).
//
//   GET  /ai-agent/rules                                 rule version, scopes, rules not run, problem
//   GET  /ai-agent/sweeps                                the hidden sweep cases and their runs
//   POST /ai-agent/runs                                  start a run (body.caseId → in that case; none → sweep,
//                                                        the instance administrator's in team mode — #2725)
//   GET  /cases/:id/ai-agent/endpoints                   the case set's endpoints, reduced fields (case WRITE)
//   POST /cases/:id/ai-agent/endpoints/refresh           re-read them from Velociraptor first (case WRITE)
//   GET  /cases/:id/ai-agent/runs                        the case's (or sweep's) runs
//   GET  /cases/:id/ai-agent/runs/:runId/status          the run's live progress in Velociraptor (#2898)
//   POST /cases/:id/ai-agent/runs/:runId/refresh         read results back, rebuild the report
//   POST /cases/:id/ai-agent/runs/:runId/add-to-case     file a sweep into body.targetCaseId
//   GET  /cases/:id/ai-agent/runs/:runId/report.md|.csv  the run report, escaped
//   GET  /cases/:id/ai-agent/runs/:runId/sigma-coverage.csv  the rule-by-endpoint Sigma table (#2722)

import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { isValidCaseId } from "../storage/caseStore.js";
import { frozenCaseRefusal } from "./importCaseGuard.js";
import { runInCaseScope } from "../storage/caseIncarnation.js";
import { logActivity } from "../analysis/activityLog.js";
import { activeAiAgentRuleSet, activeAiAgentRulesProblem } from "../analysis/aiAgentActiveRules.js";
import { groupNotRun } from "../analysis/aiAgentReport.js";
import { AiAgentRunStore, type AiAgentRun } from "../analysis/aiAgentRunStore.js";
import {
  AiAgentRunError,
  addSweepToCase,
  listSweeps,
  readAiAgentRunStatus,
  refreshAiAgentRun,
  startAiAgentRun,
  type AiAgentForensicsDeps,
} from "../integrations/velociraptor/aiAgentRuns.js";
import { AiAgentArtifactError } from "../integrations/velociraptor/aiAgentArtifact.js";
import { AiAgentLaunchError } from "../integrations/velociraptor/aiAgentLaunch.js";
import {
  aiAgentReportCsv,
  aiAgentReportMarkdown,
  aiAgentSigmaCoverageCsv,
} from "../reports/aiAgentReportExport.js";
import { requestAuthentication } from "../auth/types.js";
import type { VeloClientRecord } from "../integrations/velociraptor/clientInventory.js";

/** The run as the dashboard sees it: no raw rows. */
export function publicRun(run: AiAgentRun): Omit<AiAgentRun, "rows"> & { rowCount: number } {
  const { rows, ...rest } = run;
  return { ...rest, rowCount: run.rowCount ?? rows?.length ?? 0 };
}

function fail(res: Response, err: unknown): Response {
  const e = err as Error;
  if (err instanceof AiAgentRunError) return res.status(err.status).json({ error: e.message });
  if (err instanceof AiAgentArtifactError || err instanceof AiAgentLaunchError)
    return res.status(400).json({ error: e.message });
  return res.status(502).json({ error: e.message });
}

function deps(ctx: RouteContext, runStore: AiAgentRunStore, req?: Request): AiAgentForensicsDeps | null {
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
    onSweepCreated: (caseId) => {
      if (req) options.teamAuth?.grantCreator(req, caseId);
    },
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
    // Best-effort, in the named case's scope (#1866): a case deleted meanwhile gets no late entry.
    onActivity: (caseId, entry) => {
      void runInCaseScope(ctx.store.casesRoot, caseId, () =>
        logActivity(options.activityLogStore, options.onActivity, caseId, { category: "hunt", ...entry }),
      ).catch((e: Error) => log(`[ai-agent] activity log for ${caseId} failed: ${e.message}`));
    },
    log,
  };
}

/**
 * A case named in the BODY (not the path) gets the checks the /cases/:id gates give a path case: it
 * exists, the requester may see it AND write to it, it is not closed or archived, and it is unlocked. Sends the
 * refusal and returns false when one fails.
 */
async function writableBodyCase(
  ctx: RouteContext,
  req: Request,
  res: Response,
  caseId: string,
): Promise<boolean> {
  const meta = await ctx.store.getCaseMeta(caseId).catch(() => null);
  const visible = ctx.options.teamAuth?.visibleCaseIds(req);
  if (!meta || (visible && !visible.has(caseId))) {
    res.status(404).json({ error: "case not found" });
    return false;
  }
  if (ctx.options.teamAuth && !ctx.options.teamAuth.canWriteCase(req, caseId)) {
    res
      .status(403)
      .json({ error: "you need write access to this case to run or file AI Agent Forensics results in it" });
    return false;
  }
  const frozen = await frozenCaseRefusal(ctx.store, caseId);
  if (frozen) {
    res.status(423).json({ error: frozen });
    return false;
  }
  if (meta.password && !ctx.readUnlockState(req, caseId, meta.password.salt).unlocked) {
    res.status(401).json({ error: "locked", caseId }); // the case-lock gate's answer (#2798)
    return false;
  }
  return true;
}

const NOT_WIRED = { error: "Velociraptor hunts are not configured on this server" };

/** True for the instance administrator, and for the one operator in single-user mode. */
function isGlobalAdmin(ctx: RouteContext, req: Request): boolean {
  const teamAuth = ctx.options.teamAuth;
  if (!teamAuth) return true;
  const auth = requestAuthentication(req) ?? teamAuth.requireSession(req);
  return !!auth && teamAuth.isGlobalAdministrator(auth);
}

/** One endpoint as a case writer sees it (#2725): the reduced view, nothing else from the record. */
interface CaseEndpoint {
  clientId: string;
  hostname: string;
  fqdn: string;
  lastSeen?: string;
  labels: string[];
}

function caseEndpoint(r: VeloClientRecord): CaseEndpoint {
  return {
    clientId: String(r.clientId),
    hostname: String(r.hostname ?? ""),
    fqdn: String(r.fqdn ?? ""),
    ...(r.lastSeen ? { lastSeen: String(r.lastSeen) } : {}),
    labels: Array.isArray(r.labels) ? r.labels.map(String) : [],
  };
}

/**
 * GET /cases/:id/ai-agent/endpoints (#2725): the endpoint picker inside a case. The case policy lets a
 * reader through on GET, so WRITE is checked here — the list is for the people who may launch a run in
 * the case. Only the case's own server set is read; an unresolved set or one without Velociraptor is an
 * empty list, never another set's inventory.
 */
async function caseEndpoints(ctx: RouteContext, req: Request, res: Response): Promise<Response> {
  const caseId = req.params.id;
  if (ctx.options.teamAuth && !ctx.options.teamAuth.canWriteCase(req, caseId))
    return res.status(403).json({ error: "you need write access to this case to list its endpoints" });
  const r = ctx.serverClients.forCase(caseId);
  if (!r.ok || !r.servers.velociraptor) return res.status(200).json({ updatedAt: "", clients: [] });
  const inventory = ctx.options.clientInventoryFor?.(r.servers.setId);
  if (!inventory) return res.status(200).json({ updatedAt: "", clients: [], setName: r.servers.setName });
  try {
    const inv = await inventory.load();
    return res.status(200).json({
      updatedAt: inv.updatedAt,
      setName: r.servers.setName,
      clients: (inv.clients ?? []).map(caseEndpoint),
      ...(inv.truncated ? { truncated: true } : {}), // the list was cut at the row limit (#2887)
    });
  } catch (err) {
    ctx.serverLogger.info(`[ai-agent] endpoint list ERROR: ${(err as Error).message}`);
    return res.status(500).json({ error: "could not read the endpoint list" });
  }
}

/**
 * POST /cases/:id/ai-agent/endpoints/refresh (#2898): the picker's Refresh. Re-reads the case set's
 * client list from Velociraptor into the shared inventory, then answers exactly as the GET does. Case
 * WRITE, like the list itself: the people who may launch a run may see who is online now. The global
 * Settings refresh (POST /velociraptor/clients/refresh) stays the administrator's.
 */
async function refreshCaseEndpoints(ctx: RouteContext, req: Request, res: Response): Promise<Response> {
  const caseId = req.params.id;
  if (ctx.options.teamAuth && !ctx.options.teamAuth.canWriteCase(req, caseId))
    return res.status(403).json({ error: "you need write access to this case to refresh its endpoints" });
  const r = ctx.serverClients.forCase(caseId);
  if (!r.ok || !r.servers.velociraptor)
    return res.status(409).json({ error: "this case's server set has no Velociraptor server" });
  try {
    await ctx.refreshVeloClients(r.servers.setId);
  } catch (err) {
    ctx.serverLogger.info(`[ai-agent] endpoint refresh ERROR: ${(err as Error).message}`);
    return res.status(502).json({ error: "could not read the client list from Velociraptor" });
  }
  return caseEndpoints(ctx, req, res);
}

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

  app.get("/ai-agent/sweeps", async (req: Request, res: Response) => {
    const d = deps(ctx, runStore);
    if (!d) return res.status(501).json(NOT_WIRED);
    try {
      const visible = ctx.options.teamAuth?.visibleCaseIds(req);
      const sweeps = (await listSweeps(d)).filter((s) => !visible || visible.has(s.caseId));
      return res.status(200).json({
        sweeps: sweeps.map((s) => ({ caseId: s.caseId, run: s.run ? publicRun(s.run) : null })),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/ai-agent/runs", async (req: Request, res: Response) => {
    const d = deps(ctx, runStore, req);
    if (!d) return res.status(501).json(NOT_WIRED);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const caseId = typeof body.caseId === "string" && body.caseId.trim() ? body.caseId.trim() : undefined;
    if (caseId && !isValidCaseId(caseId))
      return res.status(400).json({ error: "caseId must be a valid case id" });
    // A run with no case open makes a sweep on any server set: the instance administrator's (#2725).
    if (!caseId && !isGlobalAdmin(ctx, req))
      return res.status(403).json({
        error:
          "only an administrator can run AI Agent Forensics with no case open — open a case you can write to",
      });
    if (caseId && !(await writableBodyCase(ctx, req, res, caseId))) return;
    try {
      const start = () =>
        startAiAgentRun(d, {
          caseId,
          serverSetId: typeof body.serverSetId === "string" ? body.serverSetId : undefined,
          clientIds: Array.isArray(body.clientIds) ? body.clientIds.map(String) : [],
          scopes: Array.isArray(body.scopes) ? body.scopes.map(String) : undefined,
          uploadMaxBytes: Number.isFinite(Number(body.uploadMaxBytes))
            ? Number(body.uploadMaxBytes)
            : undefined,
          waitMinutes: Number.isFinite(Number(body.waitMinutes)) ? Number(body.waitMinutes) : undefined,
        });
      // A run into a case writes under that case: in its scope (#1866). A sweep makes its own case.
      const out = await (caseId ? runInCaseScope(ctx.store.casesRoot, caseId, start) : start());
      return res.status(202).json({ caseId: out.caseId, sweep: out.sweep, run: publicRun(out.run) });
    } catch (err) {
      ctx.serverLogger.info(`[ai-agent] run ERROR: ${(err as Error).message}`);
      return fail(res, err);
    }
  });

  app.get("/cases/:id/ai-agent/endpoints", (req: Request, res: Response) => caseEndpoints(ctx, req, res));
  app.post("/cases/:id/ai-agent/endpoints/refresh", (req: Request, res: Response) =>
    refreshCaseEndpoints(ctx, req, res),
  );

  app.get("/cases/:id/ai-agent/runs", async (req: Request, res: Response) => {
    try {
      const runs = await runStore.list(req.params.id);
      return res.status(200).json({ runs: runs.map(publicRun) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/ai-agent/runs/:runId/status", async (req: Request, res: Response) => {
    const d = deps(ctx, runStore);
    if (!d) return res.status(501).json(NOT_WIRED);
    try {
      return res.status(200).json(await readAiAgentRunStatus(d, req.params.id, req.params.runId));
    } catch (err) {
      return fail(res, err);
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
    if (!(await writableBodyCase(ctx, req, res, target))) return;
    try {
      return res.status(200).json(await addSweepToCase(d, req.params.id, req.params.runId, target));
    } catch (err) {
      return fail(res, err);
    }
  });

  // The rule-by-endpoint Sigma coverage table (#2722): its own CSV, so the hits CSV keeps one shape.
  app.get("/cases/:id/ai-agent/runs/:runId/sigma-coverage.csv", async (req: Request, res: Response) => {
    try {
      const run = await runStore.get(req.params.id, req.params.runId);
      if (!run) return res.status(404).json({ error: "run not found" });
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="ai-agent-forensics-${run.huntId}-sigma-coverage.csv"`,
      );
      return res.type("text/csv; charset=utf-8").send(aiAgentSigmaCoverageCsv(run));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
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
