// AI Agent Forensics (#2690): the separate AI-agent rule pack — check, review, install, roll back.
// Installed packs live under `<data root>/ai-agent-rules-pack`, beside the cases folder, never in a
// case. The public demo downloads and installs nothing.
//
//   GET  /ai-agent/pack            what is installed and in use
//   POST /ai-agent/pack/check      download, verify, stage and load the newest pack; show its changes
//   POST /ai-agent/pack/install    { version } — make the staged pack live for the next run
//   POST /ai-agent/pack/rollback   { to: "previous" | "bundled" }

import type { Express, Request, Response } from "express";
import { dirname, join } from "node:path";
import { z } from "zod";
import type { RouteContext } from "./context.js";
import { AiAgentPackError, AiAgentPackStore, isAiPackTag } from "../analysis/aiAgentPack.js";
import { activeAiAgentRuleSet, activeAiAgentRulesProblem } from "../analysis/aiAgentActiveRules.js";
import { fetchOutbound } from "./outboundFetchGuard.js";
import { getAppVersion } from "../version.js";

const DEMO_REFUSAL = "The public demo does not download or install AI-agent rule packs.";
const installBody = z.object({ version: z.string().refine(isAiPackTag, "not an AI-agent pack version") });
const rollbackBody = z.object({ to: z.enum(["previous", "bundled"]) });
const fetchAsset = (url: string, timeoutMs: number) => fetchOutbound(url, { timeoutMs });

export function registerAiAgentPackRoutes(app: Express, ctx: RouteContext): void {
  const store = new AiAgentPackStore(
    join(dirname(ctx.store.casesRoot), "ai-agent-rules-pack"),
    getAppVersion(),
  );
  void store
    .restore()
    .catch((e: Error) => ctx.serverLogger.warn(`AI-agent rule pack restore failed: ${e.message}`));

  const demo = (res: Response): boolean => {
    if (!ctx.options.demoMode) return false;
    res.status(403).json({ error: DEMO_REFUSAL, demo: true });
    return true;
  };
  const fail = (res: Response, err: unknown): Response => {
    const message = err instanceof Error ? err.message : String(err);
    ctx.serverLogger.warn(`AI-agent rule pack: ${message}`);
    if (err instanceof AiAgentPackError) return res.status(err.status).json({ error: message });
    return res.status(502).json({ error: message });
  };

  app.get("/ai-agent/pack", async (_req: Request, res: Response) => {
    try {
      const pointer = await store.pointer();
      return res
        .status(200)
        .json({ ...pointer, inUse: activeAiAgentRuleSet().version, problem: activeAiAgentRulesProblem() });
    } catch (err) {
      return fail(res, err);
    }
  });

  app.post("/ai-agent/pack/check", async (_req: Request, res: Response) => {
    if (demo(res)) return;
    try {
      return res.status(200).json(await store.check(fetch, fetchAsset));
    } catch (err) {
      return fail(res, err);
    }
  });

  app.post("/ai-agent/pack/install", async (req: Request, res: Response) => {
    if (demo(res)) return;
    const body = installBody.safeParse(req.body ?? {});
    if (!body.success)
      return res.status(400).json({ error: "version must be an aiagent-rules-YYYY.MM.DD tag" });
    try {
      return res
        .status(200)
        .json({ active: await store.install(body.data.version), inUse: activeAiAgentRuleSet().version });
    } catch (err) {
      return fail(res, err);
    }
  });

  app.post("/ai-agent/pack/rollback", async (req: Request, res: Response) => {
    if (demo(res)) return;
    const body = rollbackBody.safeParse(req.body ?? {});
    if (!body.success) return res.status(400).json({ error: 'to must be "previous" or "bundled"' });
    try {
      return res
        .status(200)
        .json({ active: await store.rollback(body.data.to), inUse: activeAiAgentRuleSet().version });
    } catch (err) {
      return fail(res, err);
    }
  });
}
