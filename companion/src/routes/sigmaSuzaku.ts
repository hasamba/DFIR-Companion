// Settings → Sigma rules → Suzaku (#2508): check GitHub for a newer Suzaku rules commit, preview
// what it changes, install it, roll it back. Every route is POST, so the public demo's read-only gate
// refuses all of them. The archive download goes through the SSRF-guarded fetchOutbound; the client
// pins it to GitHub's hosts and verifies every file against its git blob SHA.

import type { Express, Request, Response } from "express";
import { z } from "zod";
import type { RouteContext } from "./context.js";
import { fetchOutbound, OutboundUrlBlockedError } from "./outboundFetchGuard.js";
import { SuzakuStoreError, type SuzakuRuleStore } from "../analysis/suzakuRuleStore.js";
import type { SigmaRuleStore } from "../analysis/sigmaRuleStore.js";

const fetchAsset = (url: string, timeoutMs: number) => fetchOutbound(url, { timeoutMs });
const installBody = z.object({ token: z.string().min(1).max(100) });

/** The Suzaku part of GET /sigma/status: version in effect, rollback target, last check as of now. */
export function suzakuStatus(store: SuzakuRuleStore | undefined): Record<string, unknown> | null {
  if (!store) return null;
  return { active: store.active(), previous: store.previous(), lastCheck: store.checkAsOfNow() ?? null };
}

export function registerSigmaSuzakuRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const need = (res: Response): { suzaku: SuzakuRuleStore; sigma: SigmaRuleStore } | undefined => {
    const suzaku = options.suzakuRuleStore;
    const sigma = options.sigmaRuleStore;
    if (!suzaku || !sigma) {
      res.status(501).json({ error: "Suzaku rule updates are not configured on this server" });
      return undefined;
    }
    return { suzaku, sigma };
  };
  const fail = (res: Response, route: string, err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    ctx.serverLogger.warn(`${route} failed: ${message}`);
    if (err instanceof SuzakuStoreError) return res.status(err.status).json({ error: message });
    const upstream =
      err instanceof OutboundUrlBlockedError || /GitHub|archive|listing|nothing was installed/.test(message);
    return res.status(upstream ? 502 : 500).json({ error: message });
  };

  // Check, and — when a newer commit exists — preview exactly that commit in the same call.
  app.post("/sigma/suzaku/check", async (_req: Request, res: Response) => {
    const s = need(res);
    if (!s) return;
    const check = await s.suzaku.checkLatest(fetch);
    if (check.error) return res.status(502).json({ error: check.error, check });
    if (!check.updateAvailable || !check.latestCommit || !check.latestDate)
      return res.json({ check, preview: null });
    try {
      const commit = { sha: check.latestCommit, date: check.latestDate, folders: check.latestFolders };
      const preview = await s.suzaku.preview(commit, fetch, fetchAsset, (f) => s.sigma.measureSuzaku(f));
      return res.json({ check, preview });
    } catch (err) {
      // The check stands; only the download failed.
      const message = err instanceof Error ? err.message : String(err);
      ctx.serverLogger.warn(`POST /sigma/suzaku/check preview failed: ${message}`);
      return res.json({ check, preview: null, previewError: message });
    }
  });

  app.post("/sigma/suzaku/install", async (req: Request, res: Response) => {
    const s = need(res);
    if (!s) return;
    const body = installBody.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: "token is required: the preview to install" });
    try {
      const active = await s.suzaku.install(body.data.token, (f) => s.sigma.measureSuzaku(f));
      ctx.serverLogger.info(`Suzaku rules: installed ${active.release} (${active.id})`);
      return res.json({ ok: true, active });
    } catch (err) {
      return fail(res, "POST /sigma/suzaku/install", err);
    }
  });

  app.post("/sigma/suzaku/rollback", async (_req: Request, res: Response) => {
    const s = need(res);
    if (!s) return;
    try {
      const active = await s.suzaku.rollback();
      ctx.serverLogger.info(`Suzaku rules: rolled back to ${active.release} (${active.id})`);
      return res.json({ ok: true, active });
    } catch (err) {
      return fail(res, "POST /sigma/suzaku/rollback", err);
    }
  });
}
