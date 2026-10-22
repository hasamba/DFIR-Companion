// Settings → Sigma rules (#2204): what the import-time Sigma engine runs, and the analyst's controls
// over it — check SigmaHQ for a newer release, preview it (download + verify + diff, nothing
// installed), install it, install from a file, roll back, and switch single rules off or on.
//
// Every mutating route is POST/PUT, so the demo's read-only gate refuses all of them. Downloads go
// through the SSRF-guarded fetchOutbound; the release client adds the GitHub host pin and the
// published-digest check. A refusal is an answer with a sentence, never a bare 500.

import type { Express, Request, Response } from "express";
import { z } from "zod";
import type { RouteContext } from "./context.js";
import { fetchOutbound, OutboundUrlBlockedError } from "./outboundFetchGuard.js";
import { SigmaStoreError, type SigmaRuleStore } from "../analysis/sigmaRuleStore.js";
import { SIGMA_RELEASE_MAX_ZIP_BYTES } from "../analysis/sigmaReleaseArchive.js";
import { computeSigmaCoverage, inventoryCounts } from "../analysis/sigmaCoverage.js";
import {
  sigmaMinLevelFromEnv,
  sigmaStatusesFromEnv,
  sigmaUpdateCheckEnabled,
} from "../analysis/sigmaSettings.js";

const OFF = new Set(["off", "0", "false", "no"]);
const fetchAsset = (url: string, timeoutMs: number) => fetchOutbound(url, { timeoutMs });

const previewBody = z.union([
  z.object({ source: z.literal("latest") }),
  z.object({
    source: z.literal("file"),
    name: z.string().min(1).max(200),
    // base64 of at most the archive cap
    zipBase64: z
      .string()
      .min(1)
      .max(Math.ceil((SIGMA_RELEASE_MAX_ZIP_BYTES * 4) / 3) + 4),
  }),
]);
const installBody = z.object({ token: z.string().min(1).max(100) });
const disabledBody = z.object({
  id: z.string().min(1).max(200),
  disabled: z.boolean(),
  reason: z.string().max(300).optional(),
});

const sigmaEnabled = (): boolean => !OFF.has(process.env.DFIR_SIGMA_RULES?.trim().toLowerCase() ?? "");

export function registerSigmaRulesRoutes(app: Express, ctx: RouteContext): void {
  const { options, store: cases } = ctx;
  const errLine = (msg: string): void => ctx.serverLogger.warn(msg);
  const need = (res: Response): SigmaRuleStore | undefined => {
    if (!options.sigmaRuleStore)
      res.status(501).json({ error: "Sigma rules are not configured on this server" });
    return options.sigmaRuleStore;
  };
  const fail = (res: Response, route: string, err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    errLine(`${route} failed: ${message}`);
    if (err instanceof SigmaStoreError) return res.status(err.status).json({ error: message });
    const upstream =
      err instanceof OutboundUrlBlockedError || /GitHub|unexpected host|SHA-256|larger than/.test(message);
    // An archive the reader refused is the analyst's file, not a server fault.
    const refused = /archive|zip|rules\/ folder|unsafe path|twice|file and a folder/.test(message);
    return res.status(upstream ? 502 : refused ? 422 : 500).json({ error: message });
  };

  app.get("/sigma/status", (_req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    const set = store.activeRuleSet();
    return res.json({
      enabled: sigmaEnabled(),
      active: store.active(),
      previous: store.previous(),
      contentSha: set.contentSha,
      disabledHash: set.disabledHash,
      settings: {
        statuses: sigmaStatusesFromEnv(),
        minLevel: sigmaMinLevelFromEnv(),
        updateCheck: sigmaUpdateCheckEnabled(),
      },
      counts: inventoryCounts(set.inventory),
      problems: set.problems,
      lastCheck: store.lastCheck ?? null,
      demoMode: !!options.demoMode,
    });
  });

  // #2217: which of this case's ingested origins Sigma grades, and with how many rules. Analyst-only
  // and read-only — derived from the super-timeline's origin counts, never fed to an AI prompt.
  app.get("/cases/:id/sigma/coverage", async (req: Request, res: Response) => {
    const sigma = need(res);
    if (!sigma) return;
    const superStore = options.superTimelineStore;
    if (!superStore) return res.status(501).json({ error: "super-timeline not configured" });
    try {
      if (!(await cases.caseExists(req.params.id)))
        return res.status(404).json({ error: `case ${req.params.id} not found` });
      const origins = await superStore.originCounts(req.params.id);
      return res.json(computeSigmaCoverage(origins, sigma.activeRuleSet().inventory, sigmaEnabled()));
    } catch (err) {
      return fail(res, "GET /cases/:id/sigma/coverage", err);
    }
  });

  app.get("/sigma/rules", (_req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    const rules = store.inventory().filter((e) => e.outcome !== "no-source");
    return res.json({ rules, otherSources: store.inventory().length - rules.length });
  });

  app.post("/sigma/check", async (_req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    try {
      const check = await store.checkLatest(fetch);
      if (check.error) return res.status(502).json({ error: check.error, check });
      // Check shows what would change in one click when a newer release exists — nothing installed.
      const preview = check.updateAvailable ? await store.previewLatest(fetch, fetchAsset) : null;
      return res.json({ check, preview });
    } catch (err) {
      return fail(res, "POST /sigma/check", err);
    }
  });

  app.post("/sigma/preview", async (req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    const body = previewBody.safeParse(req.body);
    if (!body.success)
      return res.status(400).json({ error: 'send {source:"latest"} or {source:"file", name, zipBase64}' });
    try {
      if (body.data.source === "latest")
        return res.json({ preview: await store.previewLatest(fetch, fetchAsset) });
      const bytes = Buffer.from(body.data.zipBase64, "base64");
      const preview = await store.preview(bytes, {
        source: "file",
        fileName: body.data.name,
        verified: false,
      });
      return res.json({ preview });
    } catch (err) {
      return fail(res, "POST /sigma/preview", err);
    }
  });

  app.post("/sigma/install", async (req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    const body = installBody.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: "token is required: the preview to install" });
    try {
      const active = await store.install(body.data.token);
      ctx.serverLogger.info(`Sigma rules: installed ${active.release} (${active.id})`);
      return res.json({ ok: true, active });
    } catch (err) {
      return fail(res, "POST /sigma/install", err);
    }
  });

  app.post("/sigma/rollback", async (_req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    try {
      const active = await store.rollback();
      ctx.serverLogger.info(`Sigma rules: rolled back to ${active.release} (${active.id})`);
      return res.json({ ok: true, active });
    } catch (err) {
      return fail(res, "POST /sigma/rollback", err);
    }
  });

  app.put("/sigma/disabled", async (req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    const body = disabledBody.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: "send {id, disabled: true|false, reason?}" });
    try {
      await store.setRuleDisabled(body.data.id, body.data.disabled, body.data.reason ?? "");
      return res.json({ ok: true });
    } catch (err) {
      return fail(res, "PUT /sigma/disabled", err);
    }
  });
}
