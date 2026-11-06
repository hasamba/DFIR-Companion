// Super-Timeline → Content tagger → Rule pack (#2349): the detection-rule pack released separately
// from the app, and the analyst's controls over it.
//
//   GET  /tagger/pack            — installed pack, previous pack, whether it is in use, last check.
//   POST /tagger/pack/check      — find the newest pack this app can load, download + verify it,
//                                  and return a review of it. Nothing is installed.
//   POST /tagger/pack/file       — the same review for a pack file (offline lab): "not checked
//                                  against GitHub"; the file's SHA-256 is recorded.
//   POST /tagger/pack/install    — install a reviewed pack (by its review token).
//   POST /tagger/pack/rollback   — to the previous pack, or to the rules bundled with the app.
//   POST /tagger/pack/measure    — rows of a case the reviewed pack would grade or tag differently.
//                                  Changes nothing.
//
// Everything is under /tagger, so in team mode only the instance administrator — the users who may
// edit tagger rules at all (auth/policy.ts) — reaches it. Demo mode refuses every download, install
// and roll back here, in the route, on top of the demo's read-only gate. Downloads go through the
// SSRF-guarded fetchOutbound; the client adds the GitHub host pin and the digest checks.

import type { Express, Request, Response } from "express";
import { z } from "zod";
import type { RouteContext } from "./context.js";
import { fetchOutbound, OutboundUrlBlockedError } from "./outboundFetchGuard.js";
import { itemView } from "./taggerUpdates.js";
import { RulePackError, type RulePackStore, type StagedPack } from "../analysis/rulePackStore.js";
import { checkRulePack, rulePackUpdateCheckEnabled } from "../analysis/rulePackCheck.js";
import {
  RULE_PACK_MAX_MANIFEST_BYTES,
  RULE_PACK_MAX_RULES_BYTES,
  parseRulePackManifest,
} from "../analysis/rulePackManifest.js";
import { diffRuleSets, snapshotBase } from "../analysis/taggerRulesMerge.js";
import { compileText, type TaggerStore } from "../analysis/taggerStore.js";
import { measurePack } from "../analysis/rulePackMeasure.js";
import { readTaggerSettings } from "../analysis/taggerRun.js";
import { parse as parseYaml } from "yaml";

const fetchAsset = (url: string, timeoutMs: number) => fetchOutbound(url, { timeoutMs });
const DEMO_REFUSAL = "The public demo does not download or install rule packs.";

const fileBody = z.object({
  name: z.string().min(1).max(200),
  rulesText: z.string().min(1).max(RULE_PACK_MAX_RULES_BYTES),
  manifestText: z.string().min(1).max(RULE_PACK_MAX_MANIFEST_BYTES).optional(),
});
const tokenBody = z.object({ token: z.string().min(1).max(100) });
const rollbackBody = z.object({ to: z.enum(["previous", "bundled"]) });
const measureBody = z.object({ token: z.string().min(1).max(100), caseId: z.string().min(1).max(200) });

function ruleMap(text: string): Record<string, unknown> {
  const doc: unknown = text.trim() ? parseYaml(text) : {};
  return doc && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>) : {};
}

/** What installing the staged pack changes, against the rules a pack replaces (pack in use or bundled). */
async function review(staged: StagedPack, tagger: TaggerStore | undefined) {
  const incoming = ruleMap(staged.rulesText);
  const upstream = tagger ? await tagger.upstream() : null;
  const current = upstream?.map ?? {};
  // Base = the current set itself, so "added" is new in the pack, "changed" changed in it, and
  // "retired upstream" is a rule the pack no longer has.
  const diff = diffRuleSets({ upstream: incoming, mine: current, base: snapshotBase(current) });
  const active = tagger ? await tagger.readActive() : null;
  return {
    token: staged.token,
    pack: staged.pack,
    comparedWith: upstream?.label ?? "no rules",
    activeSource: active?.source ?? "default",
    counts: { added: diff.added.length, changed: diff.changed.length, removed: diff.retiredUpstream.length },
    added: diff.added.map(itemView),
    changed: diff.changed.map((i) => itemView({ ...i, mine: current[i.key] })),
    removed: diff.retiredUpstream.map((key) => ({
      key,
      rule: itemView({ key, upstream: current[key], uncertain: false }).upstream,
    })),
  };
}

export function registerRulePackRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const need = (res: Response): RulePackStore | undefined => {
    if (!options.rulePackStore)
      res.status(501).json({ error: "rule packs are not configured on this server" });
    return options.rulePackStore;
  };
  const demo = (res: Response): boolean => {
    if (!options.demoMode) return false;
    res.status(403).json({ error: DEMO_REFUSAL, demo: true });
    return true;
  };
  const fail = (res: Response, route: string, err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    ctx.serverLogger.warn(`${route} failed: ${message}`);
    if (err instanceof RulePackError) return res.status(err.status).json({ error: message });
    const upstream =
      err instanceof OutboundUrlBlockedError || /GitHub|unexpected host|SHA-256|larger than/.test(message);
    return res.status(upstream ? 502 : 400).json({ error: message });
  };

  app.get("/tagger/pack", async (_req: Request, res: Response) => {
    const store = need(res);
    if (!store) return;
    try {
      const status = await store.status();
      const provenance = options.taggerStore
        ? await options.taggerStore.provenance().catch(() => null)
        : null;
      return res.json({
        ...status,
        activeRules: provenance,
        updateCheck: rulePackUpdateCheckEnabled(),
        demoMode: !!options.demoMode,
      });
    } catch (err) {
      return fail(res, "GET /tagger/pack", err);
    }
  });

  app.post("/tagger/pack/check", async (_req: Request, res: Response) => {
    const store = need(res);
    if (!store || demo(res)) return;
    try {
      const out = await checkRulePack(store, { fetchFn: fetch, fetchAsset, stage: true });
      if (out.record.status === "error")
        return fail(res, "POST /tagger/pack/check", new Error(out.record.message));
      const body = {
        check: out.record,
        review: out.staged ? await review(out.staged, options.taggerStore) : null,
      };
      return res.json(body);
    } catch (err) {
      return fail(res, "POST /tagger/pack/check", err);
    }
  });

  app.post("/tagger/pack/file", async (req: Request, res: Response) => {
    const store = need(res);
    if (!store || demo(res)) return;
    const body = fileBody.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: "send {name, rulesText, manifestText?}" });
    try {
      const manifest = body.data.manifestText ? parseRulePackManifest(body.data.manifestText) : undefined;
      const staged = store.stage({
        rulesText: body.data.rulesText,
        manifest,
        origin: "file",
        verifiedByGitHub: false,
        fileName: body.data.name,
      });
      return res.json({ review: await review(staged, options.taggerStore) });
    } catch (err) {
      return fail(
        res,
        "POST /tagger/pack/file",
        err instanceof RulePackError ? err : new RulePackError((err as Error).message, 422),
      );
    }
  });

  app.post("/tagger/pack/install", async (req: Request, res: Response) => {
    const store = need(res);
    if (!store || demo(res)) return;
    const body = tokenBody.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: "token is required: the review to install" });
    try {
      const pack = await store.install(body.data.token);
      ctx.serverLogger.info(`[tagger] rule pack ${pack.version} installed (${pack.origin})`);
      return res.json({ ok: true, installed: pack, status: await store.status() });
    } catch (err) {
      return fail(res, "POST /tagger/pack/install", err);
    }
  });

  app.post("/tagger/pack/rollback", async (req: Request, res: Response) => {
    const store = need(res);
    if (!store || demo(res)) return;
    const body = rollbackBody.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: 'send {to: "previous" | "bundled"}' });
    try {
      const pack = await store.rollback(body.data.to);
      ctx.serverLogger.info(`[tagger] rule pack rolled back to ${pack ? pack.version : "the bundled rules"}`);
      return res.json({ ok: true, installed: pack, status: await store.status() });
    } catch (err) {
      return fail(res, "POST /tagger/pack/rollback", err);
    }
  });

  app.post("/tagger/pack/measure", async (req: Request, res: Response) => {
    const store = need(res);
    if (!store || demo(res)) return;
    if (!options.stateStore || !options.taggerStore)
      return res.status(501).json({ error: "tagger not configured" });
    const body = measureBody.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: "send {token, caseId}" });
    const staged = store.getStaged(body.data.token);
    if (!staged)
      return res
        .status(410)
        .json({ error: "that review has expired; check for updates or choose the file again" });
    try {
      if (!(await ctx.store.caseExists(body.data.caseId)))
        return res.status(404).json({ error: `case ${body.data.caseId} not found` });
      const state = await options.stateStore.load(body.data.caseId);
      const superBatches = options.superTimelineStore
        ? options.superTimelineStore.eventBatches(body.data.caseId)
        : null;
      const result = await measurePack(
        await options.taggerStore.load(),
        compileText(staged.rulesText),
        readTaggerSettings().scope,
        state.forensicTimeline,
        superBatches,
      );
      return res.json({
        ...result,
        version: staged.pack.version,
        comparedWith: await options.taggerStore.provenance(),
      });
    } catch (err) {
      return fail(res, "POST /tagger/pack/measure", err);
    }
  });
}
